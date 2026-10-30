//! `arrowmesh run`: supervise or attach to llama.cpp, serve the loopback API, listen for peers.

use crate::app::{App, Reply};
use crate::config::Config;
use crate::gatepath::Gate;
use crate::keys::{Identity, Kdf};
use crate::mesh::{IdSlot, Listener, Sender};
use crate::supervisor::{Supervisor, llama_args};
use crate::vault::Vault;
use crate::net;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

pub struct Running {
    pub chat_addr: SocketAddr,
    pub mesh_addr: SocketAddr,
    server: Arc<tiny_http::Server>,
    workers: Vec<std::thread::JoinHandle<()>>,
    listener: Listener,
    _supervisor: Option<Supervisor>,
    app: Arc<App>,
}

impl Running {
    /// The request handler, for tests that need the stream and its place without a socket.
    #[doc(hidden)]
    pub fn app(&self) -> &Arc<App> {
        &self.app
    }

    pub fn stop(mut self) {
        // unblock() wakes one waiting worker per call.
        for _ in 0..self.workers.len() {
            self.server.unblock();
        }
        for w in self.workers.drain(..) {
            let _ = w.join();
        }
        self.listener.stop();
    }
}

/// Build the gate for a config. The model layer, when on, talks to the same local llama server.
pub fn gate_for(cfg: &Config) -> Gate {
    let model = cfg.gate_model.then(|| {
        let mut m = gate::ModelConfig::new(&format!("http://{}/v1/chat/completions", cfg.llama_addr));
        if let Ok(Some(k)) = llama_key(cfg) {
            m.token = k;
        }
        m
    });
    Gate::new(model)
}

/// The model server key. When arrowmesh launches the model the key is created here at first start
/// (mode 600); when it attaches to one, the key is read if the file exists and none is sent if not.
pub fn llama_key(cfg: &Config) -> Result<Option<String>, String> {
    if cfg.model_path.is_some() {
        crate::token::load_or_create(&cfg.llama_key_file).map(Some)
    } else if cfg.llama_key_file.exists() {
        crate::token::load(&cfg.llama_key_file).map(Some)
    } else if cfg.llama_key_required {
        Err("llama_key_required is true and the model key file is missing, refusing to start".into())
    } else {
        Ok(None)
    }
}

/// The value of a header that appears exactly once; a repeated header counts as absent.
fn single_header(req: &tiny_http::Request, name: &'static str) -> Option<String> {
    let mut it = req.headers().iter().filter(|h| h.field.equiv(name));
    let first = it.next().map(|h| h.value.as_str().to_string());
    if it.next().is_some() { None } else { first }
}

/// Write a chat stream as chunked `text/event-stream`, flushing after every event. Ends when the
/// producer is done, or when the client stops reading or goes away (the receiver is then dropped,
/// which makes the producer drop the upstream connection).
fn serve_stream(req: tiny_http::Request, rx: std::sync::mpsc::Receiver<Vec<u8>>) {
    let mut w = req.into_writer();
    let _ = write_events(&mut w, &rx);
}

/// The wire side of `serve_stream`. An error means the client is gone or stopped reading (the
/// socket's send timeout fired); the caller then drops `rx` and gives the place back.
pub(crate) fn write_events(w: &mut dyn std::io::Write, rx: &std::sync::mpsc::Receiver<Vec<u8>>) -> std::io::Result<()> {
    use std::sync::mpsc::RecvTimeoutError;
    let head = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-store\r\nTransfer-Encoding: chunked\r\n\r\n";
    let chunk = |w: &mut dyn std::io::Write, d: &[u8]| -> std::io::Result<()> {
        w.write_all(format!("{:x}\r\n", d.len()).as_bytes())?;
        w.write_all(d)?;
        w.write_all(b"\r\n")?;
        w.flush()
    };
    w.write_all(head)?;
    w.flush()?;
    loop {
        match rx.recv_timeout(crate::stream::KEEPALIVE) {
            Ok(b) => chunk(w, &b)?,
            Err(RecvTimeoutError::Timeout) => chunk(w, b": keepalive\n\n")?,
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    w.write_all(b"0\r\n\r\n")?;
    w.flush()
}

/// Unwraps the identity key with the supplied words. The loopback API token is read from
/// `cfg.token_file` (mode 600 or the daemon refuses to start).
pub fn start(cfg: Config, gate: Gate, words: &str) -> Result<Running, String> {
    start_with_floor(cfg, gate, words, Kdf::PRODUCTION)
}

/// As `start`, with an explicit Argon2id cost floor for the key file. Only tests pass less than
/// `Kdf::PRODUCTION`. The words are used once here, to unwrap the identity, and are not kept:
/// the running daemon holds only the unwrapped keys (N1).
pub fn start_with_floor(cfg: Config, gate: Gate, words: &str, floor: Kdf) -> Result<Running, String> {
    let id = Identity::load_with_floor(&cfg.key_file, words, floor)?;
    let vault = Vault::open(cfg.vault_dir.clone())?;
    vault.probe(&id).map_err(|e| format!("vault locked: {e}"))?;
    serve(cfg, gate, floor, Some(Arc::new(id)))
}

/// `arrowmesh run`: boot with the vault sealed. Nothing is read from env, file or argv; the app
/// supplies the secret through `POST /v1/vault/unlock`, and `POST /v1/vault/lock` seals it again.
pub fn start_locked(cfg: Config, gate: Gate) -> Result<Running, String> {
    start_locked_with_floor(cfg, gate, Kdf::PRODUCTION)
}

pub fn start_locked_with_floor(cfg: Config, gate: Gate, floor: Kdf) -> Result<Running, String> {
    serve(cfg, gate, floor, None)
}

fn serve(cfg: Config, gate: Gate, floor: Kdf, id: Option<Arc<Identity>>) -> Result<Running, String> {
    let token = crate::token::load(&cfg.token_file)?;
    let vault = Arc::new(Mutex::new(Vault::open(cfg.vault_dir.clone())?));
    let id: IdSlot = Arc::new(RwLock::new(id));
    let llama_key = llama_key(&cfg)?;
    let supervisor = cfg.model_path.as_ref().map(|m| Supervisor::start(cfg.llama_bin.clone(), llama_args(m, cfg.llama_addr.port(), &cfg.llama_key_file), Duration::from_secs(1)));
    let received = Arc::new(AtomicU64::new(0));
    let listener = Listener::start(&cfg, id.clone(), vault.clone(), received.clone())?;
    let app = Arc::new(App { sender: Mutex::new(Sender::new(&cfg.vault_dir)?), cfg: cfg.clone(), ident: id, vault, gate, token, llama_key, floor, jobs: Mutex::default(), streams: AtomicUsize::new(0), received });
    // Address was parsed by net::parse_loopback at config load; listen() rechecks.
    let l = net::listen(&cfg.chat_addr).map_err(|e| format!("chat listen: {}", e.kind()))?;
    net::set_send_timeout(&l, cfg.send_timeout).map_err(|e| format!("chat listen: {}", e.kind()))?;
    let server = Arc::new(tiny_http::Server::from_listener(l, None).map_err(|e| format!("chat server: {e}"))?);
    let chat_addr = server.server_addr().to_ip().ok_or("chat server address")?;
    let mut workers = Vec::new();
    for _ in 0..4 {
        let (s, a) = (server.clone(), app.clone());
        workers.push(std::thread::spawn(move || {
            for mut req in s.incoming_requests() {
                let method = req.method().as_str().to_string();
                let url = req.url().to_string();
                let mut body = String::new();
                {
                    use std::io::Read;
                    let _ = req.as_reader().take(crate::app::MAX_BODY as u64 + 1).read_to_string(&mut body);
                }
                let (host, auth, accept) = (single_header(&req, "Host"), single_header(&req, "Authorization"), single_header(&req, "Accept"));
                match a.handle_reply(&method, &url, &body, host.as_deref(), auth.as_deref(), accept.as_deref()) {
                    Reply::Plain(code, out) => {
                        let ct: &[u8] = if code == 200 && url.split('?').next() == Some("/v1/openapi.yaml") { b"application/yaml" } else { b"application/json" };
                        let h = tiny_http::Header::from_bytes(&b"Content-Type"[..], ct).unwrap();
                        let _ = req.respond(tiny_http::Response::from_string(out).with_status_code(code).with_header(h));
                    }
                    // Its own thread: a client that stops reading holds that thread, never a worker.
                    Reply::Stream(rx, slot) => {
                        std::thread::spawn(move || {
                            serve_stream(req, rx);
                            // The place is given back only when the writer is done, not when the producer is.
                            drop(slot);
                        });
                    }
                }
            }
        }));
    }
    Ok(Running { chat_addr, mesh_addr: listener.addr, server, workers, listener, _supervisor: supervisor, app })
}

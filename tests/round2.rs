//! Round 2: 423 for the sealed state only, the F1 mismatch body, F2 status hygiene, F3 lock ends the
//! session, F4 core dump hardening on the real binary.

use arrowmesh::config::Config;
use arrowmesh::daemon;
use arrowmesh::gatepath::Gate;
use arrowmesh::keys::{Identity, Kdf};
use arrowmesh::vault::Vault;
use arrowmesh::{net, testutil};
use serde_json::{Value, json};
use std::io::BufRead;
use std::net::SocketAddr;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

const WORDS: &str = "round two test words";

struct FakeLlama {
    addr: SocketAddr,
    server: Arc<tiny_http::Server>,
}

impl FakeLlama {
    /// `delay` applies to chat completions only; /health answers at once.
    fn start(delay: Duration) -> FakeLlama {
        let server = Arc::new(tiny_http::Server::http("127.0.0.1:0").unwrap());
        let addr = server.server_addr().to_ip().unwrap();
        let s = server.clone();
        std::thread::spawn(move || {
            for mut req in s.incoming_requests() {
                let mut b = String::new();
                let _ = req.as_reader().read_to_string(&mut b);
                let out = if req.url() == "/health" {
                    "{\"status\":\"ok\"}".to_string()
                } else {
                    std::thread::sleep(delay);
                    json!({"choices":[{"message":{"role":"assistant","content":"fine"}}]}).to_string()
                };
                let _ = req.respond(tiny_http::Response::from_string(out));
            }
        });
        FakeLlama { addr, server }
    }
}
impl Drop for FakeLlama {
    fn drop(&mut self) {
        self.server.unblock();
    }
}

fn call(addr: SocketAddr, token: &str, m: &str, path: &str, body: Value) -> (u16, Value) {
    let host = addr.to_string();
    let auth = format!("Bearer {token}");
    let b = if body.is_null() { None } else { Some(body.to_string()) };
    let (c, out) = net::http_with(&addr, m, path, b.as_deref(), Duration::from_secs(60), &[("Host", &host), ("Authorization", &auth)]).unwrap();
    (c, serde_json::from_slice(&out).unwrap_or(Value::Null))
}

fn unlock(a: SocketAddr, token: &str, words: &str) -> (u16, Value) {
    call(a, token, "POST", "/v1/vault/unlock", json!({"passphrase": words}))
}

fn boot(tag: &str, llama: SocketAddr) -> (daemon::Running, Config, String) {
    let home = testutil::tmp(tag);
    let mut c = Config::defaults(&home);
    c.chat_addr = "127.0.0.1:0".parse().unwrap();
    c.mesh_listen = "127.0.0.1:0".parse().unwrap();
    c.llama_addr = llama;
    Identity::generate().unwrap().save_new_with(&c.key_file, WORDS, Kdf::TEST).unwrap();
    let token = arrowmesh::token::create_new(&c.token_file).unwrap();
    let run = daemon::start_locked_with_floor(c.clone(), Gate::new(None), Kdf::TEST).unwrap();
    (run, c, token)
}

fn chat_body(text: &str) -> Value {
    json!({"conv": "t", "messages": [{"role": "user", "content": text}]})
}

#[test]
fn sealed_is_423_and_a_key_mismatch_is_503_with_no_lock_word() {
    let llama = FakeLlama::start(Duration::ZERO);
    let (run, c, token) = boot("r2mismatch", llama.addr);
    let a = run.chat_addr;
    assert_eq!(call(a, &token, "POST", "/v1/chat", chat_body("x")), (423, json!({"error": "vault locked"})));
    // Seal the vault with key A, then replace the key file with key B wrapped under the SAME words.
    assert_eq!(unlock(a, &token, WORDS).0, 200);
    assert_eq!(call(a, &token, "POST", "/v1/chat", chat_body("seal it")).0, 200);
    assert_eq!(call(a, &token, "POST", "/v1/vault/lock", json!({})).0, 200);
    std::fs::remove_file(&c.key_file).unwrap();
    Identity::generate().unwrap().save_new_with(&c.key_file, WORDS, Kdf::TEST).unwrap();
    let (code, body) = unlock(a, &token, WORDS);
    assert_eq!(code, 503, "{body}");
    let text = body.to_string().to_lowercase();
    assert!(!text.contains("lock"), "mismatch body must not say lock: {text}");
    // Still sealed afterwards, and the sealed shape is still 423.
    assert_eq!(call(a, &token, "GET", "/v1/history?conv=t", Value::Null).0, 423);
    // Junk words stay 401.
    assert_eq!(unlock(a, &token, "nope nope").0, 401);
    run.stop();
}

/// F3: an async chat in flight when the vault is locked writes nothing after the lock and leaves no job behind.
#[test]
fn lock_mid_flight_writes_no_record_and_leaves_no_job() {
    let llama = FakeLlama::start(Duration::from_millis(900));
    let (run, c, token) = boot("r2lock", llama.addr);
    let a = run.chat_addr;
    assert_eq!(unlock(a, &token, WORDS).0, 200);
    let before = Vault::open(c.vault_dir.clone()).unwrap().record_count();
    let (code, v) = call(a, &token, "POST", "/v1/chat", json!({"async": true, "conv": "t", "messages": [{"role": "user", "content": "slow one"}]}));
    assert_eq!(code, 202, "{v}");
    let job = v["job"].as_u64().unwrap();
    std::thread::sleep(Duration::from_millis(250));
    assert_eq!(call(a, &token, "POST", "/v1/vault/lock", json!({})).0, 200);
    std::thread::sleep(Duration::from_millis(1500)); // the model answers while sealed
    assert_eq!(Vault::open(c.vault_dir.clone()).unwrap().record_count(), before, "a record landed after lock");
    assert_eq!(unlock(a, &token, WORDS).0, 200);
    let (code, v) = call(a, &token, "GET", &format!("/v1/chat/jobs/{job}"), Value::Null);
    assert_eq!(code, 404, "the job survived a lock: {v}");
    // A finished job is also dropped by lock.
    let (_, v) = call(a, &token, "POST", "/v1/chat", json!({"async": true, "messages": [{"role": "user", "content": "fast"}]}));
    let job2 = v["job"].as_u64().unwrap();
    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(call(a, &token, "POST", "/v1/vault/lock", json!({})).0, 200);
    assert_eq!(unlock(a, &token, WORDS).0, 200);
    assert_eq!(call(a, &token, "GET", &format!("/v1/chat/jobs/{job2}"), Value::Null).0, 404, "a finished reply survived a lock");
    // A sync chat in flight at lock time is refused with 423 and writes nothing.
    let n = Vault::open(c.vault_dir.clone()).unwrap().record_count();
    let t2 = token.clone();
    let h = std::thread::spawn(move || call(a, &t2, "POST", "/v1/chat", chat_body("sync slow")));
    std::thread::sleep(Duration::from_millis(250));
    assert_eq!(call(a, &token, "POST", "/v1/vault/lock", json!({})).0, 200);
    assert_eq!(h.join().unwrap(), (423, json!({"error": "vault locked"})));
    assert_eq!(Vault::open(c.vault_dir.clone()).unwrap().record_count(), n);
    run.stop();
}

/// Decisive test: three threads poll status while 40 chats run. Prints the count.
#[test]
fn status_poll_never_fails_a_chat() {
    let llama = FakeLlama::start(Duration::ZERO);
    let (run, _c, token) = boot("r2f2", llama.addr);
    let a = run.chat_addr;
    assert_eq!(unlock(a, &token, WORDS).0, 200);
    let stop = Arc::new(AtomicBool::new(false));
    let polls = Arc::new(AtomicUsize::new(0));
    let pollers: Vec<_> = (0..3)
        .map(|_| {
            let (s, p, t) = (stop.clone(), polls.clone(), token.clone());
            std::thread::spawn(move || {
                while !s.load(Ordering::SeqCst) {
                    let _ = call(a, &t, "GET", "/v1/status", Value::Null);
                    p.fetch_add(1, Ordering::SeqCst);
                }
            })
        })
        .collect();
    let mut failed = 0;
    for i in 0..40 {
        let (code, v) = call(a, &token, "POST", "/v1/chat", chat_body(&format!("message {i}")));
        if code != 200 {
            failed += 1;
            eprintln!("chat {i}: {code} {v}");
        }
    }
    stop.store(true, Ordering::SeqCst);
    for p in pollers {
        p.join().unwrap();
    }
    eprintln!("F2 RESULT: {failed} of 40 chats failed, {} status polls", polls.load(Ordering::SeqCst));
    assert_eq!(failed, 0, "vault write failed on {failed} of 40 chats");
    run.stop();
}

/// F4 on the real binary: core limit 0 and not dumpable. A non dumpable process makes its own /proc entries root owned, so the same user cannot read its environ.
#[test]
fn the_real_daemon_has_no_core_limit_and_is_not_dumpable() {
    let llama = FakeLlama::start(Duration::ZERO);
    let home = testutil::tmp("r2core");
    let exe = env!("CARGO_BIN_EXE_arrowmesh");
    let out = Command::new(exe).arg("install").env("HOME", &home).env("ARROWMESH_PASSPHRASE", WORDS).env_remove("CREDENTIALS_DIRECTORY").stdin(Stdio::null()).output().unwrap();
    assert!(out.status.success());
    let unit = std::fs::read_to_string(home.join(".config/systemd/user/arrowmesh.service")).unwrap();
    assert!(unit.contains("LimitCORE=0\n"), "{unit}");
    let cfg_path = home.join(".config/arrowmesh/config");
    let d = Config::defaults(&home);
    let text = std::fs::read_to_string(&cfg_path)
        .unwrap()
        .replace(&d.chat_addr.to_string(), "127.0.0.1:0")
        .replace(&d.mesh_listen.to_string(), "127.0.0.1:0")
        .replace(&d.llama_addr.to_string(), &llama.addr.to_string());
    std::fs::write(&cfg_path, text).unwrap();
    let mut child = Command::new(exe).args(["run", "--config"]).arg(&cfg_path).env("HOME", &home).env_remove("ARROWMESH_PASSPHRASE").stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let mut err = std::io::BufReader::new(child.stderr.take().unwrap());
    let mut line = String::new();
    err.read_line(&mut line).unwrap();
    let pid = child.id();
    let limits = std::fs::read_to_string(format!("/proc/{pid}/limits")).unwrap_or_default();
    let env = std::fs::read(format!("/proc/{pid}/environ"));
    child.kill().unwrap();
    child.wait().unwrap();
    let core = limits.lines().find(|l| l.starts_with("Max core file size")).unwrap_or("");
    let cols: Vec<&str> = core.split_whitespace().collect();
    // "Max core file size <soft> <hard> bytes"
    assert_eq!(&cols[4..6], &["0", "0"], "core limit line: {core:?}");
    assert!(env.is_err(), "environ is readable, so the process is still dumpable");
}

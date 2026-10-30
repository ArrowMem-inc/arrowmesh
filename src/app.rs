//! The loopback API. Pure request handling over strings so it can be tested without sockets.
//!
//! POST /v1/chat     {"conv":"name"?, "messages":[{"role","content"}]}
//! POST /v1/send     {"peer":"name", "text":"..."}
//! GET  /v1/history?conv=name
//! GET  /v1/status
//!
//! Every request needs an `Authorization` header carrying the token from the mode 600 token file
//! `install` writes, compared in constant time, and a `Host` header that is an IP literal equal to
//! the bind address or loopback. A wrong Host is 403 with an empty body; a missing or wrong token
//! is 401. The Host check runs first, so a page that rebinds a name to 127.0.0.1 gets nothing,
//! token or not.

use crate::config::{Config, valid_name};
use crate::gatepath::Gate;
use crate::keys::Identity;
use crate::mesh::Sender;
use crate::vault::{Kind, Vault};
use crate::net;
use serde_json::{Value, json};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use subtle::ConstantTimeEq;
use std::time::Duration;

pub struct App {
    pub cfg: Config,
    pub ident: crate::mesh::IdSlot,
    pub vault: Arc<Mutex<Vault>>,
    pub gate: Gate,
    pub sender: Mutex<Sender>,
    pub token: String,
    /// Key for the model server, when it has one. Sent on every upstream call.
    pub(crate) llama_key: Option<String>,
    pub floor: crate::keys::Kdf,
    pub(crate) jobs: crate::api::Jobs,
    /// Chat streams in flight (cap `stream::MAX_STREAMS`).
    pub(crate) streams: AtomicUsize,
    /// Inbound peer messages accepted since boot. A count only; shared with the mesh listener.
    pub(crate) received: Arc<AtomicU64>,
}

/// A validated chat request: the conversation, the clean messages, and their texts.
type ChatParts = (String, Vec<Value>, Vec<String>);

/// What a request resolves to: a complete body, or an event stream the daemon writes as it arrives.
pub enum Reply {
    Plain(u16, String),
    /// The events, and the place held until the response writer has returned.
    Stream(Receiver<Vec<u8>>, StreamSlot),
}

/// One of the `MAX_STREAMS` places; released when the stream thread ends, however it ends.
pub struct StreamSlot(Arc<App>);

impl Drop for StreamSlot {
    fn drop(&mut self) {
        self.0.streams.fetch_sub(1, Ordering::SeqCst);
    }
}

/// True when the `Accept` header names `text/event-stream` (any case, parameters allowed) and does
/// not refuse it with `q=0` (RFC 9110: a quality of zero means "not acceptable").
pub fn accepts_event_stream(accept: Option<&str>) -> bool {
    accept.is_some_and(|a| {
        a.split(',').any(|m| {
            let mut parts = m.split(';');
            let named = parts.next().is_some_and(|t| t.trim().eq_ignore_ascii_case("text/event-stream"));
            let refused = parts.any(|p| {
                p.split_once('=').is_some_and(|(k, v)| {
                    k.trim().eq_ignore_ascii_case("q") && v.trim().parse::<f32>().is_ok_and(|q| q == 0.0)
                })
            });
            named && !refused
        })
    })
}

pub const MAX_BODY: usize = 1 << 20;

pub(crate) fn j(code: u16, v: Value) -> (u16, String) {
    (code, v.to_string())
}

pub(crate) fn blocked(stage: &str, cats: Vec<String>) -> (u16, String) {
    j(403, json!({"blocked": true, "stage": stage, "categories": cats}))
}

/// True only for `ip`, `ip:port` or `[v6]:port` where the IP literal is loopback or the bind address.
/// Any name (localhost included) is refused: that is the DNS-rebinding shape.
pub fn host_allowed(host: &str, bind: IpAddr) -> bool {
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    let ip: Option<IpAddr> = if let Some(rest) = host.strip_prefix('[') {
        match rest.split_once(']') {
            Some((inner, tail)) if tail.is_empty() || tail.strip_prefix(':').is_some_and(digits) => inner.parse().ok(),
            _ => None,
        }
    } else if let Ok(ip) = host.parse::<IpAddr>() {
        Some(ip)
    } else {
        match host.rsplit_once(':') {
            Some((h, port)) if digits(port) => h.parse::<std::net::Ipv4Addr>().ok().map(IpAddr::V4),
            _ => None,
        }
    };
    ip.is_some_and(|ip| ip.is_loopback() || ip == bind)
}

/// Shape of every vault route while the vault is SEALED: 423 Locked. Nothing else uses 423.
pub(crate) fn locked() -> (u16, String) {
    j(423, json!({"error": "vault locked"}))
}

/// The key unwrapped but this vault was not sealed by it. 503, and the body must not contain the
/// word "lock": that word means "ask for the passphrase", and this is not that.
pub(crate) fn mismatch() -> (u16, String) {
    j(503, json!({"error": "key opened but this vault was not sealed by it"}))
}

impl App {
    /// The unwrapped identity, or None while locked.
    pub fn identity(&self) -> Option<Arc<Identity>> {
        self.ident.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Unwrap the key with the supplied words and open the vault with it. The words are used here and dropped.
    pub fn open_with(&self, words: &str) -> Result<(), String> {
        let id = Identity::load_with_floor(&self.cfg.key_file, words, self.floor)?;
        self.vault.lock().unwrap_or_else(|e| e.into_inner()).probe(&id).map_err(|e| format!("vault mismatch: {e}"))?;
        *self.ident.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(id));
        Ok(())
    }

    /// Seal. Takes the vault mutex first, so an append in flight finishes before the key goes and
    /// none can start after; then clears the slot and every async job, so no plaintext reply
    /// survives a lock (F3). Lock order everywhere is vault, then slot.
    pub fn lock_now(&self) {
        let _v = self.vault.lock().unwrap_or_else(|e| e.into_inner());
        *self.ident.write().unwrap_or_else(|e| e.into_inner()) = None;
        crate::api::clear_jobs(&self.jobs);
    }

    /// The vault guard, or the sealed answer if the slot is empty. Checked under the mutex, which
    /// `lock_now` also takes, so nothing is written once a lock has returned.
    pub(crate) fn vault_if_unsealed(&self) -> Result<std::sync::MutexGuard<'_, Vault>, (u16, String)> {
        let g = self.vault.lock().unwrap_or_else(|e| e.into_inner());
        if self.identity().is_none() {
            return Err(locked());
        }
        Ok(g)
    }

    /// `host` and `auth` are the request's single Host and Authorization header values, if present.
    /// A streamed chat is drained to the end here (the whole event stream as one body, 200); the
    /// daemon itself calls `handle_reply` and writes the events as they arrive.
    pub fn handle(self: &Arc<Self>, method: &str, url: &str, body: &str, host: Option<&str>, auth: Option<&str>, accept: Option<&str>) -> (u16, String) {
        match self.handle_reply(method, url, body, host, auth, accept) {
            Reply::Plain(c, b) => (c, b),
            Reply::Stream(rx, _slot) => {
                let mut out = Vec::new();
                while let Ok(b) = rx.recv() {
                    out.extend(b);
                }
                (200, String::from_utf8_lossy(&out).into_owned())
            }
        }
    }

    pub fn handle_reply(self: &Arc<Self>, method: &str, url: &str, body: &str, host: Option<&str>, auth: Option<&str>, accept: Option<&str>) -> Reply {
        if !host.is_some_and(|h| host_allowed(h, self.cfg.chat_addr.ip())) {
            return Reply::Plain(403, String::new());
        }
        let given = auth.and_then(|a| a.strip_prefix("Bearer ")).unwrap_or("");
        if !bool::from(given.as_bytes().ct_eq(self.token.as_bytes())) {
            let (c, b) = j(401, json!({"error": "unauthorized"}));
            return Reply::Plain(c, b);
        }
        if body.len() > MAX_BODY {
            let (c, b) = j(413, json!({"error": "too large"}));
            return Reply::Plain(c, b);
        }
        let (path, query) = url.split_once('?').unwrap_or((url, ""));
        if method == "POST"
            && path == "/v1/chat"
            && let Some(r) = self.stream_request(body, accept)
        {
            return r;
        }
        let (c, b) = crate::api::dispatch(self, method, path, query, body);
        Reply::Plain(c, b)
    }

    /// `Some` when the body asks for a stream (or asks for one wrongly); `None` for an ordinary chat.
    fn stream_request(self: &Arc<Self>, body: &str, accept: Option<&str>) -> Option<Reply> {
        let req = serde_json::from_str::<Value>(body).ok()?;
        match req.get("stream") {
            None | Some(Value::Bool(false)) => return None,
            // `stream: true` alone is the 1.1 request: one JSON answer. Streaming needs the
            // client to say so with `Accept: text/event-stream` as well.
            Some(Value::Bool(true)) if !accepts_event_stream(accept) => return None,
            _ => {}
        }
        let plain = |(c, b): (u16, String)| Some(Reply::Plain(c, b));
        let Some(id) = self.identity() else { return plain(locked()) };
        if req["stream"] != true {
            return plain(j(400, json!({"error": "stream must be a boolean"})));
        }
        if req["async"] == true {
            return plain(j(400, json!({"error": "stream and async cannot be combined"})));
        }
        if !crate::stream::streaming_available() {
            return plain(j(400, json!({"error": "streaming is off: a blocklist line is longer than the hold window"})));
        }
        let (conv, clean, texts) = match self.chat_parse(&req) {
            Ok(x) => x,
            Err(e) => return plain(e),
        };
        if self.streams.fetch_add(1, Ordering::SeqCst) >= crate::stream::MAX_STREAMS {
            self.streams.fetch_sub(1, Ordering::SeqCst);
            return plain(j(429, json!({"error": "too many streams"})));
        }
        let slot = StreamSlot(self.clone());
        if let Err(cats) = self.gate.check(&texts.join("\n")) {
            return plain(blocked("prompt", cats));
        }
        let up = json!({"model": "local", "messages": clean, "stream": true}).to_string();
        let mut body = match net::http_stream_open(&self.cfg.llama_addr, "/v1/chat/completions", &up, Duration::from_secs(300), self.llama_key.as_deref()) {
            Ok((200, b)) => b,
            _ => return plain(j(502, json!({"error": "model unavailable or bad reply"}))),
        };
        let last_user = clean.iter().rev().find(|m| m["role"] == "user").and_then(|m| m["content"].as_str()).unwrap_or("").to_string();
        let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(32);
        let app = self.clone();
        std::thread::spawn(move || {
            let mut sink = crate::stream::ChanSink { tx, n: 0 };
            let sealed = || app.identity().is_none();
            let commit = |reply: &str| -> Result<Value, String> {
                let mut v = app.vault_if_unsealed().map_err(|_| "vault locked".to_string())?;
                v.append(&id, Kind::User, &conv, &last_user).and_then(|_| v.append(&id, Kind::Assistant, &conv, reply)).map_err(|_| "vault write failed".to_string())?;
                Ok(json!({"conv": conv, "choices": [{"message": {"role": "assistant", "content": reply}}], "gate": {"prompt": "pass", "reply": "pass"}}))
            };
            let hooks = crate::stream::Hooks { sealed: &sealed, commit: &commit };
            crate::stream::drive(&app.gate, &crate::stream::Params::PRODUCTION, &mut body, &mut sink, &hooks);
        });
        Some(Reply::Stream(rx, slot))
    }

    /// Validate a chat request body: the conversation name and the messages, rebuilt from role and
    /// content only so no unscanned field can ride along. Returns the conversation, the clean
    /// messages and their texts.
    fn chat_parse(&self, req: &Value) -> Result<ChatParts, (u16, String)> {
        let conv = req.get("conv").and_then(Value::as_str).unwrap_or("default");
        if !valid_name(conv) {
            return Err(j(400, json!({"error": "bad conv"})));
        }
        let Some(msgs) = req.get("messages").and_then(Value::as_array).filter(|m| !m.is_empty()) else {
            return Err(j(400, json!({"error": "messages required"})));
        };
        let mut clean = Vec::new();
        let mut texts = Vec::new();
        for m in msgs {
            match (m.get("role").and_then(Value::as_str), m.get("content").and_then(Value::as_str)) {
                (Some(r @ ("system" | "user" | "assistant")), Some(c)) => {
                    clean.push(json!({"role": r, "content": c}));
                    texts.push(c.to_string());
                }
                _ => return Err(j(400, json!({"error": "each message needs role and string content"}))),
            }
        }
        Ok((conv.to_string(), clean, texts))
    }

    pub(crate) fn chat(&self, body: &str) -> (u16, String) {
        let Some(id) = self.identity() else { return locked() };
        let Ok(req) = serde_json::from_str::<Value>(body) else { return j(400, json!({"error": "bad json"})) };
        let (conv, clean, texts) = match self.chat_parse(&req) {
            Ok(x) => x,
            Err(e) => return e,
        };
        let conv = conv.as_str();
        // Outgoing prompt: the gate first. Nothing is sent to the model on a refusal.
        if let Err(cats) = self.gate.check(&texts.join("\n")) {
            return blocked("prompt", cats);
        }
        let up = json!({"model": "local", "messages": clean, "stream": false}).to_string();
        let auth_value = self.llama_key.as_ref().map(|k| format!("Bearer {k}"));
        let auth: Vec<(&str, &str)> = auth_value.as_deref().map(|v| ("Authorization", v)).into_iter().collect();
        let reply = match net::http_with(&self.cfg.llama_addr, "POST", "/v1/chat/completions", Some(&up), Duration::from_secs(300), &auth) {
            Ok((200, b)) => serde_json::from_slice::<Value>(&b).ok().and_then(|v| v["choices"][0]["message"]["content"].as_str().map(str::to_string)),
            _ => None,
        };
        let Some(reply) = reply else { return j(502, json!({"error": "model unavailable or bad reply"})) };
        // Reply: the gate again, before anyone sees it.
        if let Err(cats) = self.gate.check(&reply) {
            return blocked("reply", cats);
        }
        let last_user = clean.iter().rev().find(|m| m["role"] == "user").and_then(|m| m["content"].as_str()).unwrap_or("");
        {
            let mut v = match self.vault_if_unsealed() {
                Ok(v) => v,
                Err(e) => return e,
            };
            if v.append(&id, Kind::User, conv, last_user).and_then(|_| v.append(&id, Kind::Assistant, conv, &reply)).is_err() {
                return j(503, json!({"error": "vault write failed; reply withheld"}));
            }
        }
        j(200, json!({"conv": conv, "choices": [{"message": {"role": "assistant", "content": reply}}], "gate": {"prompt": "pass", "reply": "pass"}}))
    }

    pub(crate) fn send(&self, body: &str) -> (u16, String) {
        let Some(id) = self.identity() else { return locked() };
        let Ok(req) = serde_json::from_str::<Value>(body) else { return j(400, json!({"error": "bad json"})) };
        let (Some(name), Some(text)) = (req["peer"].as_str(), req["text"].as_str()) else { return j(400, json!({"error": "peer and text required"})) };
        let Some(peer) = self.cfg.peers.iter().find(|p| p.name == name) else { return j(404, json!({"error": "unknown peer"})) };
        if let Err(cats) = self.gate.check(text) {
            return blocked("text", cats);
        }
        if text.len() > arrowmem_core::MAX_BODY {
            return j(413, json!({"error": "message longer than one sealed object"}));
        }
        // Same fail-closed rule as chat: a refused vault stops the send before the peer has anything.
        if self.vault.lock().unwrap_or_else(|e| e.into_inner()).chain_state(&id).is_err() {
            return j(503, json!({"error": "vault refused; nothing sent"}));
        }
        if let Err(e) = self.sender.lock().unwrap_or_else(|e| e.into_inner()).send(&id, peer, text) {
            return j(502, json!({"error": e}));
        }
        let mut v = match self.vault_if_unsealed() {
            Ok(v) => v,
            Err(_) => return j(503, json!({"error": "message delivered to the peer but not recorded: vault write failed", "delivered": true})),
        };
        if v.append(&id, Kind::PeerOut, &format!("peer-{name}"), text).is_err() {
            return j(503, json!({"error": "message delivered to the peer but not recorded: vault write failed", "delivered": true}));
        }
        j(200, json!({"sent": true}))
    }

    pub(crate) fn history(&self, query: &str) -> (u16, String) {
        let Some(id) = self.identity() else { return locked() };
        let conv = query.split('&').find_map(|kv| kv.strip_prefix("conv=")).unwrap_or("default");
        if !valid_name(conv) {
            return j(400, json!({"error": "bad conv"}));
        }
        let v = self.vault.lock().unwrap_or_else(|e| e.into_inner());
        match v.read(&id, conv) {
            Ok(es) => {
                let k = |k: Kind| match k { Kind::User => "user", Kind::Assistant => "assistant", Kind::PeerIn => "peer_in", Kind::PeerOut => "peer_out" };
                j(200, json!({"conv": conv, "entries": es.iter().map(|e| json!({"id": e.msg_id, "kind": k(e.kind), "text": e.text})).collect::<Vec<_>>()}))
            }
            Err(_) => j(500, json!({"error": "vault read failed"})),
        }
    }
}

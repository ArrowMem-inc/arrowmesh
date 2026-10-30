//! The /v1 loopback API: routing table and the routes added on top of chat, send, history, status.
//!
//! Frozen contract: `openapi/arrowmesh-v1.yaml`, served at `GET /v1/openapi.yaml`. Additive changes
//! only; a break is /v2. `app.rs::handle` runs the Host check, the bearer token check and the body
//! cap BEFORE anything here, so every route in this file is behind them. Nothing here logs.
//! Ceilings: the in-memory chat job table, send log and unlock throttle are process state and
//! start empty after a restart.

use crate::app::{App, j};
use crate::config;
use crate::keys::Identity;
use crate::{hex, mesh, status};
use serde_json::{Value, json};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const OPENAPI: &str = include_str!("../openapi/arrowmesh-v1.yaml");

/// Every served route. The conformance test holds this table, the router and the OpenAPI document equal.
pub const ROUTES: &[(&str, &str)] = &[
    ("GET", "/v1/openapi.yaml"),
    ("GET", "/v1/status"),
    ("GET", "/v1/install"),
    ("POST", "/v1/chat"),
    ("GET", "/v1/chat/jobs/{id}"),
    ("POST", "/v1/gate/check"),
    ("GET", "/v1/history"),
    ("POST", "/v1/vault/unlock"),
    ("POST", "/v1/vault/lock"),
    ("GET", "/v1/vault/conversations"),
    ("GET", "/v1/vault/export"),
    ("GET", "/v1/peers"),
    ("POST", "/v1/peers"),
    ("POST", "/v1/send"),
    ("GET", "/v1/sends"),
    ("GET", "/v1/sends/{id}"),
];

const MAX_JOBS: usize = 64;
const MAX_RUNNING_JOBS: usize = 8;
const MAX_SENDS: usize = 256;
const EXPORT_MAX: usize = 1000;
const UNLOCK_FAILS: u32 = 5;
const UNLOCK_PAUSE: Duration = Duration::from_secs(30);

pub(crate) enum Job {
    Running,
    Done(u16, Value),
}

/// One daemon's chat jobs (held by `App`). Forgetting them all is what a lock does.
pub(crate) type Jobs = Mutex<HashMap<u64, Job>>;

/// Forget every job, running or done. A running job's thread then finds its entry gone and drops its result.
pub(crate) fn clear_jobs(jobs: &Jobs) {
    lock(jobs).clear();
}
static NEXT_JOB: Mutex<u64> = Mutex::new(1);
static RUNNING: AtomicUsize = AtomicUsize::new(0);

struct SendRec {
    id: u64,
    peer: String,
    state: &'static str,
    categories: Vec<String>,
    reason: Option<String>,
}
static SENDS: Mutex<Option<(u64, VecDeque<SendRec>)>> = Mutex::new(None);
static UNLOCK: Mutex<(u32, Option<Instant>)> = Mutex::new((0, None));
static PEERS_FILE: Mutex<()> = Mutex::new(());

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn parse_body(body: &str) -> Result<Value, (u16, String)> {
    serde_json::from_str::<Value>(body).map_err(|_| j(400, json!({"error": "bad json"})))
}

fn matches_pattern(pattern: &str, path: &str) -> bool {
    let (p, q): (Vec<&str>, Vec<&str>) = (pattern.split('/').collect(), path.split('/').collect());
    p.len() == q.len() && p.iter().zip(&q).all(|(a, b)| if *a == "{id}" { !b.is_empty() } else { a == b })
}

pub fn dispatch(app: &Arc<App>, method: &str, path: &str, query: &str, body: &str) -> (u16, String) {
    let tail = |prefix: &str| path.strip_prefix(prefix).filter(|s| !s.is_empty() && !s.contains('/'));
    // While locked, every route that reads or writes the vault, or hands out a chat reply, answers 423 "vault locked".
    let needs_vault = matches!((method, path), ("POST", "/v1/chat" | "/v1/send") | ("GET", "/v1/history" | "/v1/vault/conversations" | "/v1/vault/export"))
        || (method == "GET" && tail("/v1/chat/jobs/").is_some());
    if needs_vault && app.identity().is_none() {
        return crate::app::locked();
    }
    match (method, path) {
        ("GET", "/v1/openapi.yaml") => (200, OPENAPI.to_string()),
        ("GET", "/v1/status") => {
            let r = status::collect_shared(&app.cfg, &app.vault, app.identity().as_deref());
            j(200, json!({"api": "v1", "model_up": r.model_up, "gate_up": r.gate_up, "vault_unlocked": r.vault_unlocked,
                "vault_records": r.vault_records, "peers_total": r.peers_total, "peers_reachable": r.peers_reachable,
                "streaming": crate::stream::streaming_available(), "model_keyed": app.llama_key.is_some(), "messages_received": app.received.load(Ordering::Relaxed), "gate_verdicts": app.gate.verdicts()}))
        }
        ("GET", "/v1/install") => install_state(app),
        ("POST", "/v1/chat") => chat(app, body),
        ("GET", _) if tail("/v1/chat/jobs/").is_some() => chat_job(app, tail("/v1/chat/jobs/").unwrap_or("")),
        ("POST", "/v1/gate/check") => gate_check(app, body),
        ("GET", "/v1/history") => app.history(query),
        ("POST", "/v1/vault/unlock") => unlock(app, body),
        ("POST", "/v1/vault/lock") => {
            app.lock_now();
            j(200, json!({"locked": true}))
        }
        ("GET", "/v1/vault/conversations") => conversations(app),
        ("GET", "/v1/vault/export") => export(app, query),
        ("GET", "/v1/peers") => peers_list(app, query),
        ("POST", "/v1/peers") => peers_add(app, body),
        ("POST", "/v1/send") => send(app, body),
        ("GET", "/v1/sends") => sends_list(),
        ("GET", _) if tail("/v1/sends/").is_some() => send_one(tail("/v1/sends/").unwrap_or("")),
        _ if ROUTES.iter().any(|(_, p)| matches_pattern(p, path)) => j(405, json!({"error": "method not allowed"})),
        _ => j(404, json!({"error": "not found"})),
    }
}

fn q_get<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    query.split('&').find_map(|kv| kv.strip_prefix(key).and_then(|r| r.strip_prefix('=')))
}

fn install_state(app: &App) -> (u16, String) {
    let c = &app.cfg;
    j(200, json!({"key_present": c.key_file.exists(), "token_present": c.token_file.exists(), "vault_present": c.vault_dir.join("r").is_dir(),
        "model_configured": c.model_path.is_some(), "peers_configured": c.peers.len()}))
}

fn chat(app: &Arc<App>, body: &str) -> (u16, String) {
    let is_async = serde_json::from_str::<Value>(body).ok().is_some_and(|v| v["async"] == true);
    if !is_async {
        return app.chat(body);
    }
    if RUNNING.load(Ordering::SeqCst) >= MAX_RUNNING_JOBS {
        return j(429, json!({"error": "too many chats running"}));
    }
    let id = {
        let mut map = lock(&app.jobs);
        if map.len() >= MAX_JOBS {
            // Drop the oldest finished job; if every slot is running, refuse.
            let oldest = map.iter().filter(|(_, v)| matches!(v, Job::Done(..))).map(|(k, _)| *k).min();
            match oldest {
                Some(k) => {
                    map.remove(&k);
                }
                None => return j(429, json!({"error": "too many chats running"})),
            }
        }
        let mut n = lock(&NEXT_JOB);
        let id = *n;
        *n += 1;
        map.insert(id, Job::Running);
        id
    };
    RUNNING.fetch_add(1, Ordering::SeqCst);
    let (a, b) = (app.clone(), body.to_string());
    std::thread::spawn(move || {
        let (code, out) = a.chat(&b);
        let v = serde_json::from_str::<Value>(&out).unwrap_or(Value::Null);
        // Only a job still in the table gets a result: a lock in between cleared it (F3).
        if let Some(slot) = lock(&a.jobs).get_mut(&id) {
            *slot = Job::Done(code, v);
        }
        RUNNING.fetch_sub(1, Ordering::SeqCst);
    });
    j(202, json!({"job": id}))
}

/// A finished job is returned once and then forgotten, so a reply does not linger in memory.
fn chat_job(app: &App, id: &str) -> (u16, String) {
    let Ok(id) = id.parse::<u64>() else { return j(404, json!({"error": "unknown id"})) };
    let mut map = lock(&app.jobs);
    match map.get(&id) {
        None => j(404, json!({"error": "unknown id"})),
        Some(Job::Running) => j(200, json!({"state": "running"})),
        Some(Job::Done(..)) => {
            let Some(Job::Done(code, v)) = map.remove(&id) else { unreachable!() };
            j(200, json!({"state": "done", "status": code, "result": v}))
        }
    }
}

fn gate_check(app: &App, body: &str) -> (u16, String) {
    let req = match parse_body(body) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let Some(text) = req["text"].as_str() else { return j(400, json!({"error": "text required"})) };
    match app.gate.check(text) {
        Ok(()) => j(200, json!({"verdict": "pass", "categories": []})),
        Err(cats) => j(200, json!({"verdict": "block", "categories": cats})),
    }
}

/// Locked: unwraps the identity key with the supplied passphrase and opens the vault (v1.1).
/// Already unlocked: re-checks the passphrase against the key file and changes nothing.
/// The phrase is never echoed, stored or logged. Every attempt, right or wrong, is counted in a 30 second window that opens at the first counted attempt; the sixth inside the window is refused (429) until it ends; a right phrase resets the count.
fn unlock(app: &App, body: &str) -> (u16, String) {
    let req = match parse_body(body) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let Some(phrase) = req["passphrase"].as_str().filter(|p| !p.is_empty()) else { return j(400, json!({"error": "passphrase required"})) };
    // Count the attempt under one lock before the (slow) check, so parallel guesses cannot all
    // pass the gate together. A right phrase resets the count.
    {
        let mut g = lock(&UNLOCK);
        if g.1.is_some_and(|t| t.elapsed() >= UNLOCK_PAUSE) {
            *g = (0, None);
        }
        if let Some(t) = g.1
            && g.0 >= UNLOCK_FAILS
        {
            return j(429, json!({"error": "too many attempts", "retry_after": (UNLOCK_PAUSE - t.elapsed()).as_secs() + 1}));
        }
        g.0 += 1;
        g.1.get_or_insert_with(Instant::now);
    }
    let ok = if app.identity().is_none() { app.open_with(phrase) } else { Identity::load_with_floor(&app.cfg.key_file, phrase, app.floor).map(|_| ()) };
    match ok {
        Ok(()) => {
            *lock(&UNLOCK) = (0, None);
            j(200, json!({"unlocked": true}))
        }
        // Key unwrapped but the vault would not open under it: stay sealed, say so without the word "lock".
        Err(e) if e.starts_with("vault mismatch") => crate::app::mismatch(),
        Err(_) => j(401, json!({"error": "wrong passphrase"})),
    }
}

fn conversations(app: &App) -> (u16, String) {
    let Some(id) = app.identity() else { return crate::app::locked() };
    let v = lock(&app.vault);
    match v.read_all(&id) {
        Ok(all) => {
            let mut order: Vec<String> = Vec::new();
            let mut m: HashMap<String, (usize, u64)> = HashMap::new();
            for (c, e) in all {
                if !m.contains_key(&c) {
                    order.push(c.clone());
                }
                let s = m.entry(c).or_insert((0, 0));
                s.0 += 1;
                s.1 = e.msg_id;
            }
            let list: Vec<Value> = order.iter().map(|c| json!({"name": c, "messages": m[c].0, "last_msg_id": m[c].1})).collect();
            j(200, json!({"conversations": list}))
        }
        Err(_) => j(500, json!({"error": "vault read failed"})),
    }
}

/// The sealed export: the vault's own ciphertext objects, hex, in record order. No plaintext leaves
/// in this route; a holder of the identity key can open them, nobody else can.
fn export(app: &App, query: &str) -> (u16, String) {
    let from = match q_get(query, "from").map(str::parse::<u64>) {
        None => 1,
        Some(Ok(n)) if n >= 1 => n,
        _ => return j(400, json!({"error": "bad from"})),
    };
    let limit = match q_get(query, "limit").map(str::parse::<usize>) {
        None => EXPORT_MAX,
        Some(Ok(n)) if (1..=EXPORT_MAX).contains(&n) => n,
        _ => return j(400, json!({"error": "bad limit"})),
    };
    let vault = lock(&app.vault); // held for the whole read so a concurrent append cannot split records from head
    let root = vault.dir().to_path_buf();
    let dir = root.join("r");
    let Ok(rd) = std::fs::read_dir(&dir) else { return j(500, json!({"error": "vault read failed"})) };
    let mut nums: Vec<u64> = rd
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            let n = u64::from_str_radix(name.strip_suffix(".obj")?, 16).ok()?;
            (name == format!("{n:016x}.obj")).then_some(n)
        })
        .collect();
    nums.sort();
    let total = nums.len();
    let mut recs = Vec::new();
    let mut next = Value::Null;
    for n in nums.into_iter().filter(|n| *n >= from) {
        if recs.len() == limit {
            next = json!(n);
            break;
        }
        let Ok(obj) = std::fs::read(dir.join(format!("{n:016x}.obj"))) else { return j(500, json!({"error": "vault read failed"})) };
        recs.push(json!({"n": n, "object": hex::enc(&obj)}));
    }
    let mut out = json!({"format": "arrowmesh-sealed-v1", "total": total, "records": recs, "next": next});
    if next.is_null() {
        // The sealed head record rides on the last page only: restore needs it, and an export
        // without it (cut at the tail) is refused by the vault on open.
        match std::fs::read(root.join("head")) {
            Ok(h) => out["head"] = json!(hex::enc(&h)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => out["head"] = Value::Null,
            Err(_) => return j(500, json!({"error": "vault read failed"})),
        }
    }
    j(200, out)
}

fn peers_list(app: &App, query: &str) -> (u16, String) {
    let probe = q_get(query, "probe") == Some("1");
    let mut out: Vec<Value> = app
        .cfg
        .peers
        .iter()
        .map(|p| {
            let mut v = json!({"name": p.name, "addr": p.addr.to_string(), "sign_pub": hex::enc(&p.sign_pub), "seal_pub": hex::enc(&p.seal_pub), "active": true});
            if probe {
                v["reachable"] = json!(mesh::reachable(p));
            }
            v
        })
        .collect();
    for p in config::read_pending(&app.cfg.key_file) {
        if !app.cfg.peers.iter().any(|q| q.name == p.name) {
            out.push(json!({"name": p.name, "addr": p.addr.to_string(), "sign_pub": hex::enc(&p.sign_pub), "seal_pub": hex::enc(&p.seal_pub), "active": false}));
        }
    }
    j(200, json!({"peers": out}))
}

/// The mesh listener and sender hold the peer list read at start, so an added peer is written to a
/// sidecar file beside the identity key and becomes active on the next restart (`active:false` until then).
fn peers_add(app: &App, body: &str) -> (u16, String) {
    let req = match parse_body(body) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let f = |k: &str| req[k].as_str().filter(|s| !s.is_empty() && !s.contains(char::is_whitespace));
    let (Some(name), Some(addr), Some(sp), Some(lp)) = (f("name"), f("addr"), f("sign_pub"), f("seal_pub")) else {
        return j(400, json!({"error": "name, addr, sign_pub and seal_pub required"}));
    };
    let line = format!("{name} {addr} {sp} {lp}");
    let peer = match config::parse_peer(&line) {
        Ok(p) => p,
        Err(_) => return j(400, json!({"error": "bad peer"})),
    };
    let _g = lock(&PEERS_FILE);
    let path = config::pending_peers_path(&app.cfg.key_file);
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    let taken = app.cfg.peers.iter().any(|p| p.name == peer.name) || config::read_pending(&app.cfg.key_file).iter().any(|p| p.name == peer.name);
    if taken {
        return j(409, json!({"error": "peer name already exists"}));
    }
    let mut text = existing;
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(&line);
    text.push('\n');
    if crate::fsio::write_atomic(&path, text.as_bytes()).is_err() {
        return j(500, json!({"error": "could not save peer"}));
    }
    j(202, json!({"added": true, "name": peer.name, "active": false, "restart_required": true}))
}

fn record_send(peer: &str, state: &'static str, categories: Vec<String>, reason: Option<String>) -> u64 {
    let mut g = lock(&SENDS);
    let (next, q) = g.get_or_insert_with(|| (1, VecDeque::new()));
    let id = *next;
    *next += 1;
    if q.len() >= MAX_SENDS {
        q.pop_front();
    }
    q.push_back(SendRec { id, peer: peer.to_string(), state, categories, reason });
    id
}

fn send_json(r: &SendRec) -> Value {
    json!({"id": r.id, "peer": r.peer, "state": r.state, "categories": r.categories, "reason": r.reason})
}

fn send(app: &App, body: &str) -> (u16, String) {
    let (code, out) = app.send(body);
    let peer = serde_json::from_str::<Value>(body).ok().and_then(|v| v["peer"].as_str().map(str::to_string)).unwrap_or_default();
    let mut v = serde_json::from_str::<Value>(&out).unwrap_or(Value::Null);
    let id = match code {
        200 => record_send(&peer, "delivered", vec![], None),
        403 if v["blocked"] == true => {
            let cats = v["categories"].as_array().map(|a| a.iter().filter_map(|c| c.as_str().map(str::to_string)).collect()).unwrap_or_default();
            record_send(&peer, "blocked", cats, None)
        }
        503 if v["delivered"] == true => record_send(&peer, "delivered", vec![], None),
        502 => record_send(&peer, "failed", vec![], v["error"].as_str().map(str::to_string)),
        _ => return (code, out),
    };
    if let Some(o) = v.as_object_mut() {
        o.insert("send_id".into(), json!(id));
        if code == 200 {
            o.insert("state".into(), json!("delivered"));
        }
    }
    (code, v.to_string())
}

fn sends_list() -> (u16, String) {
    let g = lock(&SENDS);
    let list: Vec<Value> = g.as_ref().map(|(_, q)| q.iter().rev().map(send_json).collect()).unwrap_or_default();
    j(200, json!({"sends": list}))
}

fn send_one(id: &str) -> (u16, String) {
    let Ok(id) = id.parse::<u64>() else { return j(404, json!({"error": "unknown id"})) };
    let g = lock(&SENDS);
    match g.as_ref().and_then(|(_, q)| q.iter().find(|r| r.id == id)) {
        Some(r) => j(200, send_json(r)),
        None => j(404, json!({"error": "unknown id"})),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pattern_matching() {
        assert!(matches_pattern("/v1/sends/{id}", "/v1/sends/7"));
        assert!(!matches_pattern("/v1/sends/{id}", "/v1/sends/"));
        assert!(!matches_pattern("/v1/sends/{id}", "/v1/sends/7/x"));
        assert!(matches_pattern("/v1/status", "/v1/status"));
    }
}

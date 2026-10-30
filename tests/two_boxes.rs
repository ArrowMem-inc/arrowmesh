//! Two instances on loopback ports exchange sealed messages; the gate path fails closed.

use arrowmesh::config::{Config, Peer};
use arrowmesh::daemon::{self, Running};
use arrowmesh::gatepath::Gate;
use arrowmesh::keys::{Identity, Kdf};
use arrowmesh::{net, testutil};
use arrowmem_core::{OBJECT_SIZE, seal};
use hpke::Deserializable;
use serde_json::{Value, json};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

/// A stand-in for llama.cpp: /health, and /v1/chat/completions that answers with `reply`.
struct FakeLlama {
    addr: SocketAddr,
    hits: Arc<AtomicUsize>,
    last: Arc<std::sync::Mutex<String>>,
    server: Arc<tiny_http::Server>,
    h: Option<std::thread::JoinHandle<()>>,
}

impl FakeLlama {
    fn start(reply: &str) -> FakeLlama {
        let server = Arc::new(tiny_http::Server::http("127.0.0.1:0").unwrap());
        let addr = server.server_addr().to_ip().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let last = Arc::new(std::sync::Mutex::new(String::new()));
        let lc = last.clone();
        let (s, hc, reply) = (server.clone(), hits.clone(), reply.to_string());
        let h = std::thread::spawn(move || {
            for mut req in s.incoming_requests() {
                let mut body = String::new();
                let _ = req.as_reader().read_to_string(&mut body);
                *lc.lock().unwrap() = body;
                let out = if req.url() == "/health" {
                    "{\"status\":\"ok\"}".to_string()
                } else {
                    hc.fetch_add(1, Ordering::SeqCst);
                    json!({"choices":[{"message":{"role":"assistant","content":reply}}]}).to_string()
                };
                let _ = req.respond(tiny_http::Response::from_string(out));
            }
        });
        FakeLlama { addr, hits, last, server, h: Some(h) }
    }
}

impl Drop for FakeLlama {
    fn drop(&mut self) {
        self.server.unblock();
        if let Some(h) = self.h.take() {
            let _ = h.join();
        }
    }
}

struct Box_ {
    run: Running,
    cfg: Config,
    id: Identity,
}

fn cfg_for(tag: &str, llama: SocketAddr) -> (Config, Identity) {
    let home = testutil::tmp(tag);
    let mut c = Config::defaults(&home);
    c.chat_addr = "127.0.0.1:0".parse().unwrap();
    c.mesh_listen = "127.0.0.1:0".parse().unwrap();
    c.llama_addr = llama;
    let id = Identity::generate().unwrap();
    id.save_new_with(&c.key_file, PHRASE, Kdf::TEST).unwrap();
    arrowmesh::token::create_new(&c.token_file).unwrap();
    (c, id)
}

const PHRASE: &str = "integration test phrase";

/// Running servers by chat address, so `call` can find the API credential written for each one.
static CREDS: std::sync::Mutex<Vec<(SocketAddr, String)>> = std::sync::Mutex::new(Vec::new());

fn start(c: Config, gate: Gate) -> Running {
    let cred = arrowmesh::token::load(&c.token_file).unwrap();
    let r = daemon::start_with_floor(c, gate, PHRASE, Kdf::TEST).unwrap();
    CREDS.lock().unwrap().push((r.chat_addr, cred));
    r
}

fn cred_for(addr: SocketAddr) -> String {
    CREDS.lock().unwrap().iter().rev().find(|(a, _)| *a == addr).map(|(_, t)| t.clone()).unwrap()
}

fn auth_value(addr: SocketAddr) -> String {
    format!("Bearer {}", cred_for(addr))
}

fn peer(name: &str, addr: SocketAddr, id: &Identity) -> Peer {
    Peer { name: name.into(), addr, sign_pub: id.sign_pub(), seal_pub: id.seal_pub() }
}

fn call(addr: SocketAddr, m: &str, path: &str, body: Value) -> (u16, Value) {
    let auth = auth_value(addr);
    let (c, b) = net::http_with(&addr, m, path, Some(&body.to_string()), Duration::from_secs(10), &[("Authorization", &auth)]).unwrap();
    (c, serde_json::from_slice(&b).unwrap_or(Value::Null))
}

/// A raw request with chosen headers, for the credential and Host checks.
fn raw(addr: SocketAddr, host: Option<&str>, auth: Option<&str>) -> (u16, Vec<u8>) {
    let mut h: Vec<(&str, &str)> = Vec::new();
    if let Some(x) = host {
        h.push(("Host", x));
    }
    if let Some(x) = auth {
        h.push(("Authorization", x));
    }
    net::http_with(&addr, "GET", "/v1/history?conv=default", None, Duration::from_secs(10), &h).unwrap()
}

fn two_boxes(llama: SocketAddr) -> (Box_, Box_) {
    // Bob first, so Alice can be given his real mesh address. Bob only needs Alice's keys.
    let (mut cb, idb) = cfg_for("bob", llama);
    let (mut ca, ida) = cfg_for("alice", llama);
    cb.peers.push(peer("alice", "127.0.0.1:1".parse().unwrap(), &ida));
    let rb = start(cb.clone(), Gate::new(None));
    ca.peers.push(peer("bob", rb.mesh_addr, &idb));
    let ra = start(ca.clone(), Gate::new(None));
    (Box_ { run: ra, cfg: ca, id: ida }, Box_ { run: rb, cfg: cb, id: idb })
}

#[test]
fn two_instances_exchange_one_sealed_message() {
    let llama = FakeLlama::start("ok");
    let (a, b) = two_boxes(llama.addr);
    let (code, v) = call(a.run.chat_addr, "POST", "/v1/send", json!({"peer":"bob","text":"meet at the shop at noon"}));
    assert_eq!((code, v["sent"].as_bool()), (200, Some(true)), "{v}");
    // Bob's vault holds it, decrypted only through his own key.
    let (code, v) = call(b.run.chat_addr, "GET", "/v1/history?conv=peer-alice", json!(null));
    assert_eq!(code, 200);
    assert_eq!(v["entries"][0]["text"], "meet at the shop at noon");
    assert_eq!(v["entries"][0]["kind"], "peer_in");
    // Alice kept her own sent copy.
    let (_, v) = call(a.run.chat_addr, "GET", "/v1/history?conv=peer-bob", json!(null));
    assert_eq!(v["entries"][0]["kind"], "peer_out");
    // What is on Bob's disk is sealed objects only.
    for e in std::fs::read_dir(b.cfg.vault_dir.join("r")).unwrap().flatten() {
        let bytes = std::fs::read(e.path()).unwrap();
        assert_eq!(bytes.len(), OBJECT_SIZE);
        assert!(!bytes.windows(8).any(|w| w == b"the shop"));
    }
    // A second message goes through (counter moves on), and status counts it.
    let (code, _) = call(a.run.chat_addr, "POST", "/v1/send", json!({"peer":"bob","text":"second"}));
    assert_eq!(code, 200);
    let (_, st) = call(b.run.chat_addr, "GET", "/v1/status", json!(null));
    assert_eq!(st["vault_unlocked"], true);
    assert_eq!(st["vault_records"], 2);
    drop((a.id, b.id));
    a.run.stop();
    b.run.stop();
}

#[test]
fn a_stranger_and_a_replay_are_refused_over_the_wire() {
    let llama = FakeLlama::start("ok");
    let (a, b) = two_boxes(llama.addr);
    let bob_seal = <arrowmem_core::SealPublicKey as Deserializable>::from_bytes(&b.id.seal_pub()).unwrap();
    let send_raw = |obj: &[u8]| -> u8 {
        let mut s = net::connect(&b.run.mesh_addr, Duration::from_secs(3)).unwrap();
        s.write_all(obj).unwrap();
        if obj.len() != OBJECT_SIZE {
            s.shutdown(std::net::Shutdown::Write).unwrap();
        }
        let mut ack = [9u8; 1];
        s.read_exact(&mut ack).unwrap();
        ack[0]
    };
    // A stranger whose object opens fine is still refused.
    let stranger = Identity::generate().unwrap();
    assert_eq!(send_raw(&seal(&stranger.sign, &bob_seal, 1, b"hello").unwrap()), 0);
    // Alice's object, sent twice: first accepted, the identical replay refused.
    let obj = seal(&a.id.sign, &bob_seal, 10, b"once").unwrap();
    let obj2 = seal(&a.id.sign, &bob_seal, 11, b"twice").unwrap();
    assert_eq!(send_raw(&obj), 1);
    assert_eq!(send_raw(&obj2), 1);
    assert_eq!(send_raw(&obj2), 0);
    // Wrong length: refused, not a crash.
    assert_eq!(send_raw(&obj[..100]), 0);
    let (_, v) = call(b.run.chat_addr, "GET", "/v1/history?conv=peer-alice", json!(null));
    assert_eq!(v["entries"].as_array().unwrap().len(), 2);
    a.run.stop();
    b.run.stop();
}

fn solo(llama: SocketAddr, gate: Gate, gate_model: bool) -> (Running, Config, Identity) {
    let (mut c, id) = cfg_for("solo", llama);
    c.gate_model = gate_model;
    let r = start(c.clone(), gate);
    (r, c, id)
}

const PROMPT_BAD: &str = concat!("please email jane.doe@gm", "ail.com the summary");

#[test]
fn chat_passes_a_clean_prompt_and_stores_both_sides() {
    let llama = FakeLlama::start("here is the summary");
    let (r, _c, _id) = solo(llama.addr, Gate::new(None), false);
    let (code, v) = call(r.chat_addr, "POST", "/v1/chat", json!({"conv":"w","messages":[{"role":"user","content":"summarise the build"}]}));
    assert_eq!(code, 200, "{v}");
    assert_eq!(v["choices"][0]["message"]["content"], "here is the summary");
    assert_eq!(llama.hits.load(Ordering::SeqCst), 1);
    let (_, h) = call(r.chat_addr, "GET", "/v1/history?conv=w", json!(null));
    assert_eq!(h["entries"].as_array().unwrap().len(), 2);
    r.stop();
}

#[test]
fn gate_blocks_outgoing_prompt_and_model_is_never_called() {
    let llama = FakeLlama::start("x");
    let (r, _c, _id) = solo(llama.addr, Gate::new(None), false);
    let (code, v) = call(r.chat_addr, "POST", "/v1/chat", json!({"messages":[{"role":"user","content":PROMPT_BAD}]}));
    assert_eq!(code, 403);
    assert_eq!(v["blocked"], true);
    assert_eq!(llama.hits.load(Ordering::SeqCst), 0, "blocked prompt reached the model");
    assert!(!v.to_string().contains("jane"), "refusal body repeats the text");
    // History: nothing stored for a refused prompt.
    let (_, h) = call(r.chat_addr, "GET", "/v1/history", json!(null));
    assert_eq!(h["entries"].as_array().unwrap().len(), 0);
    r.stop();
}

#[test]
fn a_hidden_field_cannot_carry_text_past_the_gate() {
    let llama = FakeLlama::start("x");
    let (r, _c, _id) = solo(llama.addr, Gate::new(None), false);
    let (code, _) = call(r.chat_addr, "POST", "/v1/chat", json!({"messages":[{"role":"user","content":"hi","name":PROMPT_BAD}]}));
    // The extra field is dropped before forwarding; the model must never see its text.
    assert_eq!(code, 200);
    assert!(!llama.last.lock().unwrap().contains("jane"), "an unscanned field reached the model");
    r.stop();
}

#[test]
fn gate_blocks_a_reply_that_leaks() {
    let llama = FakeLlama::start(concat!("sure, her address is jane.doe@gm", "ail.com"));
    let (r, _c, _id) = solo(llama.addr, Gate::new(None), false);
    let (code, v) = call(r.chat_addr, "POST", "/v1/chat", json!({"conv":"w","messages":[{"role":"user","content":"who do I write to"}]}));
    assert_eq!(code, 403);
    assert!(!v.to_string().contains("jane"));
    assert_eq!(llama.hits.load(Ordering::SeqCst), 1);
    let (_, h) = call(r.chat_addr, "GET", "/v1/history?conv=w", json!(null));
    assert_eq!(h["entries"].as_array().unwrap().len(), 0, "a withheld reply was stored");
    r.stop();
}

#[test]
fn fail_closed_when_the_scan_panics() {
    let llama = FakeLlama::start("x");
    let (r, _c, _id) = solo(llama.addr, Gate::with_scan(|_| panic!("scan blew up")), false);
    let (code, _) = call(r.chat_addr, "POST", "/v1/chat", json!({"messages":[{"role":"user","content":"hello"}]}));
    assert_eq!(code, 403);
    assert_eq!(llama.hits.load(Ordering::SeqCst), 0);
    r.stop();
}

#[test]
fn fail_closed_when_the_model_layer_is_unreachable() {
    // Model layer on, pointed at a port nothing listens on: even a clean prompt is refused.
    let dead: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let (c, id) = cfg_for("dead", dead);
    drop(id);
    let mut c = c;
    c.gate_model = true;
    let r = start(c.clone(), daemon::gate_for(&c));
    let (code, v) = call(r.chat_addr, "POST", "/v1/chat", json!({"messages":[{"role":"user","content":"the build is green"}]}));
    assert_eq!(code, 403, "{v}");
    assert_eq!(v["categories"][0], "model:unreachable");
    r.stop();
}

#[test]
fn peer_send_goes_through_the_gate_too() {
    let llama = FakeLlama::start("x");
    let (a, b) = two_boxes(llama.addr);
    let (code, _) = call(a.run.chat_addr, "POST", "/v1/send", json!({"peer":"bob","text":PROMPT_BAD}));
    assert_eq!(code, 403);
    let (_, st) = call(b.run.chat_addr, "GET", "/v1/status", json!(null));
    assert_eq!(st["vault_records"], 0);
    a.run.stop();
    b.run.stop();
}

#[test]
fn status_reports_counts_for_a_live_pair() {
    let llama = FakeLlama::start("x");
    let (a, b) = two_boxes(llama.addr);
    let r = arrowmesh::status::collect(&a.cfg, Some(&a.id));
    assert!(r.model_up && r.gate_up && r.vault_unlocked);
    assert_eq!((r.peers_total, r.peers_reachable), (1, 1));
    assert!(r.all_up());
    b.run.stop();
    let r2 = arrowmesh::status::collect(&a.cfg, Some(&a.id));
    assert_eq!(r2.peers_reachable, 0);
    a.run.stop();
    let _ = &b.cfg;
}

#[test]
fn m1_no_credential_and_a_wrong_credential_are_401() {
    let llama = FakeLlama::start("x");
    let (r, _c, _id) = solo(llama.addr, Gate::new(None), false);
    let bind = r.chat_addr.to_string();
    let good = auth_value(r.chat_addr);
    assert_eq!(raw(r.chat_addr, Some(&bind), None).0, 401);
    assert_eq!(raw(r.chat_addr, Some(&bind), Some("Bearer wrong")).0, 401);
    let mut near = good.clone();
    near.pop();
    near.push(if good.ends_with('0') { '1' } else { '0' });
    assert_eq!(raw(r.chat_addr, Some(&bind), Some(&near)).0, 401); // one character off
    assert_eq!(raw(r.chat_addr, Some(&bind), Some(&good[7..])).0, 401); // credential without the scheme
    assert_eq!(raw(r.chat_addr, Some(&bind), Some(&good)).0, 200);
    r.stop();
}

#[test]
fn m1_wrong_host_and_the_dns_rebinding_shape_are_403_with_no_body() {
    let llama = FakeLlama::start("x");
    let (r, _c, _id) = solo(llama.addr, Gate::new(None), false);
    let good = auth_value(r.chat_addr);
    let port = r.chat_addr.port();
    // Even WITH the right credential, a Host that is a name or a foreign IP gets nothing.
    for h in [format!("evil.example:{port}"), format!("localhost:{port}"), format!("127.0.0.1.evil.example:{port}"), format!("8.8.8.8:{port}"), String::new()] {
        let (code, body) = raw(r.chat_addr, Some(&h), Some(&good));
        assert_eq!((code, body.len()), (403, 0), "host {h:?}");
    }
    // 403 is returned before the credential is even looked at.
    assert_eq!(raw(r.chat_addr, Some(&format!("evil.example:{port}")), None).0, 403);
    // Loopback literals pass the Host check.
    assert_eq!(raw(r.chat_addr, Some(&format!("127.0.0.1:{port}")), Some(&good)).0, 200);
    assert_eq!(raw(r.chat_addr, Some("127.0.0.1"), Some(&good)).0, 200);
    r.stop();
}

#[test]
fn m1_daemon_refuses_to_start_with_a_loose_or_missing_token_file() {
    use std::os::unix::fs::PermissionsExt;
    let llama = FakeLlama::start("x");
    let (c, _id) = cfg_for("tokmode", llama.addr);
    std::fs::set_permissions(&c.token_file, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(daemon::start_with_floor(c.clone(), Gate::new(None), PHRASE, Kdf::TEST).is_err());
    std::fs::remove_file(&c.token_file).unwrap();
    assert!(daemon::start_with_floor(c, Gate::new(None), PHRASE, Kdf::TEST).is_err());
}

#[test]
fn m2_daemon_will_not_start_on_a_wrong_passphrase_and_status_says_locked() {
    let llama = FakeLlama::start("x");
    let (c, id) = cfg_for("wrongpw", llama.addr);
    assert!(daemon::start_with_floor(c.clone(), Gate::new(None), "not the phrase", Kdf::TEST).is_err());
    assert!(Identity::load_with_floor(&c.key_file, "not the phrase", Kdf::TEST).is_err());
    // An empty vault opens under any key; with one record, only the right identity unlocks it.
    arrowmesh::vault::Vault::open(c.vault_dir.clone()).unwrap().append(&id, arrowmesh::vault::Kind::User, "x", "y").unwrap();
    assert!(!arrowmesh::status::collect(&c, Some(&Identity::generate().unwrap())).vault_unlocked);
    assert!(!arrowmesh::status::collect(&c, None).vault_unlocked);
    assert!(arrowmesh::status::collect(&c, Some(&id)).vault_unlocked);
}

/// The "no internet" claim, as far as a test can hold it: every socket call in src/ is inside net.rs,
/// which refuses anything outside loopback and RFC1918 before it connects or binds.
#[test]
fn only_net_rs_opens_sockets() {
    let mut offenders = Vec::new();
    for e in std::fs::read_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/src")).unwrap().flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if name == "net.rs" || !name.ends_with(".rs") {
            continue;
        }
        let text = std::fs::read_to_string(e.path()).unwrap();
        // Strip test modules' own use of net:: helpers; look for direct std/ureq socket entry points.
        for pat in ["TcpStream::connect", "UdpSocket", "TcpListener::bind", "ToSocketAddrs", "ureq::", "tiny_http::Server::http(", "to_socket_addrs"] {
            if text.contains(pat) {
                offenders.push(format!("{name}: {pat}"));
            }
        }
    }
    assert!(offenders.is_empty(), "{offenders:?}");
}

/// N1: status after unlock never touches the key file or the KDF. The key file is deleted after
/// start, and the key is the production Argon2id cost (64 MiB, 3 passes, 4 lanes), so a status
/// call that re-ran the KDF would both fail (no file) and take far longer than this bound.
#[test]
fn n1_status_after_unlock_does_not_rerun_argon2id_and_app_keeps_no_passphrase() {
    let llama = FakeLlama::start("reply");
    let home = testutil::tmp("n1");
    let mut c = Config::defaults(&home);
    c.chat_addr = "127.0.0.1:0".parse().unwrap();
    c.mesh_listen = "127.0.0.1:0".parse().unwrap();
    c.llama_addr = llama.addr;
    Identity::generate().unwrap().save_new_with(&c.key_file, PHRASE, Kdf::PRODUCTION).unwrap();
    arrowmesh::token::create_new(&c.token_file).unwrap();
    let cred = arrowmesh::token::load(&c.token_file).unwrap();
    let r = daemon::start(c.clone(), Gate::new(None), PHRASE).unwrap();
    CREDS.lock().unwrap().push((r.chat_addr, cred));
    let (code, _) = call(r.chat_addr, "POST", "/v1/chat", json!({"conv":"w","messages":[{"role":"user","content":"hello there"}]}));
    assert_eq!(code, 200);
    std::fs::remove_file(&c.key_file).unwrap();
    let t0 = std::time::Instant::now();
    for _ in 0..5 {
        let (code, st) = call(r.chat_addr, "GET", "/v1/status", json!(null));
        assert_eq!(code, 200);
        assert_eq!(st["vault_unlocked"], true);
    }
    let el = t0.elapsed();
    assert!(el < Duration::from_millis(1500), "5 status calls took {el:?}");
    r.stop();
    // The passphrase is not a field of App.
    let app = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/app.rs")).unwrap();
    let body = app.split("pub struct App {").nth(1).unwrap().split('}').next().unwrap();
    assert!(!body.contains("pass"), "{body}");
}

fn send_obj(addr: SocketAddr, obj: &[u8]) -> u8 {
    let mut s = net::connect(&addr, Duration::from_secs(3)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(obj).unwrap();
    let mut ack = [9u8; 1];
    s.read_exact(&mut ack).unwrap();
    ack[0]
}

/// M5: one stalled LAN connection (and one that drips a byte then goes quiet) must not make a
/// second peer wait out the 3 s read timeout. Before the repair the accept loop was serial and
/// this message waited for the stalled socket to time out first.
#[test]
fn m5_a_stalled_peer_does_not_block_a_second_peers_message() {
    let llama = FakeLlama::start("ok");
    let (a, b) = two_boxes(llama.addr);
    let bob_seal = <arrowmem_core::SealPublicKey as Deserializable>::from_bytes(&b.id.seal_pub()).unwrap();
    let silent = net::connect(&b.run.mesh_addr, Duration::from_secs(3)).unwrap();
    let mut drip = net::connect(&b.run.mesh_addr, Duration::from_secs(3)).unwrap();
    drip.write_all(&[1]).unwrap();
    std::thread::sleep(Duration::from_millis(100)); // both are now parked in the listener
    let t0 = std::time::Instant::now();
    let ack = send_obj(b.run.mesh_addr, &seal(&a.id.sign, &bob_seal, 20, b"while stalled").unwrap());
    let el = t0.elapsed();
    assert_eq!(ack, 1);
    assert!(el < Duration::from_millis(1000), "second peer waited {el:?} behind a stalled connection");
    drop((silent, drip));
    a.run.stop();
    b.run.stop();
}

/// M5: concurrency is capped. With the cap's worth of stalled connections, the next one is closed
/// unanswered at once (not queued behind them), and service resumes after the stalled ones time out.
#[test]
fn m5_connections_are_capped_and_service_resumes_after_the_deadline() {
    let llama = FakeLlama::start("ok");
    let (a, b) = two_boxes(llama.addr);
    let bob_seal = <arrowmem_core::SealPublicKey as Deserializable>::from_bytes(&b.id.seal_pub()).unwrap();
    let held: Vec<_> = (0..arrowmesh::mesh::MAX_CONNS).map(|_| net::connect(&b.run.mesh_addr, Duration::from_secs(3)).unwrap()).collect();
    std::thread::sleep(Duration::from_millis(300));
    let mut over = net::connect(&b.run.mesh_addr, Duration::from_secs(3)).unwrap();
    over.set_read_timeout(Some(Duration::from_millis(800))).unwrap();
    let mut one = [0u8; 1];
    let t0 = std::time::Instant::now();
    let r = over.read(&mut one);
    assert!(matches!(r, Ok(0)) || r.is_err(), "over-cap connection got an answer: {r:?}");
    assert!(t0.elapsed() < Duration::from_millis(900));
    // After the deadline the held slots free and a real message goes through.
    std::thread::sleep(arrowmesh::mesh::CONN_DEADLINE + Duration::from_millis(700));
    let ack = send_obj(b.run.mesh_addr, &seal(&a.id.sign, &bob_seal, 30, b"after").unwrap());
    assert_eq!(ack, 1);
    drop(held);
    a.run.stop();
    b.run.stop();
}

#[test]
fn send_on_a_refused_vault_is_503_and_nothing_reaches_the_peer() {
    let llama = FakeLlama::start("x");
    let (a, b) = two_boxes(llama.addr);
    assert_eq!(call(a.run.chat_addr, "POST", "/v1/send", json!({"peer":"bob","text":"first clean note"})).0, 200);
    std::fs::remove_file(a.cfg.vault_dir.join("head")).unwrap();
    let (code, v) = call(a.run.chat_addr, "POST", "/v1/send", json!({"peer":"bob","text":"second clean note"}));
    assert_eq!(code, 503, "{v}");
    let (_, st) = call(b.run.chat_addr, "GET", "/v1/status", json!(null));
    assert_eq!(st["vault_records"], 1, "bob holds only the first note");
    a.run.stop();
    b.run.stop();
}

/// The production entry point must not boot with the test KDF or a lowered floor.
#[test]
fn main_rs_has_no_test_floor_or_test_kdf() {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs")).unwrap();
    for pat in ["_with_floor(", "Kdf::TEST"] {
        assert!(!text.contains(pat), "src/main.rs contains {pat}");
    }
}

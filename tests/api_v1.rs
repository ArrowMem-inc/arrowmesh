//! The /v1 contract: every route has a test, and the served routes equal the OpenAPI document.

use arrowmesh::config::{Config, Peer};
use arrowmesh::daemon::{self, Running};
use arrowmesh::gatepath::Gate;
use arrowmesh::keys::{Identity, Kdf};
use arrowmesh::{api, net, testutil};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

const UNWRAP: &str = "api test words";
const NOT_IT: &str = "not-the-words-xyz";
const YAML: &str = include_str!("../openapi/arrowmesh-v1.yaml");

struct FakeLlama {
    addr: SocketAddr,
    server: Arc<tiny_http::Server>,
}

impl FakeLlama {
    fn start(reply: &str) -> FakeLlama {
        let server = Arc::new(tiny_http::Server::http("127.0.0.1:0").unwrap());
        let addr = server.server_addr().to_ip().unwrap();
        let (s, reply) = (server.clone(), reply.to_string());
        std::thread::spawn(move || {
            for mut req in s.incoming_requests() {
                let mut b = String::new();
                let _ = req.as_reader().read_to_string(&mut b);
                let out = if req.url() == "/health" { "{\"status\":\"ok\"}".to_string() } else { json!({"choices":[{"message":{"role":"assistant","content":reply}}]}).to_string() };
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

struct Box_ {
    run: Running,
    cfg: Config,
    id: Identity,
    token: String,
}

fn boot_as(tag: &str, llama: SocketAddr, id: Identity, peers: Vec<Peer>) -> Box_ {
    let home = testutil::tmp(tag);
    let mut c = Config::defaults(&home);
    c.chat_addr = "127.0.0.1:0".parse().unwrap();
    c.mesh_listen = "127.0.0.1:0".parse().unwrap();
    c.llama_addr = llama;
    c.peers = peers;
    id.save_new_with(&c.key_file, UNWRAP, Kdf::TEST).unwrap();
    let token = arrowmesh::token::create_new(&c.token_file).unwrap();
    let run = daemon::start_with_floor(c.clone(), Gate::new(None), UNWRAP, Kdf::TEST).unwrap();
    Box_ { run, cfg: c, id, token }
}

fn boot(tag: &str, llama: SocketAddr, peers: Vec<Peer>) -> Box_ {
    boot_as(tag, llama, Identity::generate().unwrap(), peers)
}

impl Box_ {
    fn raw(&self, m: &str, path: &str, body: Option<Value>, host: Option<&str>, auth: Option<&str>) -> (u16, Vec<u8>) {
        let mut h: Vec<(&str, &str)> = Vec::new();
        if let Some(x) = host {
            h.push(("Host", x));
        }
        if let Some(x) = auth {
            h.push(("Authorization", x));
        }
        let b = body.map(|v| v.to_string());
        net::http_with(&self.run.chat_addr, m, path, b.as_deref(), Duration::from_secs(20), &h).unwrap()
    }
    fn call(&self, m: &str, path: &str, body: Value) -> (u16, Value) {
        let host = self.run.chat_addr.to_string();
        let auth = format!("Bearer {}", self.token);
        let b = if body.is_null() { None } else { Some(body) };
        let (c, out) = self.raw(m, path, b, Some(&host), Some(&auth));
        (c, serde_json::from_slice(&out).unwrap_or(Value::Null))
    }
    fn unlock(&self, phrase: &str) -> (u16, Value) {
        self.call("POST", "/v1/vault/unlock", json!({"passphrase": phrase}))
    }
}

fn peer_of(name: &str, addr: SocketAddr, id: &Identity) -> Peer {
    Peer { name: name.into(), addr, sign_pub: id.sign_pub(), seal_pub: id.seal_pub() }
}

/// (method, path) pairs declared in the YAML, read from the `paths:` block by indentation.
fn yaml_routes() -> Vec<(String, String)> {
    let mut out = Vec::new();
    let (mut in_paths, mut cur) = (false, String::new());
    for l in YAML.lines() {
        if l == "paths:" {
            in_paths = true;
            continue;
        }
        if in_paths && !l.is_empty() && !l.starts_with(' ') {
            break;
        }
        if !in_paths {
            continue;
        }
        if l.starts_with("  /") && l.ends_with(':') {
            cur = l.trim().trim_end_matches(':').to_string();
        } else if let Some(m) = l.strip_prefix("    ").and_then(|r| r.strip_suffix(':'))
            && ["get", "post", "put", "delete", "patch"].contains(&m)
        {
            out.push((m.to_uppercase(), cur.clone()));
        }
    }
    out
}

fn poll_job(b: &Box_, id: u64) -> Value {
    for _ in 0..100 {
        let (c, v) = b.call("GET", &format!("/v1/chat/jobs/{id}"), Value::Null);
        assert_eq!(c, 200);
        if v["state"] == "done" {
            return v;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Value::Null
}

#[test]
fn conformance_served_routes_equal_the_openapi_document() {
    let mut served: Vec<(String, String)> = api::ROUTES.iter().map(|(m, p)| (m.to_string(), p.to_string())).collect();
    let mut doc = yaml_routes();
    served.sort();
    doc.sort();
    assert_eq!(served, doc, "ROUTES and openapi/arrowmesh-v1.yaml disagree");
    assert!(doc.len() >= 15);
    let ids: Vec<&str> = YAML.lines().filter_map(|l| l.trim().strip_prefix("operationId: ")).collect();
    let mut u = ids.clone();
    u.sort();
    u.dedup();
    assert_eq!(ids.len(), doc.len());
    assert_eq!(u.len(), ids.len());
    assert!(YAML.starts_with("openapi: 3.1.0"));
    assert!(YAML.contains("security:\n  - bearerToken: []"));
}

#[test]
fn conformance_every_documented_route_is_really_served_and_nothing_else_is() {
    let llama = FakeLlama::start("ok");
    let b = boot("conf", llama.addr, vec![]);
    for (m, p) in api::ROUTES {
        let url = p.replace("{id}", "1");
        let (c, body) = b.call(m, &url, if *m == "POST" { json!({}) } else { Value::Null });
        assert!(!(c == 404 && body["error"] == "not found") && c != 405, "{m} {p} -> {c} {body}");
    }
    let (c, body) = b.call("GET", "/v1/nope", Value::Null);
    assert_eq!((c, body["error"].as_str()), (404, Some("not found")));
    assert_eq!(b.call("DELETE", "/v1/status", Value::Null).0, 405);
    assert_eq!(b.call("GET", "/v1/chat", Value::Null).0, 405);
    b.run.stop();
}

#[test]
fn the_document_is_served_behind_the_token_and_host_rules() {
    let llama = FakeLlama::start("ok");
    let b = boot("doc", llama.addr, vec![]);
    let host = b.run.chat_addr.to_string();
    let good = format!("Bearer {}", b.token);
    let (c, body) = b.raw("GET", "/v1/openapi.yaml", None, Some(&host), Some(&good));
    assert_eq!(c, 200);
    assert_eq!(String::from_utf8(body).unwrap(), YAML);
    assert_eq!(b.raw("GET", "/v1/openapi.yaml", None, Some(&host), None).0, 401);
    assert_eq!(b.raw("GET", "/v1/openapi.yaml", None, Some(&host), Some("Bearer nope")).0, 401);
    let (c, body) = b.raw("GET", "/v1/openapi.yaml", None, Some("localhost:8088"), Some(&good));
    assert_eq!((c, body.len()), (403, 0));
    let (c, body) = b.raw("GET", "/v1/openapi.yaml", None, Some(""), Some(&good));
    assert_eq!((c, body.len()), (403, 0));
    for (m, p) in api::ROUTES {
        let url = p.replace("{id}", "1");
        assert_eq!(b.raw(m, &url, None, Some(&host), None).0, 401, "{m} {p} without token");
        assert_eq!(b.raw(m, &url, None, Some("evil.example"), Some(&good)).0, 403, "{m} {p} wrong host");
    }
    b.run.stop();
}

#[test]
fn chat_carries_the_gate_verdict_and_a_block_names_its_stage() {
    let llama = FakeLlama::start("here is the summary");
    let b = boot("chat", llama.addr, vec![]);
    let (c, v) = b.call("POST", "/v1/chat", json!({"conv":"w","messages":[{"role":"user","content":"summarise the build"}]}));
    assert_eq!(c, 200, "{v}");
    assert_eq!(v["gate"], json!({"prompt":"pass","reply":"pass"}));
    let (c, v) = b.call("POST", "/v1/chat", json!({"messages":[{"role":"user","content":concat!("email jane.doe@gm", "ail.com the summary")}]}));
    assert_eq!(c, 403);
    assert_eq!((v["blocked"].clone(), v["stage"].clone()), (json!(true), json!("prompt")));
    assert!(v["categories"].as_array().unwrap().iter().any(|c| c == "personal:email"), "{v}");
    assert!(!v.to_string().contains("jane.doe"));
    b.run.stop();
    let leaky = FakeLlama::start(concat!("mail jane.doe@gm", "ail.com"));
    let b = boot("chat2", leaky.addr, vec![]);
    let (c, v) = b.call("POST", "/v1/chat", json!({"messages":[{"role":"user","content":"hello"}]}));
    assert_eq!((c, v["stage"].clone()), (403, json!("reply")));
    b.run.stop();
}

#[test]
fn async_chat_is_polled_once_and_a_block_comes_back_through_the_job() {
    let llama = FakeLlama::start("polled reply");
    let b = boot("job", llama.addr, vec![]);
    let (c, v) = b.call("POST", "/v1/chat", json!({"async":true,"messages":[{"role":"user","content":"hi there"}]}));
    assert_eq!(c, 202, "{v}");
    let id = v["job"].as_u64().unwrap();
    let done = poll_job(&b, id);
    assert_eq!(done["status"], 200, "{done}");
    assert_eq!(done["result"]["choices"][0]["message"]["content"], "polled reply");
    assert_eq!(b.call("GET", &format!("/v1/chat/jobs/{id}"), Value::Null).0, 404, "returned once");
    let (_, v) = b.call("POST", "/v1/chat", json!({"async":true,"messages":[{"role":"user","content":"card 4111 1111 1111 1111"}]}));
    let done = poll_job(&b, v["job"].as_u64().unwrap());
    assert_eq!((done["status"].clone(), done["result"]["blocked"].clone()), (json!(403), json!(true)), "{done}");
    assert_eq!(b.call("GET", "/v1/chat/jobs/abc", Value::Null).0, 404);
    b.run.stop();
}

#[test]
fn gate_check_returns_categories_only() {
    let llama = FakeLlama::start("ok");
    let b = boot("gc", llama.addr, vec![]);
    let (c, v) = b.call("POST", "/v1/gate/check", json!({"text":"the build is green"}));
    assert_eq!((c, v["verdict"].clone()), (200, json!("pass")));
    let (c, v) = b.call("POST", "/v1/gate/check", json!({"text":concat!("write to jane.doe@gm", "ail.com")}));
    assert_eq!((c, v["verdict"].clone()), (200, json!("block")));
    assert!(!v.to_string().contains("jane"));
    assert_eq!(b.call("POST", "/v1/gate/check", json!({})).0, 400);
    b.run.stop();
}

#[test]
fn unlock_checks_the_phrase_never_echoes_it_and_throttles() {
    let llama = FakeLlama::start("ok");
    let b = boot("unlock", llama.addr, vec![]);
    let (c, v) = b.unlock(UNWRAP);
    assert_eq!((c, v["unlocked"].clone()), (200, json!(true)));
    for _ in 0..4 {
        let (c, v) = b.unlock(NOT_IT);
        assert_eq!(c, 401);
        assert!(!v.to_string().contains(NOT_IT));
    }
    assert_eq!(b.unlock(UNWRAP).0, 200, "a right phrase resets the count");
    for _ in 0..3 {
        assert_eq!(b.unlock(NOT_IT).0, 401);
    }
    // Boundary: 3 counted, 4 parallel wrong guesses. Exactly 2 may be checked; the rest are 429.
    let codes: Vec<u16> = std::thread::scope(|sc| {
        let hs: Vec<_> = (0..4).map(|_| sc.spawn(|| b.unlock(NOT_IT).0)).collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    assert_eq!((codes.iter().filter(|c| **c == 401).count(), codes.iter().filter(|c| **c == 429).count()), (2, 2), "{codes:?}");
    let (c, v) = b.unlock(UNWRAP);
    assert_eq!(c, 429, "{v}");
    assert!(v["retry_after"].as_u64().unwrap() >= 1);
    assert_eq!(b.call("POST", "/v1/vault/unlock", json!({})).0, 400);
    b.run.stop();
}

#[test]
fn vault_list_and_sealed_export() {
    let llama = FakeLlama::start("reply text xyzzy");
    let b = boot("vault", llama.addr, vec![]);
    for conv in ["alpha", "beta", "alpha"] {
        assert_eq!(b.call("POST", "/v1/chat", json!({"conv":conv,"messages":[{"role":"user","content":"plain words"}]})).0, 200);
    }
    let (c, v) = b.call("GET", "/v1/vault/conversations", Value::Null);
    assert_eq!(c, 200);
    assert_eq!(v["conversations"], json!([{"name":"alpha","messages":4,"last_msg_id":6},{"name":"beta","messages":2,"last_msg_id":4}]), "{v}");
    let (c, v) = b.call("GET", "/v1/vault/export", Value::Null);
    assert_eq!(c, 200);
    assert_eq!((v["format"].clone(), v["total"].clone(), v["next"].clone()), (json!("arrowmesh-sealed-v1"), json!(6), Value::Null));
    let recs = v["records"].as_array().unwrap();
    assert_eq!(recs.len(), 6);
    for r in recs {
        assert_eq!(r["object"].as_str().unwrap().len(), arrowmem_core::OBJECT_SIZE * 2);
    }
    assert!(!v.to_string().contains("plain words") && !v.to_string().contains(&arrowmesh::hex::enc(b"xyzzy")));
    let (_, p1) = b.call("GET", "/v1/vault/export?limit=4", Value::Null);
    assert_eq!((p1["records"].as_array().unwrap().len(), p1["next"].clone()), (4, json!(5)));
    let (_, p2) = b.call("GET", "/v1/vault/export?from=5&limit=4", Value::Null);
    assert_eq!((p2["records"].as_array().unwrap().len(), p2["next"].clone()), (2, Value::Null));
    assert_eq!(b.call("GET", "/v1/vault/export?limit=0", Value::Null).0, 400);
    assert_eq!(b.call("GET", "/v1/vault/export?from=x", Value::Null).0, 400);
    b.run.stop();
}

#[test]
fn peers_add_list_and_become_active_through_config_load() {
    let llama = FakeLlama::start("ok");
    let b = boot("peers", llama.addr, vec![]);
    let other = Identity::generate().unwrap();
    let body = json!({"name":"carol","addr":"192.168.1.20:8090","sign_pub":arrowmesh::hex::enc(&other.sign_pub()),"seal_pub":arrowmesh::hex::enc(&other.seal_pub())});
    let (c, v) = b.call("POST", "/v1/peers", body.clone());
    assert_eq!((c, v["restart_required"].clone(), v["active"].clone()), (202, json!(true), json!(false)), "{v}");
    assert_eq!(b.call("POST", "/v1/peers", body.clone()).0, 409);
    let (_, v) = b.call("GET", "/v1/peers", Value::Null);
    assert_eq!((v["peers"][0]["name"].clone(), v["peers"][0]["active"].clone()), (json!("carol"), json!(false)));
    let mut bad = body.clone();
    bad["addr"] = json!("8.8.8.8:8090");
    assert_eq!(b.call("POST", "/v1/peers", bad).0, 400);
    let mut bad = body.clone();
    bad["name"] = json!("x y");
    assert_eq!(b.call("POST", "/v1/peers", bad).0, 400);
    let mut bad = body.clone();
    bad["name"] = json!("dave");
    bad["seal_pub"] = json!("04ab");
    assert_eq!(b.call("POST", "/v1/peers", bad).0, 400);
    assert_eq!(b.call("POST", "/v1/peers", json!({"name":"e"})).0, 400);
    let cfg_file = b.cfg.key_file.with_file_name("config");
    std::fs::write(&cfg_file, format!("key_file = {}\n", b.cfg.key_file.display())).unwrap();
    let loaded = Config::load(&cfg_file, &testutil::tmp("home")).unwrap();
    assert_eq!(loaded.peers.len(), 1);
    assert_eq!(loaded.peers[0].name, "carol");
    b.run.stop();
}

#[test]
fn send_status_delivered_failed_and_blocked() {
    let llama = FakeLlama::start("ok");
    let alice_id = Identity::generate().unwrap();
    let bob = boot("bob", llama.addr, vec![peer_of("alice", "127.0.0.1:1".parse().unwrap(), &alice_id)]);
    let dead: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let alice = boot_as("alice", llama.addr, alice_id, vec![peer_of("bob", bob.run.mesh_addr, &bob.id), peer_of("ghost", dead, &bob.id)]);
    let (c, v) = alice.call("POST", "/v1/send", json!({"peer":"bob","text":"hello bob"}));
    assert_eq!((c, v["state"].clone()), (200, json!("delivered")), "{v}");
    let sid = v["send_id"].as_u64().unwrap();
    let (c, r) = alice.call("GET", &format!("/v1/sends/{sid}"), Value::Null);
    assert_eq!((c, r["state"].clone(), r["peer"].clone()), (200, json!("delivered"), json!("bob")), "{r}");
    assert!(!r.to_string().contains("hello bob"));
    let (c, v) = alice.call("POST", "/v1/send", json!({"peer":"ghost","text":"anyone there"}));
    assert_eq!(c, 502, "{v}");
    let (_, r) = alice.call("GET", &format!("/v1/sends/{}", v["send_id"].as_u64().unwrap()), Value::Null);
    assert_eq!(r["state"], "failed");
    assert!(r["reason"].is_string());
    let (c, v) = alice.call("POST", "/v1/send", json!({"peer":"bob","text":concat!("mail jane.doe@gm", "ail.com")}));
    assert_eq!((c, v["stage"].clone()), (403, json!("text")));
    let (_, list) = alice.call("GET", "/v1/sends", Value::Null);
    let states: Vec<&str> = list["sends"].as_array().unwrap().iter().map(|s| s["state"].as_str().unwrap()).collect();
    assert_eq!(states, ["blocked", "failed", "delivered"]);
    assert!(!list.to_string().contains("jane.doe"));
    let (_, pl) = alice.call("GET", "/v1/peers?probe=1", Value::Null);
    let reach: Vec<(String, bool)> = pl["peers"].as_array().unwrap().iter().map(|p| (p["name"].as_str().unwrap().to_string(), p["reachable"].as_bool().unwrap())).collect();
    assert!(reach.contains(&("bob".to_string(), true)) && reach.contains(&("ghost".to_string(), false)), "{reach:?}");
    assert_eq!(alice.call("GET", "/v1/sends/99999", Value::Null).0, 404);
    assert_eq!(alice.call("POST", "/v1/send", json!({"peer":"nobody","text":"x"})).0, 404);
    let _ = &alice.cfg;
    alice.run.stop();
    bob.run.stop();
}

#[test]
fn status_and_install_state() {
    let llama = FakeLlama::start("ok");
    let b = boot("st", llama.addr, vec![]);
    let (c, v) = b.call("GET", "/v1/status", Value::Null);
    assert_eq!((c, v["api"].clone(), v["vault_unlocked"].clone(), v["model_up"].clone()), (200, json!("v1"), json!(true), json!(true)), "{v}");
    let (c, v) = b.call("GET", "/v1/install", Value::Null);
    assert_eq!((c, v["key_present"].clone(), v["token_present"].clone(), v["peers_configured"].clone()), (200, json!(true), json!(true), json!(0)));
    assert!(!v.to_string().contains('/'), "no paths: {v}");
    let _ = &b.id;
    b.run.stop();
}

#[test]
fn e1_export_carries_the_head_restores_and_a_cut_tail_is_detected() {
    let llama = FakeLlama::start("reply");
    let b = boot("e1", llama.addr, vec![]);
    for conv in ["alpha", "beta", "alpha"] {
        assert_eq!(b.call("POST", "/v1/chat", json!({"conv":conv,"messages":[{"role":"user","content":"plain"}]})).0, 200);
    }
    let (_, p1) = b.call("GET", "/v1/vault/export?limit=4", Value::Null);
    assert!(p1.get("head").is_none(), "head only on the last page: {p1}");
    let (_, p2) = b.call("GET", "/v1/vault/export?from=5&limit=4", Value::Null);
    let head = arrowmesh::hex::dec(p2["head"].as_str().expect("head on last page")).unwrap();
    let recs: Vec<(u64, Vec<u8>)> = [&p1, &p2]
        .iter()
        .flat_map(|p| p["records"].as_array().unwrap().iter().map(|r| (r["n"].as_u64().unwrap(), arrowmesh::hex::dec(r["object"].as_str().unwrap()).unwrap())))
        .collect();
    assert_eq!(recs.len(), 6);
    let restore = |tag: &str, upto: usize, with_head: bool| {
        let dir = testutil::tmp(tag);
        let v = arrowmesh::vault::Vault::open(dir.clone()).unwrap();
        for (n, o) in recs.iter().take(upto) {
            std::fs::write(dir.join(format!("r/{n:016x}.obj")), o).unwrap();
        }
        if with_head {
            std::fs::write(dir.join("head"), &head).unwrap();
        }
        v.read_all(&b.id)
    };
    assert!(restore("e1a", 6, false).err().unwrap().contains("head record missing"), "records alone are refused");
    assert_eq!(restore("e1b", 6, true).unwrap().len(), 6, "full export plus head restores and reads");
    assert!(restore("e1c", 4, true).is_err(), "tail-truncated records against the head are refused");
    assert!(restore("e1d", 4, false).is_err(), "an export whose last page was never fetched has no head and is refused");
    b.run.stop();
}

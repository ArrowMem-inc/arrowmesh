//! v1.1: the daemon boots LOCKED and the app supplies the passphrase over the loopback API.
//! Boot locked, refused before unlock, works after, locks again, and the passphrase never reaches
//! the daemon's output, its argv, its environment or the systemd unit.

use arrowmesh::config::Config;
use arrowmesh::daemon;
use arrowmesh::gatepath::Gate;
use arrowmesh::keys::{Identity, Kdf};
use arrowmesh::vault::{Kind, Vault};
use arrowmesh::{api, net, testutil};
use serde_json::{Value, json};
use std::io::{BufRead, Read, Write};
use std::net::SocketAddr;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

const WORDS: &str = "locked start test words";
const WRONG: &str = "definitely-not-the-words-q9";

struct FakeLlama {
    addr: SocketAddr,
    server: Arc<tiny_http::Server>,
}

impl FakeLlama {
    fn start() -> FakeLlama {
        let server = Arc::new(tiny_http::Server::http("127.0.0.1:0").unwrap());
        let addr = server.server_addr().to_ip().unwrap();
        let s = server.clone();
        std::thread::spawn(move || {
            for mut req in s.incoming_requests() {
                let mut b = String::new();
                let _ = req.as_reader().read_to_string(&mut b);
                let out = if req.url() == "/health" { "{\"status\":\"ok\"}".to_string() } else { json!({"choices":[{"message":{"role":"assistant","content":"fine"}}]}).to_string() };
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

fn is_locked(r: &(u16, Value)) -> bool {
    r.0 == 423 && r.1 == json!({"error": "vault locked"})
}

#[test]
fn boots_locked_refuses_until_unlock_works_after_and_locks_again() {
    let llama = FakeLlama::start();
    let home = testutil::tmp("lockedstart");
    let mut c = Config::defaults(&home);
    c.chat_addr = "127.0.0.1:0".parse().unwrap();
    c.mesh_listen = "127.0.0.1:0".parse().unwrap();
    c.llama_addr = llama.addr;
    let id = Identity::generate().unwrap();
    id.save_new_with(&c.key_file, WORDS, Kdf::TEST).unwrap();
    // A record written before boot: only the right key can read it back after unlock.
    Vault::open(c.vault_dir.clone()).unwrap().append(&id, Kind::User, "old", "written before boot").unwrap();
    let token = arrowmesh::token::create_new(&c.token_file).unwrap();
    let run = daemon::start_locked_with_floor(c.clone(), Gate::new(None), Kdf::TEST).unwrap();
    let a = run.chat_addr;
    let chat = || call(a, &token, "POST", "/v1/chat", json!({"conv": "t", "messages": [{"role": "user", "content": "hello there"}]}));

    // Boot state: status says locked, the record count is visible, every vault route refuses with the one shape.
    let (code, st) = call(a, &token, "GET", "/v1/status", Value::Null);
    assert_eq!((code, st["vault_unlocked"].clone(), st["vault_records"].clone()), (200, json!(false), json!(1)), "{st}");
    let guarded: [(&str, &str, Value); 7] = [
        ("POST", "/v1/chat", json!({"conv": "t", "messages": [{"role": "user", "content": "x"}]})),
        ("POST", "/v1/chat", json!({"async": true, "messages": [{"role": "user", "content": "x"}]})),
        ("GET", "/v1/chat/jobs/1", Value::Null),
        ("POST", "/v1/send", json!({"peer": "p", "text": "x"})),
        ("GET", "/v1/history?conv=old", Value::Null),
        ("GET", "/v1/vault/conversations", Value::Null),
        ("GET", "/v1/vault/export", Value::Null),
    ];
    for (m, p, b) in &guarded {
        let r = call(a, &token, m, p, b.clone());
        assert!(is_locked(&r), "{m} {p} while locked -> {r:?}");
    }
    // Routes that need no key still work while locked.
    assert_eq!(call(a, &token, "GET", "/v1/install", Value::Null).0, 200);
    assert_eq!(call(a, &token, "GET", "/v1/peers", Value::Null).0, 200);
    // The mesh listener answers nothing while locked.
    let mut s = net::connect(&run.mesh_addr, Duration::from_secs(3)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let _ = s.write_all(&vec![7u8; arrowmem_core::OBJECT_SIZE]);
    let mut ack = [9u8; 1];
    assert!(s.read_exact(&mut ack).is_err(), "locked listener answered {ack:?}");

    // A wrong phrase: 401, still locked, no echo.
    let (code, v) = call(a, &token, "POST", "/v1/vault/unlock", json!({"passphrase": WRONG}));
    assert_eq!(code, 401);
    assert!(!v.to_string().contains(WRONG));
    assert!(is_locked(&chat()), "a wrong phrase must not unlock");
    // Unlock, through the same attempt counter: the wrong try above counted.
    assert_eq!(call(a, &token, "POST", "/v1/vault/unlock", json!({"passphrase": WORDS})), (200, json!({"unlocked": true})));
    let (code, st) = call(a, &token, "GET", "/v1/status", Value::Null);
    assert_eq!((code, st["vault_unlocked"].clone()), (200, json!(true)));
    assert_eq!(chat().0, 200);
    let (code, h) = call(a, &token, "GET", "/v1/history?conv=old", Value::Null);
    assert_eq!((code, h["entries"][0]["text"].clone()), (200, json!("written before boot")), "{h}");
    assert_eq!(call(a, &token, "GET", "/v1/vault/export", Value::Null).0, 200);

    // Lock again: refused again, status false, the listener closes, and unlock works a second time.
    assert_eq!(call(a, &token, "POST", "/v1/vault/lock", json!({})), (200, json!({"locked": true})));
    assert_eq!(call(a, &token, "POST", "/v1/vault/lock", Value::Null), (200, json!({"locked": true})), "idempotent");
    for (m, p, b) in &guarded {
        let r = call(a, &token, m, p, b.clone());
        assert!(is_locked(&r), "{m} {p} after lock -> {r:?}");
    }
    let (_, st) = call(a, &token, "GET", "/v1/status", Value::Null);
    assert_eq!(st["vault_unlocked"], false);
    let mut s = net::connect(&run.mesh_addr, Duration::from_secs(3)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let _ = s.write_all(&vec![7u8; arrowmem_core::OBJECT_SIZE]);
    assert!(s.read_exact(&mut ack).is_err(), "listener answered after lock");
    assert_eq!(call(a, &token, "POST", "/v1/vault/unlock", json!({"passphrase": WORDS})).0, 200);
    assert_eq!(chat().0, 200);
    run.stop();
}

#[test]
fn the_lock_route_is_in_the_table_and_the_document() {
    assert!(api::ROUTES.contains(&("POST", "/v1/vault/lock")));
    let yaml = include_str!("../openapi/arrowmesh-v1.yaml");
    assert!(yaml.contains("  /v1/vault/lock:\n    post:\n      operationId: postVaultLock"));
    assert!(yaml.contains("  version: 1.3.0"));
}

/// The real binary: install, run with NO passphrase source anywhere, unlock over HTTP, lock, then
/// grep everything the process printed, its argv, its environment and the unit for the passphrase.
#[test]
fn the_real_daemon_starts_sealed_and_the_passphrase_never_appears_anywhere_it_could_leak() {
    let llama = FakeLlama::start();
    let home = testutil::tmp("lockedbin");
    let exe = env!("CARGO_BIN_EXE_arrowmesh");
    let words = "binary test words 7731 unique-marker";
    let out = Command::new(exe).arg("install").env("HOME", &home).env("ARROWMESH_PASSPHRASE", words).env_remove("CREDENTIALS_DIRECTORY").stdin(Stdio::null()).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let mut leaked = String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    let unit = std::fs::read_to_string(home.join(".config/systemd/user/arrowmesh.service")).unwrap();
    assert!(!unit.contains(words) && !unit.contains("Credential") && !unit.contains("PASSPHRASE") && !unit.contains("Environment"), "{unit}");
    assert!(unit.contains("ExecStart=") && unit.contains(" run --config "));
    let cfg_path = home.join(".config/arrowmesh/config");
    let text = std::fs::read_to_string(&cfg_path).unwrap();
    let defaults = Config::defaults(&home);
    let text = text
        .replace(&defaults.chat_addr.to_string(), "127.0.0.1:0")
        .replace(&defaults.mesh_listen.to_string(), "127.0.0.1:0")
        .replace(&defaults.llama_addr.to_string(), &llama.addr.to_string());
    std::fs::write(&cfg_path, text).unwrap();

    let mut child = Command::new(exe)
        .args(["run", "--config"])
        .arg(&cfg_path)
        .env("HOME", &home)
        .env_remove("ARROWMESH_PASSPHRASE")
        .env_remove("CREDENTIALS_DIRECTORY")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut err = std::io::BufReader::new(child.stderr.take().unwrap());
    let mut line = String::new();
    err.read_line(&mut line).unwrap();
    leaked += &line;
    assert!(line.contains("vault locked"), "first line was {line:?}");
    let addr: SocketAddr = line.split("chat ").nth(1).unwrap().split(',').next().unwrap().parse().unwrap();
    let token = std::fs::read_to_string(&defaults.token_file).unwrap().trim().to_string();

    assert_eq!(call(addr, &token, "GET", "/v1/status", Value::Null).1["vault_unlocked"], false);
    let chat = json!({"messages": [{"role": "user", "content": "hello there"}]});
    assert!(is_locked(&call(addr, &token, "POST", "/v1/chat", chat.clone())));
    assert_eq!(call(addr, &token, "POST", "/v1/vault/unlock", json!({"passphrase": WRONG})).0, 401);
    assert_eq!(call(addr, &token, "POST", "/v1/vault/unlock", json!({"passphrase": words})).0, 200);
    assert_eq!(call(addr, &token, "POST", "/v1/chat", chat.clone()).0, 200);
    // While running, the phrase is in neither argv nor environment.
    let pid = child.id();
    let cmd = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap();
    // environ is unreadable for the same user once the process is not dumpable (F4); if it is
    // readable anyway, it must not carry the phrase.
    let env = std::fs::read(format!("/proc/{pid}/environ")).unwrap_or_default();
    for (what, b) in [("cmdline", &cmd), ("environ", &env)] {
        assert!(!String::from_utf8_lossy(b).contains(words), "{what} carries the phrase");
    }
    assert_eq!(call(addr, &token, "POST", "/v1/vault/lock", json!({})).0, 200);
    assert!(is_locked(&call(addr, &token, "POST", "/v1/chat", chat)));
    child.kill().unwrap();
    let mut rest = String::new();
    let _ = err.read_to_string(&mut rest);
    let mut so = String::new();
    let _ = child.stdout.take().unwrap().read_to_string(&mut so);
    child.wait().unwrap();
    leaked += &rest;
    leaked += &so;
    assert!(!leaked.contains(words), "the passphrase reached captured output");
    assert!(!leaked.contains(WRONG), "a wrong guess reached captured output");
    // The check can fail: prove the grep sees a planted marker.
    assert!((leaked.clone() + words).contains(words));
}

//! R15: the model server is keyed and locked down, and arrowmesh sends the key on every call.
//! The live probe needs the real llama-server binary and a gguf, so it is ignored by default:
//! `ARROWMESH_R15_BIN=/usr/lib/arrowmem/llama-server-vulkan ARROWMESH_R15_MODEL=/path/m.gguf
//!  cargo test --test r15_keyed_model live -- --ignored --nocapture`

use arrowmesh::config::Config;
use arrowmesh::daemon;
use arrowmesh::gatepath::Gate;
use arrowmesh::keys::{Identity, Kdf};
use arrowmesh::{net, testutil};
use serde_json::json;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const PHRASE: &str = "r15 test phrase";

/// A model stand-in that records the head of every request it gets.
fn recorder() -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let s2 = seen.clone();
    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            let mut raw = Vec::new();
            let mut b = [0u8; 4096];
            while !raw.windows(4).any(|w| w == b"\r\n\r\n") {
                match c.read(&mut b) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => raw.extend_from_slice(&b[..n]),
                }
            }
            s2.lock().unwrap().push(String::from_utf8_lossy(&raw).to_string());
            let body = json!({"choices": [{"message": {"content": "ok then"}}]}).to_string();
            let _ = c.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes());
        }
    });
    (addr, seen)
}

fn boot(tag: &str, llama: SocketAddr, key: Option<&str>) -> (daemon::Running, String, Config) {
    let home = testutil::tmp(tag);
    let mut c = Config::defaults(&home);
    c.chat_addr = "127.0.0.1:0".parse().unwrap();
    c.mesh_listen = "127.0.0.1:0".parse().unwrap();
    c.llama_addr = llama;
    Identity::generate().unwrap().save_new_with(&c.key_file, PHRASE, Kdf::TEST).unwrap();
    let token = arrowmesh::token::create_new(&c.token_file).unwrap();
    if let Some(k) = key {
        std::fs::write(&c.llama_key_file, k).unwrap();
        std::fs::set_permissions(&c.llama_key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let run = daemon::start_with_floor(c.clone(), Gate::new(None), PHRASE, Kdf::TEST).unwrap();
    (run, token, c)
}

fn chat(run: &daemon::Running, token: &str, stream: bool) -> u16 {
    let auth = format!("Bearer {token}");
    let body = json!({"conv": "r", "stream": stream, "messages": [{"role": "user", "content": "say hello"}]}).to_string();
    let accept = if stream { "text/event-stream" } else { "application/json" };
    let (code, _) = net::http_with(&run.chat_addr, "POST", "/v1/chat", Some(&body), Duration::from_secs(20), &[("Authorization", &auth), ("Accept", accept)]).unwrap();
    code
}

fn auth_lines(heads: &[String]) -> Vec<Option<String>> {
    heads.iter().map(|h| h.lines().find(|l| l.to_ascii_lowercase().starts_with("authorization:")).map(|l| l.split_once(':').unwrap().1.trim().to_string())).collect()
}

#[test]
fn arrowmesh_sends_the_model_key_on_every_upstream_call_streaming_or_not() {
    let (addr, seen) = recorder();
    let key = "k".repeat(64);
    let (run, token, _) = boot("r15a", addr, Some(&key));
    assert_eq!(chat(&run, &token, false), 200);
    let _ = chat(&run, &token, true);
    let heads = seen.lock().unwrap().clone();
    assert!(heads.len() >= 2, "expected a plain and a streaming upstream call, saw {}", heads.len());
    let want = format!("Bearer {key}");
    for a in auth_lines(&heads) {
        assert_eq!(a.as_deref(), Some(want.as_str()), "an upstream call went out without the key");
    }
    run.stop();
}

#[test]
fn with_no_key_file_no_authorization_header_goes_upstream() {
    let (addr, seen) = recorder();
    let (run, token, _) = boot("r15b", addr, None);
    assert_eq!(chat(&run, &token, false), 200);
    let heads = seen.lock().unwrap().clone();
    assert!(!heads.is_empty());
    assert!(auth_lines(&heads).iter().all(Option::is_none));
    run.stop();
}

#[test]
fn a_launched_model_gets_a_new_mode_600_key_once_and_the_same_key_after() {
    let home = testutil::tmp("r15c");
    let mut c = Config::defaults(&home);
    c.model_path = Some("/nonexistent.gguf".into());
    c.llama_bin = "/nonexistent/llama-server".into();
    let k1 = daemon::llama_key(&c).unwrap().unwrap();
    assert_eq!(k1.len(), 64);
    assert_eq!(std::fs::metadata(&c.llama_key_file).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(daemon::llama_key(&c).unwrap().unwrap(), k1);
    // A loose file is refused, not used.
    std::fs::set_permissions(&c.llama_key_file, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(daemon::llama_key(&c).is_err());
    // Attaching with no key file means no key; the file is never created for an attach.
    let mut d = Config::defaults(&testutil::tmp("r15d"));
    d.model_path = None;
    assert_eq!(daemon::llama_key(&d).unwrap(), None);
    assert!(!d.llama_key_file.exists());
}

fn raw(addr: &SocketAddr, req: &str) -> String {
    let mut s = net::connect(addr, Duration::from_secs(5)).unwrap();
    s.write_all(req.as_bytes()).unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    String::from_utf8_lossy(&out).to_string()
}

/// True when the response lets a foreign page in: a non-empty Allow-Origin (an empty value matches
/// no origin in any browser) or Allow-Credentials: true.
fn reflect(head: &str) -> bool {
    head.lines().any(|l| {
        let l = l.to_ascii_lowercase();
        let v = l.split_once(':').map(|(_, v)| v.trim().to_string()).unwrap_or_default();
        (l.starts_with("access-control-allow-origin:") && !v.is_empty()) || (l.starts_with("access-control-allow-credentials:") && v == "true")
    })
}

fn status(head: &str) -> u16 {
    head.split(' ').nth(1).and_then(|c| c.parse().ok()).unwrap_or(0)
}

/// The measurement made against the shipped binary with the production arguments.
#[test]
#[ignore = "needs the real llama-server and a gguf: set ARROWMESH_R15_BIN and ARROWMESH_R15_MODEL"]
fn live_the_supervised_model_server_refuses_everything_without_the_key() {
    let (Ok(bin), Ok(model)) = (std::env::var("ARROWMESH_R15_BIN"), std::env::var("ARROWMESH_R15_MODEL")) else {
        panic!("set ARROWMESH_R15_BIN and ARROWMESH_R15_MODEL");
    };
    let port: u16 = std::env::var("ARROWMESH_R15_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(18392);
    let home = testutil::tmp("r15live");
    let mut c = Config::defaults(&home);
    c.chat_addr = "127.0.0.1:0".parse().unwrap();
    c.mesh_listen = "127.0.0.1:0".parse().unwrap();
    c.llama_addr = format!("127.0.0.1:{port}").parse().unwrap();
    c.model_path = Some(model);
    c.llama_bin = bin;
    Identity::generate().unwrap().save_new_with(&c.key_file, PHRASE, Kdf::TEST).unwrap();
    let token = arrowmesh::token::create_new(&c.token_file).unwrap();
    let run = daemon::start_with_floor(c.clone(), Gate::new(None), PHRASE, Kdf::TEST).unwrap();
    let key = std::fs::read_to_string(&c.llama_key_file).unwrap().trim().to_string();
    let a = c.llama_addr;
    let t0 = Instant::now();
    while !matches!(net::http(&a, "GET", "/health", None, Duration::from_secs(2)), Ok((200, _))) {
        assert!(t0.elapsed() < Duration::from_secs(180), "model server never became healthy");
        std::thread::sleep(Duration::from_millis(500));
    }
    let get = |p: &str, extra: &str| raw(&a, &format!("GET {p} HTTP/1.1\r\nHost: {a}\r\nConnection: close\r\n{extra}\r\n"));
    let mut report = Vec::new();
    // Anonymous reads.
    for p in ["/props", "/slots", "/v1/models", "/models", "/metrics", "/"] {
        let s = status(&get(p, ""));
        report.push(format!("anon GET {p} -> {s}"));
        assert!(s == 401 || s == 404, "anonymous GET {p} answered {s}");
    }
    // Anonymous completion.
    let body = json!({"messages": [{"role": "user", "content": "hi"}], "max_tokens": 2}).to_string();
    let post = |extra: &str| raw(&a, &format!("POST /v1/chat/completions HTTP/1.1\r\nHost: {a}\r\nConnection: close\r\nContent-Type: application/json\r\n{extra}Content-Length: {}\r\n\r\n{body}", body.len()));
    let h = post("Origin: https://evil.example\r\n");
    report.push(format!("anon cross origin POST completion -> {}", status(&h)));
    assert!(matches!(status(&h), 401 | 403), "unkeyed completion answered {}", status(&h));
    assert!(!reflect(&h), "origin reflected on the refusal");
    // Cross origin on a read and on a preflight, anonymous and keyed: nothing reflected, no credentials.
    let h = get("/v1/models", "Origin: https://evil.example\r\n");
    report.push(format!("anon cross origin GET /v1/models -> {}, reflected {}", status(&h), reflect(&h)));
    assert!(!reflect(&h));
    let h = raw(&a, &format!("OPTIONS /v1/chat/completions HTTP/1.1\r\nHost: {a}\r\nConnection: close\r\nOrigin: https://evil.example\r\nAccess-Control-Request-Method: POST\r\n\r\n"));
    report.push(format!("cross origin preflight -> {}, reflected {}", status(&h), reflect(&h)));
    assert!(!reflect(&h));
    let auth = format!("Authorization: Bearer {key}\r\n");
    let h = get("/v1/models", &format!("{auth}Origin: https://evil.example\r\n"));
    report.push(format!("keyed cross origin GET /v1/models -> {}, reflected {}", status(&h), reflect(&h)));
    assert_eq!(status(&h), 200);
    assert!(!reflect(&h));
    // Disabled endpoints, even with the key.
    let s = status(&get("/slots", &auth));
    report.push(format!("keyed GET /slots -> {s}"));
    assert_ne!(s, 200);
    // Measured, not asserted: the binary has no Host check, so a hostile Host with the key.
    let h = raw(&a, &format!("GET /v1/models HTTP/1.1\r\nHost: evil.example\r\nConnection: close\r\n{auth}\r\n"));
    report.push(format!("keyed hostile Host (real) GET /v1/models -> {}", status(&h)));
    let h = raw(&a, "GET /v1/models HTTP/1.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n");
    report.push(format!("anon hostile Host GET /v1/models -> {}", status(&h)));
    assert!(matches!(status(&h), 401 | 404));
    // Keyed POST works, and arrowmesh's own chat works with the key.
    let h = post(&auth);
    report.push(format!("keyed POST completion -> {}", status(&h)));
    assert_eq!(status(&h), 200);
    let code = chat(&run, &token, false);
    report.push(format!("arrowmesh /v1/chat (plain) -> {code}"));
    assert_eq!(code, 200);
    let code = chat(&run, &token, true);
    report.push(format!("arrowmesh /v1/chat (stream) -> {code}"));
    assert_eq!(code, 200);
    run.stop();
    println!("{}", report.join("\n"));
}

fn status_keyed(run: &daemon::Running, token: &str) -> serde_json::Value {
    let auth = format!("Bearer {token}");
    let (code, body) = net::http_with(&run.chat_addr, "GET", "/v1/status", None, Duration::from_secs(5), &[("Authorization", &auth)]).unwrap();
    assert_eq!(code, 200);
    serde_json::from_slice(&body).unwrap()
}

fn boot_req(tag: &str, required: bool, with_file: bool) -> Result<(daemon::Running, String), String> {
    let home = testutil::tmp(tag);
    let mut c = Config::defaults(&home);
    c.chat_addr = "127.0.0.1:0".parse().unwrap();
    c.mesh_listen = "127.0.0.1:0".parse().unwrap();
    c.llama_key_required = required;
    Identity::generate().unwrap().save_new_with(&c.key_file, PHRASE, Kdf::TEST).unwrap();
    let token = arrowmesh::token::create_new(&c.token_file).unwrap();
    if with_file {
        std::fs::write(&c.llama_key_file, "k".repeat(64)).unwrap();
        std::fs::set_permissions(&c.llama_key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    daemon::start_with_floor(c, Gate::new(None), PHRASE, Kdf::TEST).map(|r| (r, token))
}

#[test]
fn required_true_and_no_key_file_refuses_to_start_with_one_plain_line() {
    let e = boot_req("r15e", true, false).err().expect("must refuse");
    assert_eq!(e, "llama_key_required is true and the model key file is missing, refusing to start");
    assert!(!e.contains('\n'));
}

#[test]
fn required_true_with_key_file_starts_and_status_says_keyed() {
    let (run, token) = boot_req("r15f", true, true).unwrap();
    assert_eq!(status_keyed(&run, &token)["model_keyed"], json!(true));
    run.stop();
}

#[test]
fn required_false_and_no_key_file_starts_and_status_says_not_keyed() {
    let (run, token) = boot_req("r15g", false, false).unwrap();
    assert_eq!(status_keyed(&run, &token)["model_keyed"], json!(false));
    run.stop();
}

#[test]
fn llama_key_required_parses_and_defaults_false() {
    let h = testutil::tmp("r15h");
    assert!(!Config::parse("", &h).unwrap().llama_key_required);
    assert!(Config::parse("llama_key_required = true", &h).unwrap().llama_key_required);
}

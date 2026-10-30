//! Gated per chunk streaming over the real wire: the daemon, a fake model that streams, and a
//! reference client. Engine level invariants (T1 to T11, T13) are in `src/stream/tests.rs`.

use arrowmesh::config::{Config, Peer};
use arrowmesh::daemon::{self, Running};
use arrowmesh::gatepath::Gate;
use arrowmesh::keys::{Identity, Kdf};
use arrowmesh::{api, net, testutil};
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const PHRASE: &str = "streaming test phrase";
const YAML: &str = include_str!("../openapi/arrowmesh-v1.yaml");

// ---- a fake model that streams ----

struct Fake {
    addr: SocketAddr,
    streams: Arc<AtomicUsize>,
    dropped: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
}

#[derive(Clone)]
struct Plan {
    /// The whole reply, for a non streaming request.
    full: String,
    /// What a streaming request is sent, piece by piece.
    pieces: Vec<String>,
    delay: Duration,
    /// After the first piece, send nothing real, only comments, until the client goes.
    hang: bool,
}

impl Plan {
    fn text(reply: &str, piece: usize, delay_ms: u64) -> Plan {
        let cs: Vec<char> = reply.chars().collect();
        let pieces = cs.chunks(piece).map(|c| c.iter().collect()).collect();
        Plan { full: reply.to_string(), pieces, delay: Duration::from_millis(delay_ms), hang: false }
    }
}

fn read_request(s: &mut TcpStream) -> Option<(String, String)> {
    let mut raw = Vec::new();
    let mut b = [0u8; 4096];
    let head_end = loop {
        if let Some(i) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        let n = s.read(&mut b).ok()?;
        if n == 0 {
            return None;
        }
        raw.extend_from_slice(&b[..n]);
    };
    let head = String::from_utf8_lossy(&raw[..head_end]).to_string();
    let len: usize = head.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap_or(0))).unwrap_or(0);
    while raw.len() < head_end + 4 + len {
        let n = s.read(&mut b).ok()?;
        if n == 0 {
            return None;
        }
        raw.extend_from_slice(&b[..n]);
    }
    let path = head.lines().next()?.split(' ').nth(1)?.to_string();
    Some((path, String::from_utf8_lossy(&raw[head_end + 4..head_end + 4 + len]).to_string()))
}

fn chunk(s: &mut TcpStream, d: &[u8]) -> bool {
    s.write_all(format!("{:x}\r\n", d.len()).as_bytes()).and_then(|_| s.write_all(d)).and_then(|_| s.write_all(b"\r\n")).and_then(|_| s.flush()).is_ok()
}

impl Fake {
    fn start(plan: Plan) -> Fake {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.set_nonblocking(true).unwrap();
        let addr = l.local_addr().unwrap();
        let (streams, dropped, stop) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicBool::new(false)), Arc::new(AtomicBool::new(false)));
        let (st, dr, sp) = (streams.clone(), dropped.clone(), stop.clone());
        std::thread::spawn(move || {
            while !sp.load(Ordering::SeqCst) {
                match l.accept() {
                    Ok((mut s, _)) => {
                        s.set_nonblocking(false).unwrap();
                        let (plan, st, dr, sp) = (plan.clone(), st.clone(), dr.clone(), sp.clone());
                        std::thread::spawn(move || serve(&mut s, &plan, &st, &dr, &sp));
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(10)),
                }
            }
        });
        Fake { addr, streams, dropped, stop }
    }
}

impl Drop for Fake {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

fn serve(s: &mut TcpStream, plan: &Plan, streams: &AtomicUsize, dropped: &AtomicBool, stop: &AtomicBool) {
    let Some((path, body)) = read_request(s) else { return };
    let plain = |s: &mut TcpStream, out: String| {
        let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{out}", out.len()).as_bytes());
    };
    if path == "/health" {
        return plain(s, "{\"status\":\"ok\"}".into());
    }
    let wants_stream = serde_json::from_str::<Value>(&body).map(|v| v["stream"] == true).unwrap_or(false);
    if !wants_stream {
        return plain(s, json!({"choices": [{"message": {"role": "assistant", "content": plan.full}}]}).to_string());
    }
    streams.fetch_add(1, Ordering::SeqCst);
    if s.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n").is_err() {
        return;
    }
    for (i, p) in plan.pieces.iter().enumerate() {
        let ev = format!("data: {}\n\n", json!({"choices": [{"delta": {"content": p}}]}));
        if !chunk(s, ev.as_bytes()) {
            dropped.store(true, Ordering::SeqCst);
            return;
        }
        if plan.hang && i == 0 {
            while !stop.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(100));
                if !chunk(s, b": still thinking\n\n") {
                    dropped.store(true, Ordering::SeqCst);
                    return;
                }
            }
            return;
        }
        std::thread::sleep(plan.delay);
    }
    let _ = chunk(s, b"data: [DONE]\n\n");
    let _ = s.write_all(b"0\r\n\r\n");
}

// ---- the daemon under test ----

struct Boxx {
    run: Running,
    token: String,
}

fn boot_with(tag: &str, llama: SocketAddr, gate: Gate, peers: Vec<Peer>, locked: bool) -> Boxx {
    let home = testutil::tmp(tag);
    let mut c = Config::defaults(&home);
    c.chat_addr = "127.0.0.1:0".parse().unwrap();
    c.mesh_listen = "127.0.0.1:0".parse().unwrap();
    c.llama_addr = llama;
    c.peers = peers;
    // Attach mode against a keyed model: copy the key into this box's own key file.
    if let Ok(k) = std::env::var("ARROWMESH_T16_KEY_FILE") {
        let key = std::fs::read_to_string(&k).expect("ARROWMESH_T16_KEY_FILE unreadable");
        std::fs::create_dir_all(c.llama_key_file.parent().unwrap()).unwrap();
        std::fs::write(&c.llama_key_file, key.trim()).unwrap();
        std::fs::set_permissions(&c.llama_key_file, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    }
    Identity::generate().unwrap().save_new_with(&c.key_file, PHRASE, Kdf::TEST).unwrap();
    let token = arrowmesh::token::create_new(&c.token_file).unwrap();
    let run = if locked { daemon::start_locked_with_floor(c.clone(), gate, Kdf::TEST).unwrap() } else { daemon::start_with_floor(c.clone(), gate, PHRASE, Kdf::TEST).unwrap() };
    Boxx { run, token }
}

fn boot(tag: &str, llama: SocketAddr) -> Boxx {
    boot_with(tag, llama, Gate::new(None), vec![], false)
}

impl Boxx {
    fn call(&self, m: &str, path: &str, body: Value) -> (u16, Value) {
        let auth = format!("Bearer {}", self.token);
        let b = if body.is_null() { None } else { Some(body.to_string()) };
        let (c, out) = net::http_with(&self.run.chat_addr, m, path, b.as_deref(), Duration::from_secs(20), &[("Authorization", &auth)]).unwrap();
        (c, serde_json::from_slice(&out).unwrap_or(Value::Null))
    }
    fn records(&self) -> u64 {
        self.call("GET", "/v1/status", Value::Null).1["vault_records"].as_u64().unwrap()
    }
}

// ---- the reference client ----

struct Sse {
    status: u16,
    content_type: String,
    events: Vec<(String, Value)>,
    /// When each event arrived, relative to the request.
    at: Vec<Duration>,
    /// The chunked body ended with its terminating chunk.
    clean_end: bool,
    /// The plain body, when the answer was not a stream.
    plain: Value,
}

fn parse_events(block: &str) -> Option<(String, Value)> {
    let (mut name, mut data) = (String::new(), String::new());
    for l in block.lines() {
        if let Some(v) = l.strip_prefix("event: ") {
            name = v.to_string();
        } else if let Some(v) = l.strip_prefix("data: ") {
            data.push_str(v);
        }
    }
    if name.is_empty() { None } else { Some((name, serde_json::from_str(&data).unwrap_or(Value::Null))) }
}

/// POST /v1/chat and read the whole answer, whichever shape it takes.
fn chat(b: &Boxx, body: Value) -> Sse {
    chat_accept(b, body, Some("text/event-stream"))
}

fn chat_accept(b: &Boxx, body: Value, accept: Option<&str>) -> Sse {
    let accept = accept.map(|a| format!("Accept: {a}\r\n")).unwrap_or_default();
    let t0 = Instant::now();
    let mut s = net::connect(&b.run.chat_addr, Duration::from_secs(5)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
    let body = body.to_string();
    let req = format!("POST /v1/chat HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\n{accept}Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", b.run.chat_addr, b.token, body.len());
    s.write_all(req.as_bytes()).unwrap();
    read_answer(s, t0)
}

fn read_answer(s: TcpStream, t0: Instant) -> Sse {
    let mut r = BufReader::new(s);
    let mut status_line = String::new();
    r.read_line(&mut status_line).unwrap();
    let status: u16 = status_line.split(' ').nth(1).unwrap().parse().unwrap();
    let (mut content_type, mut len, mut chunked) = (String::new(), 0usize, false);
    loop {
        let mut l = String::new();
        r.read_line(&mut l).unwrap();
        if l == "\r\n" {
            break;
        }
        let low = l.to_ascii_lowercase();
        if let Some(v) = low.strip_prefix("content-type:") {
            content_type = v.trim().to_string();
        }
        if let Some(v) = low.strip_prefix("content-length:") {
            len = v.trim().parse().unwrap();
        }
        if low.starts_with("transfer-encoding:") && low.contains("chunked") {
            chunked = true;
        }
    }
    let mut out = Sse { status, content_type, events: vec![], at: vec![], clean_end: false, plain: Value::Null };
    if !chunked {
        let mut buf = vec![0u8; len];
        r.read_exact(&mut buf).unwrap();
        out.plain = serde_json::from_slice(&buf).unwrap_or(Value::Null);
        return out;
    }
    let mut pending = String::new();
    loop {
        let mut size_line = String::new();
        if r.read_line(&mut size_line).unwrap_or(0) == 0 {
            return out; // the connection ended with no terminating chunk
        }
        let Ok(n) = usize::from_str_radix(size_line.trim(), 16) else { return out };
        if n == 0 {
            out.clean_end = true;
            return out;
        }
        let mut buf = vec![0u8; n + 2];
        if r.read_exact(&mut buf).is_err() {
            return out;
        }
        pending.push_str(&String::from_utf8_lossy(&buf[..n]));
        while let Some(i) = pending.find("\n\n") {
            let block: String = pending.drain(..i + 2).collect();
            if let Some(ev) = parse_events(&block) {
                out.events.push(ev);
                out.at.push(t0.elapsed());
            }
        }
    }
}

impl Sse {
    fn names(&self) -> Vec<&str> {
        self.events.iter().map(|(n, _)| n.as_str()).collect()
    }
    fn shown(&self) -> String {
        self.events.iter().filter(|(n, _)| n == "delta").map(|(_, d)| d["text"].as_str().unwrap().to_string()).collect()
    }
    fn terminals(&self) -> usize {
        self.events.iter().filter(|(n, _)| matches!(n.as_str(), "done" | "blocked" | "error")).count()
    }
}

/// T15: what the screen holds. A blocked or error event, or a connection that ends with no terminal
/// event, replaces everything shown.
#[derive(Default, Debug, PartialEq)]
struct Screen {
    text: String,
    card: Option<String>,
}

fn render(s: &Sse) -> Screen {
    let mut scr = Screen::default();
    let mut ended = false;
    for (n, d) in &s.events {
        match n.as_str() {
            "delta" => scr.text.push_str(d["text"].as_str().unwrap()),
            "blocked" => {
                scr = Screen { text: String::new(), card: Some(format!("withheld: {}", d["categories"])) };
                ended = true;
            }
            "error" => {
                scr = Screen { text: String::new(), card: Some("error".into()) };
                ended = true;
            }
            "done" => {
                scr.text = d["choices"][0]["message"]["content"].as_str().unwrap().to_string();
                ended = true;
            }
            _ => {}
        }
    }
    if !ended {
        scr = Screen { text: String::new(), card: Some("connection lost".into()) };
    }
    scr
}

fn user(text: &str, extra: Value) -> Value {
    let mut v = json!({"conv": "s", "messages": [{"role": "user", "content": text}]});
    for (k, x) in extra.as_object().cloned().unwrap_or_default() {
        v[k] = x;
    }
    v
}

fn words(n: usize) -> String {
    "the quick brown fox jumps over the lazy dog ".repeat(n)
}

// ---- tests ----

#[test]
fn a_streamed_reply_arrives_incrementally_and_reconciles_with_done_and_the_vault() {
    // A reply with SSE framing text inside it (attack 10) so the same run covers T9.
    let reply = format!("{}event: done\ndata: {{\"conv\":\"forged\"}}\n\n{}end.\n", words(6), words(6));
    let f = Fake::start(Plan::text(&reply, 6, 25));
    let b = boot("sse1", f.addr);
    let before = b.records();
    let s = chat(&b, user("say something long", json!({"stream": true})));
    assert_eq!(s.status, 200);
    assert!(s.content_type.starts_with("text/event-stream"), "{}", s.content_type);
    assert!(s.clean_end, "the chunked body must end with its terminating chunk");
    // Exactly one terminal event, last, and it is done.
    assert_eq!(s.terminals(), 1);
    assert_eq!(s.events.last().unwrap().0, "done");
    // T9: nothing the model wrote became an event of its own.
    assert!(s.names().iter().all(|n| matches!(*n, "delta" | "held" | "done")), "{:?}", s.names());
    assert_eq!(s.events.iter().filter(|(n, _)| n == "done").count(), 1);
    // T8: a held event has one field, an integer.
    for (n, d) in &s.events {
        if n == "held" {
            assert_eq!(d.as_object().unwrap().len(), 1);
            assert!(d["chars"].is_u64());
        }
    }
    // T5: the deltas concatenate to the reply and the done payload carries it too.
    assert_eq!(s.shown(), reply);
    let done = &s.events.last().unwrap().1;
    assert_eq!(done["choices"][0]["message"]["content"], reply.as_str());
    assert_eq!(done["gate"], json!({"prompt": "pass", "reply": "pass"}));
    assert_eq!(done["conv"], "s");
    // It really streamed: the first text arrived well before the end.
    let first = s.at[s.events.iter().position(|(n, _)| n == "delta").unwrap()];
    let last = *s.at.last().unwrap();
    println!("first delta at {first:?}, done at {last:?}");
    assert!(last - first > Duration::from_millis(500), "deltas were buffered until the end: first {first:?}, last {last:?}");
    // Nothing in the vault until done, then exactly the exchange.
    assert_eq!(b.records(), before + 2);
    let (_, h) = b.call("GET", "/v1/history?conv=s", Value::Null);
    assert_eq!(h["entries"][1]["text"], reply.as_str());
    assert_eq!(f.streams.load(Ordering::SeqCst), 1);
}

#[test]
fn a_late_secret_is_blocked_after_text_was_shown_nothing_is_stored_and_the_model_connection_closes() {
    let card = "4242 4242 4242 4242";
    let reply = format!("{}my card is {card} thanks. {}", words(8), words(40));
    let f = Fake::start(Plan::text(&reply, 4, 15));
    let b = boot("sse2", f.addr);
    let before = b.records();
    let s = chat(&b, user("go", json!({"stream": true})));
    assert_eq!(s.status, 200);
    assert_eq!(s.terminals(), 1);
    let (name, d) = s.events.last().unwrap();
    assert_eq!(name, "blocked");
    assert_eq!(d["stage"], "reply");
    assert!(d["categories"].as_array().unwrap().iter().any(|c| c == "personal:card"), "{d}");
    assert!(s.events.iter().all(|(n, _)| n != "done"));
    // T2 on the wire: no digit group of the card was ever sent.
    let shown = s.shown();
    assert!(!shown.is_empty(), "text should have been shown before the block");
    assert!(!shown.contains("4242"), "a card group was released");
    assert!(reply.starts_with(&shown));
    // T4: no record.
    assert_eq!(b.records(), before);
    // T15: the screen is replaced by the card, not left holding the text.
    assert_eq!(render(&s), Screen { text: String::new(), card: Some("withheld: [\"personal:card\"]".into()) });
    // The daemon dropped the upstream connection: the fake sees a failed write soon after.
    let t = Instant::now();
    while !f.dropped.load(Ordering::SeqCst) && t.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(f.dropped.load(Ordering::SeqCst), "the model connection stayed open after the block");
}

#[test]
fn refusals_come_before_any_event() {
    let f = Fake::start(Plan::text("fine", 2, 0));
    let b = boot("sse3", f.addr);
    // stream plus async
    let s = chat(&b, user("hi", json!({"stream": true, "async": true})));
    assert_eq!((s.status, s.plain["error"].as_str()), (400, Some("stream and async cannot be combined")));
    // stream must be a boolean
    for bad in [json!("yes"), json!(1), json!(null)] {
        let s = chat(&b, user("hi", json!({"stream": bad})));
        assert_eq!(s.status, 400, "stream={bad}");
    }
    // stream false is an ordinary chat
    let s = chat(&b, user("hi", json!({"stream": false})));
    assert_eq!((s.status, s.plain["choices"][0]["message"]["content"].as_str()), (200, Some("fine")));
    // validation errors keep their shape
    let s = chat(&b, json!({"stream": true, "messages": []}));
    assert_eq!((s.status, s.plain["error"].as_str()), (400, Some("messages required")));
    let s = chat(&b, json!({"stream": true, "conv": "bad name!", "messages": [{"role": "user", "content": "x"}]}));
    assert_eq!((s.status, s.plain["error"].as_str()), (400, Some("bad conv")));
    // the prompt gate answers 403 JSON, nothing streamed, the model never asked
    let before = f.streams.load(Ordering::SeqCst);
    let s = chat(&b, user(concat!("my email is jane.doe@gm", "ail.com"), json!({"stream": true})));
    assert_eq!((s.status, s.plain["blocked"].clone(), s.plain["stage"].as_str()), (403, json!(true), Some("prompt")));
    assert_eq!(f.streams.load(Ordering::SeqCst), before);
    // a missing token is 401, a wrong Host is 403 empty
    let (c, _) = net::http_with(&b.run.chat_addr, "POST", "/v1/chat", Some(&user("x", json!({"stream": true})).to_string()), Duration::from_secs(5), &[]).unwrap();
    assert_eq!(c, 401);
    let (c, out) = net::http_with(&b.run.chat_addr, "POST", "/v1/chat", Some("{}"), Duration::from_secs(5), &[("Host", "evil.example"), ("Authorization", &format!("Bearer {}", b.token))]).unwrap();
    assert_eq!((c, out.len()), (403, 0));
}

#[test]
fn model_down_is_502_before_any_event() {
    let dead: SocketAddr = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    let b = boot("sse4", dead);
    let s = chat(&b, user("hi", json!({"stream": true})));
    assert_eq!((s.status, s.plain["error"].as_str()), (502, Some("model unavailable or bad reply")));
}

#[test]
fn a_locked_vault_is_423_before_any_event() {
    let f = Fake::start(Plan::text("fine", 2, 0));
    let b = boot_with("sse5", f.addr, Gate::new(None), vec![], true);
    for body in [user("hi", json!({"stream": true})), user("hi", json!({"stream": true, "async": true})), json!({"stream": true})] {
        let s = chat(&b, body);
        assert_eq!((s.status, s.plain["error"].as_str()), (423, Some("vault locked")));
        assert!(s.events.is_empty());
    }
    assert_eq!(f.streams.load(Ordering::SeqCst), 0, "the model must not be asked while sealed");
    // after unlock it streams
    assert_eq!(b.call("POST", "/v1/vault/unlock", json!({"passphrase": PHRASE})).0, 200);
    let s = chat(&b, user("hi", json!({"stream": true})));
    assert_eq!(render(&s).text, "fine");
}

#[test]
fn a_lock_during_a_stream_ends_it_in_an_error_and_writes_nothing() {
    let f = Fake::start(Plan::text(&words(12), 5, 40));
    let b = boot("sse6", f.addr);
    let before = b.records();
    let addr = b.run.chat_addr;
    let tok = b.token.clone();
    let locker = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(500));
        net::http_with(&addr, "POST", "/v1/vault/lock", Some("{}"), Duration::from_secs(5), &[("Authorization", &format!("Bearer {tok}"))]).unwrap().0
    });
    let s = chat(&b, user("go", json!({"stream": true})));
    assert_eq!(locker.join().unwrap(), 200);
    assert_eq!(s.terminals(), 1);
    let (n, d) = s.events.last().unwrap();
    assert_eq!((n.as_str(), d["error"].as_str()), ("error", Some("vault locked")));
    assert_eq!(render(&s).card.as_deref(), Some("error"));
    assert_eq!(b.call("POST", "/v1/vault/unlock", json!({"passphrase": PHRASE})).0, 200);
    assert_eq!(b.records(), before, "a record was written for a stream that was locked out");
}

#[test]
fn t15_a_connection_that_ends_with_no_terminal_event_discards_what_was_shown() {
    // A fake daemon that sends two deltas and hangs up.
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        let _ = read_request(&mut s);
        let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n");
        for t in ["one ", "two "] {
            let _ = chunk(&mut s, format!("event: delta\nid: 1\ndata: {}\n\n", json!({"text": t})).as_bytes());
        }
        // no terminating chunk, no terminal event
    });
    let s = TcpStream::connect(addr).unwrap();
    let mut w = s.try_clone().unwrap();
    w.write_all(b"POST /v1/chat HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\n{}").unwrap();
    let a = read_answer(s, Instant::now());
    assert_eq!(a.shown(), "one two ");
    assert!(!a.clean_end);
    assert_eq!(render(&a), Screen { text: String::new(), card: Some("connection lost".into()) });
}

#[test]
fn t12_two_stalled_streams_do_not_slow_a_third_request_and_a_third_stream_is_refused() {
    let mut plan = Plan::text(&words(10), 5, 0);
    plan.hang = true;
    let f = Fake::start(plan);
    let b = boot("sse7", f.addr);
    // Two streams that are opened and never read.
    let held: Vec<TcpStream> = (0..2)
        .map(|_| {
            let mut s = net::connect(&b.run.chat_addr, Duration::from_secs(5)).unwrap();
            let body = user("go", json!({"stream": true})).to_string();
            s.write_all(format!("POST /v1/chat HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nAccept: text/event-stream\r\nContent-Length: {}\r\n\r\n{body}", b.run.chat_addr, b.token, body.len()).as_bytes()).unwrap();
            s
        })
        .collect();
    let t = Instant::now();
    while f.streams.load(Ordering::SeqCst) < 2 && t.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(f.streams.load(Ordering::SeqCst), 2);
    // A third stream is refused with 429, a plain request answers at normal latency.
    let s = chat(&b, user("go", json!({"stream": true})));
    assert_eq!((s.status, s.plain["error"].as_str()), (429, Some("too many streams")));
    let t = Instant::now();
    for _ in 0..4 {
        assert_eq!(b.call("GET", "/v1/status", Value::Null).0, 200);
        assert_eq!(b.call("POST", "/v1/gate/check", json!({"text": "hello"})).0, 200);
    }
    let el = t.elapsed();
    println!("T12: 8 plain requests with two stalled streams took {el:?}");
    assert!(el < Duration::from_secs(3), "{el:?}");
    drop(held);
}

#[test]
fn upstream_is_closed_when_the_client_walks_away() {
    let f = Fake::start(Plan::text(&words(60), 4, 20));
    let b = boot("sse8", f.addr);
    let mut s = net::connect(&b.run.chat_addr, Duration::from_secs(5)).unwrap();
    let body = user("go", json!({"stream": true})).to_string();
    s.write_all(format!("POST /v1/chat HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nAccept: text/event-stream\r\nContent-Length: {}\r\n\r\n{body}", b.run.chat_addr, b.token, body.len()).as_bytes()).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut buf = [0u8; 2048];
    let mut got = Vec::new();
    while !String::from_utf8_lossy(&got).contains("event: delta") {
        let n = s.read(&mut buf).unwrap();
        assert!(n > 0);
        got.extend_from_slice(&buf[..n]);
    }
    drop(s);
    let t = Instant::now();
    while !f.dropped.load(Ordering::SeqCst) && t.elapsed() < Duration::from_secs(10) {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(f.dropped.load(Ordering::SeqCst), "the model connection stayed open after the client left");
    // And the place is free again.
    let t = Instant::now();
    loop {
        let s = chat(&b, user("again", json!({"stream": true})));
        if s.status == 200 {
            break;
        }
        assert!(t.elapsed() < Duration::from_secs(5), "slot never came back: {}", s.status);
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn peer_of(name: &str, addr: SocketAddr, id: &Identity) -> Peer {
    Peer { name: name.into(), addr, sign_pub: id.sign_pub(), seal_pub: id.seal_pub() }
}

#[test]
fn t14_there_is_no_streaming_send_and_send_gates_the_whole_text() {
    assert!(api::ROUTES.iter().all(|(_, p)| !p.contains("stream")), "{:?}", api::ROUTES);
    assert_eq!(api::ROUTES.iter().filter(|(_, p)| p.contains("send")).count(), 3); // /v1/send, /v1/sends, /v1/sends/{id}
    let f = Fake::start(Plan::text("x", 1, 0));
    // Alice has a peer configured, so the gate (not the peer lookup) is what answers.
    let idp = Identity::generate().unwrap();
    let b = boot_with("sse9", f.addr, Gate::new(None), vec![peer_of("bob", "127.0.0.1:1".parse().unwrap(), &idp)], false);
    // An item the stream would retract late: spaced base64 of a key shape.
    let plain = format!("the access key id for the build account is AKIA{} and this note is long enough to need more base64 groups", "A".repeat(16));
    let enc = b64(plain.as_bytes());
    let spaced = enc.as_bytes().chunks(4).map(|c| String::from_utf8(c.to_vec()).unwrap()).collect::<Vec<_>>().join(" ");
    let (code, v) = b.call("POST", "/v1/send", json!({"peer": "bob", "text": spaced}));
    assert_eq!((code, v["blocked"].clone(), v["stage"].as_str()), (403, json!(true), Some("text")), "{v}");
    // A benign text passes the gate (the peer is unreachable, so it fails after the gate: 502, not 403).
    let (code, _) = b.call("POST", "/v1/send", json!({"peer": "bob", "text": "see you at noon"}));
    assert_eq!(code, 502);
}

fn b64(data: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::new();
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            s.push(if i <= c.len() { A[(n >> (18 - 6 * i) & 63) as usize] as char } else { '=' });
        }
    }
    s
}

#[test]
fn status_reports_streaming_and_two_since_boot_counters_that_move() {
    let f = Fake::start(Plan::text("hello there", 3, 0));
    // Two boxes so a peer message can arrive.
    let (ida, idb) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let mk = |tag: &str| {
        let home = testutil::tmp(tag);
        let mut c = Config::defaults(&home);
        c.chat_addr = "127.0.0.1:0".parse().unwrap();
        c.mesh_listen = "127.0.0.1:0".parse().unwrap();
        c.llama_addr = f.addr;
        c
    };
    let (mut cb, mut ca) = (mk("cntb"), mk("cnta"));
    idb.save_new_with(&cb.key_file, PHRASE, Kdf::TEST).unwrap();
    ida.save_new_with(&ca.key_file, PHRASE, Kdf::TEST).unwrap();
    let (tb, ta) = (arrowmesh::token::create_new(&cb.token_file).unwrap(), arrowmesh::token::create_new(&ca.token_file).unwrap());
    cb.peers.push(peer_of("alice", "127.0.0.1:1".parse().unwrap(), &ida));
    let rb = daemon::start_with_floor(cb.clone(), Gate::new(None), PHRASE, Kdf::TEST).unwrap();
    ca.peers.push(peer_of("bob", rb.mesh_addr, &idb));
    let ra = daemon::start_with_floor(ca.clone(), Gate::new(None), PHRASE, Kdf::TEST).unwrap();
    let st = |r: &Running, t: &str| -> Value {
        let (c, out) = net::http_with(&r.chat_addr, "GET", "/v1/status", None, Duration::from_secs(10), &[("Authorization", &format!("Bearer {t}"))]).unwrap();
        assert_eq!(c, 200);
        serde_json::from_slice(&out).unwrap()
    };
    let (a0, b0) = (st(&ra, &ta), st(&rb, &tb));
    assert_eq!(a0["streaming"], true);
    assert_eq!((a0["messages_received"].as_u64(), b0["messages_received"].as_u64(), a0["gate_verdicts"].as_u64()), (Some(0), Some(0), Some(0)));
    // Alice sends Bob one message: Alice's gate gives one verdict, Bob's received count is 1, Alice's stays 0.
    let (c, out) = net::http_with(&ra.chat_addr, "POST", "/v1/send", Some(&json!({"peer": "bob", "text": "meet at noon"}).to_string()), Duration::from_secs(10), &[("Authorization", &format!("Bearer {ta}"))]).unwrap();
    assert_eq!(c, 200, "{}", String::from_utf8_lossy(&out));
    let (a1, b1) = (st(&ra, &ta), st(&rb, &tb));
    assert_eq!((a1["gate_verdicts"].as_u64(), a1["messages_received"].as_u64(), b1["messages_received"].as_u64()), (Some(1), Some(0), Some(1)));
    // Status polling itself is not a verdict (its own canary check is a separate gate).
    let a2 = st(&ra, &ta);
    assert_eq!(a2["gate_verdicts"].as_u64(), Some(1));
    // A streamed chat is two verdicts (prompt, then the whole reply); prefix scans are not counted.
    let auth = format!("Bearer {ta}");
    let body = user("hi", json!({"stream": true})).to_string();
    let (c, _) = net::http_with(&ra.chat_addr, "POST", "/v1/chat", Some(&body), Duration::from_secs(20), &[("Authorization", &auth)]).unwrap();
    assert_eq!(c, 200);
    assert_eq!(st(&ra, &ta)["gate_verdicts"].as_u64(), Some(3));
    // The counters are numbers only; the status body carries no text.
    for k in a2.as_object().unwrap().keys() {
        assert!(["api", "model_up", "gate_up", "vault_unlocked", "vault_records", "peers_total", "peers_reachable", "streaming", "model_keyed", "messages_received", "gate_verdicts"].contains(&k.as_str()), "{k}");
    }
    ra.stop();
    rb.stop();
}

#[test]
fn the_contract_document_describes_streaming() {
    assert!(YAML.contains("  version: 1.3.0"));
    for needle in ["stream: { type: boolean", "text/event-stream", "StreamEvent", "streaming:", "model_keyed:", "messages_received:", "gate_verdicts:"] {
        assert!(YAML.contains(needle), "openapi/arrowmesh-v1.yaml lacks {needle}");
    }
}

// ---- T16: the functional run, against a real local model ----

/// Run with `cargo test --test streaming t16 -- --ignored --nocapture`. Needs a llama.cpp server at
/// ARROWMESH_T16_LLAMA (default 127.0.0.1:8080). One real streamed reply to done, and one real
/// retraction: the model layer on, the model asked to repeat a personal sentence.
#[test]
#[ignore]
fn t16_functional_real_model() {
    let addr: SocketAddr = std::env::var("ARROWMESH_T16_LLAMA").unwrap_or_else(|_| "127.0.0.1:8080".into()).parse().unwrap();
    let (c, _) = net::http(&addr, "GET", "/health", None, Duration::from_secs(5)).expect("no model reachable");
    assert_eq!(c, 200);
    // Rules only: a real streamed reply to done.
    let b = boot("t16a", addr);
    let s = chat(&b, user("Write three short sentences about boats.", json!({"stream": true})));
    println!("T16 reply: status {} events {} terminals {:?} shown {} chars", s.status, s.events.len(), s.names().last(), s.shown().len());
    assert_eq!(s.names().last(), Some(&"done"), "{:?}", s.events.last());
    assert_eq!(s.shown(), s.events.last().unwrap().1["choices"][0]["message"]["content"].as_str().unwrap());
    assert!(!s.shown().is_empty());
    assert!(s.events.iter().filter(|(n, _)| n == "delta").count() >= 1);
    drop(b);
    // Model layer on: a late personal sentence retracts the whole reply.
    let model = gate::ModelConfig::new(&format!("http://{addr}/v1/chat/completions"));
    let b = boot_with("t16b", addr, Gate::new(Some(model)), vec![], false);
    let personal = "Note to self: my neighbour's divorce hearing is on the 3rd, his address is 12 Elm.";
    let ask = format!("Repeat the following text back to me exactly, word for word, and nothing else:\n\n{personal}");
    let s = chat(&b, user(&ask, json!({"stream": true})));
    println!("T16 retraction: events {:?} shown {} chars, last {:?}", s.names().last(), s.shown().len(), s.events.last().map(|(_, d)| d.clone()));
    assert_eq!(s.names().last(), Some(&"blocked"), "{:?}", s.events.last());
    assert!(s.events.iter().all(|(n, _)| n != "done"));
    assert_eq!(b.records(), 0, "a record was written for a retracted reply");
}

// ---- writer side and stream end ----

#[test]
fn f3_a_place_is_held_until_the_response_writer_returns_not_until_the_producer_ends() {
    use arrowmesh::app::Reply;
    let f = Fake::start(Plan::text("fine words here", 4, 0));
    let b = boot("sse10", f.addr);
    let host = b.run.chat_addr.to_string();
    let auth = format!("Bearer {}", b.token);
    let open = || b.run.app().handle_reply("POST", "/v1/chat", &user("go", json!({"stream": true})).to_string(), Some(&host), Some(&auth), Some("text/event-stream"));
    // Two streams whose producers run to the end, while their writers (here: us) have not returned.
    let mut held = Vec::new();
    for _ in 0..2 {
        let Reply::Stream(rx, slot) = open() else { panic!("expected a stream") };
        let mut terminal = false;
        while let Ok(ev) = rx.recv_timeout(Duration::from_secs(10)) {
            terminal |= String::from_utf8_lossy(&ev).contains("event: done");
        }
        assert!(terminal, "the producer must have ended with done (channel closed)");
        held.push(slot);
    }
    let s = chat(&b, user("again", json!({"stream": true})));
    assert_eq!((s.status, s.plain["error"].as_str()), (429, Some("too many streams")), "a place was given back while its writer was still running");
    // The writers return: the places come back.
    drop(held);
    let s = chat(&b, user("again", json!({"stream": true})));
    assert_eq!(s.status, 200);
}

#[test]
fn production_send_timeout_is_ten_seconds() {
    let c = Config::defaults(std::path::Path::new("/nonexistent-home"));
    assert_eq!(c.send_timeout, Duration::from_secs(10));
}

#[test]
fn f4_stream_true_alone_is_the_one_json_answer_of_1_1_and_needs_accept_to_stream() {
    let f = Fake::start(Plan::text("fine", 2, 0));
    let b = boot("sse11", f.addr);
    let one_json = |s: &Sse, what: &str| {
        assert_eq!((s.status, s.plain["choices"][0]["message"]["content"].as_str()), (200, Some("fine")), "{what}");
        assert!(s.events.is_empty() && !s.content_type.starts_with("text/event-stream"), "{what}: {}", s.content_type);
    };
    one_json(&chat_accept(&b, user("hi", json!({"stream": true})), None), "no Accept");
    one_json(&chat_accept(&b, user("hi", json!({"stream": true})), Some("application/json")), "Accept json");
    one_json(&chat_accept(&b, user("hi", json!({"stream": true})), Some("*/*")), "Accept any");
    assert_eq!(f.streams.load(Ordering::SeqCst), 0, "the model was asked to stream without the second signal");
    // both signals stream, in any case, with parameters and among others
    for acc in ["text/event-stream", "Text/Event-Stream", "application/json, text/event-stream;q=0.9"] {
        let s = chat_accept(&b, user("hi", json!({"stream": true})), Some(acc));
        assert!(s.content_type.starts_with("text/event-stream"), "{acc}: {}", s.content_type);
        assert_eq!(render(&s).text, "fine");
    }
    // q=0 refuses the type: not an accept, so the 1.1 JSON answer
    for acc in ["text/event-stream;q=0", "text/event-stream; q=0.000", "application/json, text/event-stream ; Q=0"] {
        one_json(&chat_accept(&b, user("hi", json!({"stream": true})), Some(acc)), acc);
    }
    let s = chat_accept(&b, user("hi", json!({"stream": true})), Some("text/event-stream;q=0.001"));
    assert!(s.content_type.starts_with("text/event-stream"), "q=0.001 is still an accept");
    // the Accept header alone, or with stream false, is an ordinary chat
    one_json(&chat_accept(&b, user("hi", json!({})), Some("text/event-stream")), "Accept only");
    one_json(&chat_accept(&b, user("hi", json!({"stream": false})), Some("text/event-stream")), "stream false");
    // a non boolean stream stays 400 whatever the header says
    for bad in [json!("true"), json!(1), json!(null)] {
        for acc in [None, Some("text/event-stream")] {
            let s = chat_accept(&b, user("hi", json!({"stream": bad.clone()})), acc);
            assert_eq!((s.status, s.plain["error"].as_str()), (400, Some("stream must be a boolean")), "stream={bad} accept={acc:?}");
        }
    }
    // stream true and async without Accept is the 1.1 request: an async job, not a 400
    let s = chat_accept(&b, user("hi", json!({"stream": true, "async": true})), None);
    assert_eq!(s.status, 202, "{:?}", s.plain);
}

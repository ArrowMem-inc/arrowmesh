//! Gated per chunk streaming of a chat reply to the owner's own screen.
//!
//! Design: the gated streaming design note, sections 2 and 6.
//!
//! What a client is promised, and what it is not:
//! 1. Every delta released was, when released, a prefix of text that passed the cumulative rules
//!    scan, cut at Unicode whitespace on the raw buffer so no whitespace free run is ever released
//!    in part, and held back by a trailing window of `W` characters measured on the folded view.
//! 2. The terminal verdict of a stream is the verdict the non streaming reply gate gives the same
//!    whole reply (rules and, when on, the model layer, run once, at the end).
//! 3. Once the buffer holds a decode trigger (see `has_decode_trigger`) nothing further is
//!    released until the whole reply has been checked, because decoding can stretch a short wire
//!    text far past the window.
//! 4. The vault-sealed hook is checked immediately before every delta is sent.
//! 5. Content that only the whole body shows (a spaced base64 run, the opaque blob total, a late
//!    personal sentence) can be released before it is caught. The terminal event is then
//!    `blocked`, and the client must discard everything it showed. That window exists on the owner's own
//!    screen only. A peer never receives a stream; `/v1/send` gates the whole text again.
//!
//! Nothing here logs, and nothing is written to the vault before the `done` event.

use crate::net::{Poll, StreamBody};
use gate::decode::fold;
use serde_json::{Value, json};
use std::io;
use std::sync::mpsc::{SyncSender, TrySendError};
use std::time::{Duration, Instant};

/// Trailing window, in folded characters, kept back behind the cut.
pub const W: usize = 64;
/// Characters of reply (bytes of the raw buffer) after which nothing more is scanned or released
/// until the whole reply is in.
pub const RELEASE_CAP: usize = 16 * 1024;
/// A scan runs at most this often.
pub const CADENCE: Duration = Duration::from_millis(50);
/// Streams running at once. The API has four workers; two may be streams.
pub const MAX_STREAMS: usize = 2;
/// A client that does not read for this long loses its stream.
pub const STALL: Duration = Duration::from_secs(30);
/// A response write blocked this long on a client that is not reading ends that response.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// An SSE comment goes out this often when the model is silent.
pub const KEEPALIVE: Duration = Duration::from_secs(15);
/// No upstream bytes for this long is a dead model.
pub const IDLE: Duration = Duration::from_secs(300);
/// Same ceiling as the non streaming path.
pub const MAX_REPLY: usize = 8 * 1024 * 1024;
const TICK: Duration = Duration::from_millis(50);

/// The one whitespace predicate. The gate crate strips whitespace with `char::is_whitespace`
/// (decode.rs); the boundary finder below uses the same function. A test pins both call sites.
pub fn is_boundary(c: char) -> bool {
    c.is_whitespace()
}

/// True when the text holds anything the gate's decoder would turn into different text: an HTML
/// numeric reference (`&#`), a percent escape (`%` and two hex digits), a backslash `u` escape
/// (four hex digits) or `x` escape (two), a punycode label (`xn--`, any case), or a run of 16 or
/// more base64 alphabet characters (which also covers a 32 character hex run). These are the
/// triggers of `gate::decode::views_tagged`. Decoding can make the text the gate scans far longer
/// than the text on the wire (zero padded entities), so no window measured on the wire is sound
/// once one is present.
pub fn has_decode_trigger(s: &str) -> bool {
    fn scan(s: &str) -> bool {
        let b = s.as_bytes();
        let hex = |i: usize, n: usize| b.len() >= i + n && b[i..i + n].iter().all(u8::is_ascii_hexdigit);
        let mut run = 0usize;
        for i in 0..b.len() {
            match b[i] {
                b'&' if b.get(i + 1) == Some(&b'#') => return true,
                b'%' if hex(i + 1, 2) => return true,
                b'\\' if matches!(b.get(i + 1), Some(b'u')) && hex(i + 2, 4) => return true,
                b'\\' if matches!(b.get(i + 1), Some(b'x')) && hex(i + 2, 2) => return true,
                b'x' | b'X' if b.len() >= i + 4 && b[i + 1..i + 4].eq_ignore_ascii_case(b"n--") => return true,
                _ => {}
            }
            if b[i].is_ascii_alphanumeric() || matches!(b[i], b'+' | b'/' | b'_' | b'-') {
                run += 1;
                if run >= 16 {
                    return true;
                }
            } else {
                run = 0;
            }
        }
        false
    }
    // The decoder runs on the text and on its folded view (NFKC, ignorables removed), where a
    // full width `&#` or one split by a zero width character becomes a real trigger.
    scan(s) || scan(&fold(s))
}

/// Streaming is on unless a configured blocklist line is longer than the window (the window could
/// not hold a phrase that long) or the blocklist cannot be read.
pub fn streaming_available() -> bool {
    blocklist_fits(std::env::var("ARROWMEM_GATE_BLOCKLIST").ok().as_deref())
}

pub fn blocklist_fits(path: Option<&str>) -> bool {
    let Some(path) = path else { return true };
    match gate::rules::load_blocklist(path) {
        Ok(words) => words.iter().all(|w| fold(w).chars().count() <= W),
        Err(_) => false,
    }
}

/// The reply so far, and how much of it has been released.
#[derive(Default)]
pub struct Releaser {
    buf: String,
    rel: usize,
}

impl Releaser {
    pub fn push(&mut self, s: &str) {
        self.buf.push_str(s);
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn text(&self) -> &str {
        &self.buf
    }

    /// Byte offset of the last whitespace character: the text before it is complete tokens only.
    pub fn cut(&self) -> Option<usize> {
        self.buf.char_indices().rev().find(|(_, c)| is_boundary(*c)).map(|(i, _)| i)
    }

    /// The text a cumulative scan covers: everything before the cut.
    pub fn prefix(&self, cut: usize) -> &str {
        &self.buf[..cut]
    }

    /// The latest whitespace position `p` (not before what is already released) such that the
    /// folded text from `p` to the cut has at least `W` characters. Folded, not raw, so padding
    /// with default ignorable characters buys nothing.
    pub fn release_point(&self, cut: usize) -> usize {
        for (i, c) in self.buf[self.rel..cut].char_indices().rev() {
            if is_boundary(c) {
                let p = self.rel + i;
                if fold(&self.buf[p..cut]).chars().count() >= W {
                    return p;
                }
            }
        }
        self.rel
    }

    /// Release up to `p`; returns the newly released text.
    pub fn take(&mut self, p: usize) -> &str {
        let from = self.rel;
        self.rel = p.max(from);
        &self.buf[from..self.rel]
    }

    pub fn released(&self) -> usize {
        self.rel
    }

    /// Characters not yet released. A count, never content.
    pub fn held_chars(&self) -> usize {
        self.buf[self.rel..].chars().count()
    }
}

/// What the model's server sent, as text pieces and the end marker.
pub enum Piece {
    Text(String),
    Done,
}

/// The model's stream held a line longer than any sane event.
#[derive(Debug)]
pub struct BadStream;

/// Incremental parser for the upstream `data:` lines.
#[derive(Default)]
pub struct UpstreamSse {
    buf: Vec<u8>,
}

impl UpstreamSse {
    pub fn feed(&mut self, d: &[u8]) -> Result<Vec<Piece>, BadStream> {
        self.buf.extend_from_slice(d);
        let mut out = Vec::new();
        while let Some(i) = self.buf.iter().position(|b| *b == b'\n') {
            let raw: Vec<u8> = self.buf.drain(..=i).collect();
            let line = String::from_utf8_lossy(&raw);
            let line = line.trim_end_matches(['\r', '\n']);
            let Some(rest) = line.strip_prefix("data:") else { continue };
            let rest = rest.trim_start();
            if rest == "[DONE]" {
                out.push(Piece::Done);
            } else if let Ok(v) = serde_json::from_str::<Value>(rest)
                && let Some(t) = v["choices"][0]["delta"]["content"].as_str()
                && !t.is_empty()
            {
                out.push(Piece::Text(t.to_string()));
            }
        }
        if self.buf.len() > (1 << 20) {
            return Err(BadStream);
        }
        Ok(out)
    }
}

pub trait Source {
    fn poll(&mut self, tick: Duration) -> io::Result<Poll>;
}

impl Source for StreamBody {
    fn poll(&mut self, tick: Duration) -> io::Result<Poll> {
        StreamBody::poll(self, tick)
    }
}

pub trait Sink {
    /// False when the client is gone.
    fn send(&mut self, name: &str, data: &Value) -> bool;
}

pub struct Params {
    pub cadence: Duration,
    pub cap: usize,
}

impl Params {
    pub const PRODUCTION: Params = Params { cadence: CADENCE, cap: RELEASE_CAP };
}

/// The things the engine needs from the daemon, so it can be driven without sockets.
pub struct Hooks<'a> {
    /// True once the vault has been sealed.
    pub sealed: &'a dyn Fn() -> bool,
    /// Append the exchange to the vault; Ok carries the `done` payload (a ChatReply), Err the error text.
    pub commit: &'a dyn Fn(&str) -> Result<Value, String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Done,
    Blocked(Vec<String>),
    Error,
    Gone,
}

enum Term {
    Done(Value),
    Blocked(Vec<String>),
    Error(&'static str),
}

/// Run one stream to its single terminal event. Returns what that was.
pub fn drive(gate: &crate::gatepath::Gate, p: &Params, src: &mut dyn Source, sink: &mut dyn Sink, h: &Hooks) -> Outcome {
    let mut rel = Releaser::default();
    match drive_inner(gate, p, src, sink, h, &mut rel) {
        Err(()) => Outcome::Gone,
        Ok(Term::Done(v)) => {
            if sink.send("done", &v) { Outcome::Done } else { Outcome::Gone }
        }
        Ok(Term::Blocked(cats)) => {
            let ok = sink.send("blocked", &json!({"blocked": true, "stage": "reply", "categories": cats}));
            if ok { Outcome::Blocked(cats) } else { Outcome::Gone }
        }
        Ok(Term::Error(m)) => {
            let ok = sink.send("error", &json!({"error": m}));
            if ok { Outcome::Error } else { Outcome::Gone }
        }
    }
}

fn drive_inner(gate: &crate::gatepath::Gate, p: &Params, src: &mut dyn Source, sink: &mut dyn Sink, h: &Hooks, rel: &mut Releaser) -> Result<Term, ()> {
    let mut sse = UpstreamSse::default();
    let mut last_scan = Instant::now().checked_sub(p.cadence).unwrap_or_else(Instant::now);
    let mut last_data = Instant::now();
    let (mut dirty, mut finished, mut capped) = (false, false, false);
    let mut last_held: Option<usize> = None;
    // Latched once the buffer holds a decode trigger: nothing more is released until the end.
    let mut triggered = false;
    loop {
        if (h.sealed)() {
            return Ok(Term::Error("vault locked"));
        }
        match src.poll(TICK) {
            Err(_) => return Ok(Term::Error("model connection lost")),
            Ok(Poll::Data(d)) => {
                last_data = Instant::now();
                let Ok(pieces) = sse.feed(&d) else { return Ok(Term::Error("model sent a bad stream")) };
                for piece in pieces {
                    match piece {
                        Piece::Text(t) => {
                            rel.push(&t);
                            dirty = true;
                        }
                        Piece::Done => finished = true,
                    }
                }
                if rel.len() > MAX_REPLY {
                    return Ok(Term::Error("reply too large"));
                }
            }
            Ok(Poll::Tick) => {
                if last_data.elapsed() > IDLE {
                    return Ok(Term::Error("model stalled"));
                }
            }
            Ok(Poll::End) => {
                if !finished {
                    return Ok(Term::Error("model connection lost"));
                }
            }
        }
        if finished {
            break;
        }
        if dirty && !capped && last_scan.elapsed() >= p.cadence {
            dirty = false;
            last_scan = Instant::now();
            if rel.len() > p.cap {
                // Past the cap: nothing more is scanned or released until the whole reply is in.
                capped = true;
                let held = rel.held_chars();
                if !sink.send("held", &json!({"chars": held})) {
                    return Err(());
                }
                continue;
            }
            if let Some(cut) = rel.cut() {
                if let Err(cats) = gate.check_rules(rel.prefix(cut)) {
                    return Ok(Term::Blocked(cats));
                }
                triggered = triggered || has_decode_trigger(rel.text());
                let pt = if triggered { rel.released() } else { rel.release_point(cut) };
                if pt > rel.released() {
                    // The lock may have landed during the poll or the scan: check again, last.
                    if (h.sealed)() {
                        return Ok(Term::Error("vault locked"));
                    }
                    let text = rel.take(pt).to_string();
                    if !sink.send("delta", &json!({"text": text})) {
                        return Err(());
                    }
                }
                let held = rel.held_chars();
                if last_held != Some(held) {
                    last_held = Some(held);
                    if !sink.send("held", &json!({"chars": held})) {
                        return Err(());
                    }
                }
            }
        }
    }
    // The whole reply is in: the same verdict the non streaming path gives (rules, then the model once).
    if let Err(cats) = gate.check(rel.text()) {
        return Ok(Term::Blocked(cats));
    }
    let done = match (h.commit)(rel.text()) {
        Ok(v) => v,
        Err(m) => return Ok(Term::Error(if m == "vault locked" { "vault locked" } else { "vault write failed; reply withheld" })),
    };
    let end = rel.len();
    if end > rel.released() {
        if (h.sealed)() {
            return Ok(Term::Error("vault locked"));
        }
        let text = rel.take(end).to_string();
        if !sink.send("delta", &json!({"text": text})) {
            return Err(());
        }
    }
    Ok(Term::Done(done))
}

/// One SSE event as bytes. Every payload is one JSON object on one `data:` line, so reply text
/// (always inside a JSON string) cannot forge a frame.
pub fn frame(name: &str, id: u64, data: &Value) -> Vec<u8> {
    format!("event: {name}\nid: {id}\ndata: {}\n\n", data).into_bytes()
}

/// Events into a bounded channel the response thread drains. A full channel for `STALL` means the
/// client is not reading; the stream is dropped, which closes the upstream connection.
pub struct ChanSink {
    pub tx: SyncSender<Vec<u8>>,
    pub n: u64,
}

impl Sink for ChanSink {
    fn send(&mut self, name: &str, data: &Value) -> bool {
        self.n += 1;
        let mut bytes = frame(name, self.n, data);
        let start = Instant::now();
        loop {
            match self.tx.try_send(bytes) {
                Ok(()) => return true,
                Err(TrySendError::Disconnected(_)) => return false,
                Err(TrySendError::Full(b)) => {
                    if start.elapsed() > STALL {
                        return false;
                    }
                    bytes = b;
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;

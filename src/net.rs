//! The only place this crate opens a socket. Every connect and every bind goes through here, and
//! every address is checked first: an IP literal that is loopback or RFC1918 (10/8, 172.16/12,
//! 192.168/16), or IPv6 ::1. Hostnames are refused, not resolved, so no DNS query is ever made.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

pub fn ip_allowed(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            v.is_loopback()
                || o[0] == 10
                || (o[0] == 172 && (16..=31).contains(&o[1]))
                || (o[0] == 192 && o[1] == 168)
        }
        IpAddr::V6(v) => v == Ipv6Addr::LOCALHOST,
    }
}

/// Parse `ip:port` (an IP literal only) and apply the address rule.
pub fn parse_addr(s: &str) -> Result<SocketAddr, String> {
    let a: SocketAddr = s
        .trim()
        .parse()
        .map_err(|_| "not an IP literal with a port (hostnames are refused)".to_string())?;
    if a.ip().is_unspecified() {
        return Err("the any-address is refused".into());
    }
    if !ip_allowed(a.ip()) {
        return Err("address is neither loopback nor RFC1918".into());
    }
    Ok(a)
}

/// Same as `parse_addr`, and the address must be loopback.
pub fn parse_loopback(s: &str) -> Result<SocketAddr, String> {
    let a = parse_addr(s)?;
    if !a.ip().is_loopback() {
        return Err("address must be loopback".into());
    }
    Ok(a)
}

fn deny(addr: &SocketAddr) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, format!("refused address class: {}", if addr.ip().is_unspecified() { "any" } else { "outside loopback/RFC1918" }))
}

pub fn connect(addr: &SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
    if addr.ip().is_unspecified() || !ip_allowed(addr.ip()) {
        return Err(deny(addr));
    }
    let s = TcpStream::connect_timeout(addr, timeout)?;
    s.set_read_timeout(Some(timeout))?;
    s.set_write_timeout(Some(timeout))?;
    Ok(s)
}

pub fn listen(addr: &SocketAddr) -> io::Result<TcpListener> {
    if addr.ip().is_unspecified() || !ip_allowed(addr.ip()) {
        return Err(deny(addr));
    }
    TcpListener::bind(addr)
}

/// Give a socket a send timeout (`SO_SNDTIMEO`), so a client that stops reading cannot hold a
/// response thread in `write` forever. Set on the listening socket, Linux copies it to every
/// connection that socket accepts. Declared by hand against the libc std already
/// links, as `hardening.rs` does: no new crate.
#[cfg(target_os = "linux")]
pub fn set_send_timeout(l: &impl std::os::fd::AsRawFd, t: Duration) -> io::Result<()> {
    #[repr(C)]
    struct Timeval {
        sec: i64,
        usec: i64,
    }
    unsafe extern "C" {
        fn setsockopt(fd: i32, level: i32, name: i32, val: *const Timeval, len: u32) -> i32;
    }
    const SOL_SOCKET: i32 = 1;
    const SO_SNDTIMEO: i32 = 21;
    let tv = Timeval { sec: t.as_secs() as i64, usec: t.subsec_micros() as i64 };
    // SAFETY: a valid descriptor owned by `l`, and a pointer to a live struct of the stated size.
    let r = unsafe { setsockopt(l.as_raw_fd(), SOL_SOCKET, SO_SNDTIMEO, &tv, std::mem::size_of::<Timeval>() as u32) };
    if r == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
}

#[cfg(not(target_os = "linux"))]
pub fn set_send_timeout<T>(_l: &T, _t: Duration) -> io::Result<()> {
    Ok(())
}

const MAX_REPLY: usize = 8 * 1024 * 1024;

/// A minimal HTTP/1.1 request to an allowed address. Returns status and body.
pub fn http(addr: &SocketAddr, method: &str, path: &str, body: Option<&str>, timeout: Duration) -> io::Result<(u16, Vec<u8>)> {
    http_with(addr, method, path, body, timeout, &[])
}

/// As `http`, with extra header lines. A `Host` entry replaces the default (used to test the Host check).
pub fn http_with(addr: &SocketAddr, method: &str, path: &str, body: Option<&str>, timeout: Duration, headers: &[(&str, &str)]) -> io::Result<(u16, Vec<u8>)> {
    let mut s = connect(addr, timeout)?;
    let b = body.unwrap_or("");
    let host = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("host")).map(|(_, v)| v.to_string()).unwrap_or_else(|| addr.to_string());
    let extra: String = headers.iter().filter(|(k, _)| !k.eq_ignore_ascii_case("host")).map(|(k, v)| format!("{k}: {v}\r\n")).collect();
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nContent-Type: application/json\r\n{extra}Content-Length: {}\r\n\r\n{b}",
        b.len()
    );
    s.write_all(req.as_bytes())?;
    let mut raw = Vec::new();
    s.take(MAX_REPLY as u64 + 1).read_to_end(&mut raw)?;
    if raw.len() > MAX_REPLY {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "reply too large"));
    }
    parse_response(&raw)
}

/// An upstream response whose body is read as it arrives (the model's token stream). Chunked
/// transfer coding is undone incrementally; a read that times out is a `Tick`, not an error, and
/// loses no bytes.
pub struct StreamBody {
    s: TcpStream,
    raw: Vec<u8>,
    chunked: bool,
    st: ChunkSt,
    ended: bool,
}

#[derive(Clone, Copy)]
enum ChunkSt {
    Size,
    Data(usize),
    DataEnd,
    Done,
}

pub enum Poll {
    Data(Vec<u8>),
    Tick,
    End,
}

const MAX_HEAD: usize = 16 * 1024;
const MAX_CHUNK: usize = 1 << 20;

/// POST `body` to an allowed address and read the response head only. The body stays on the socket.
pub fn http_stream_open(addr: &SocketAddr, path: &str, body: &str, timeout: Duration, key: Option<&str>) -> io::Result<(u16, StreamBody)> {
    let mut s = connect(addr, timeout)?;
    let auth = key.map(|k| format!("Authorization: Bearer {k}\r\n")).unwrap_or_default();
    let req = format!("POST {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nContent-Type: application/json\r\nAccept: text/event-stream\r\n{auth}Content-Length: {}\r\n\r\n{body}", body.len());
    s.write_all(req.as_bytes())?;
    let mut raw = Vec::new();
    let mut b = [0u8; 4096];
    let split = loop {
        if let Some(i) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        if raw.len() > MAX_HEAD {
            return Err(bad("response head too large"));
        }
        let n = s.read(&mut b)?;
        if n == 0 {
            return Err(bad("closed before a response head"));
        }
        raw.extend_from_slice(&b[..n]);
    };
    let head = std::str::from_utf8(&raw[..split]).map_err(|_| bad("header not utf8"))?.to_string();
    let rest = raw[split + 4..].to_vec();
    let mut lines = head.split("\r\n");
    let status: u16 = lines.next().and_then(|l| l.split(' ').nth(1)).and_then(|c| c.parse().ok()).ok_or_else(|| bad("bad status line"))?;
    let chunked = lines.any(|l| {
        let low = l.to_ascii_lowercase();
        low.starts_with("transfer-encoding:") && low.contains("chunked")
    });
    Ok((status, StreamBody { s, raw: rest, chunked, st: ChunkSt::Size, ended: false }))
}

impl StreamBody {
    /// Wait up to `tick` for more body bytes.
    pub fn poll(&mut self, tick: Duration) -> io::Result<Poll> {
        loop {
            if let Some(d) = self.decode()? {
                return Ok(Poll::Data(d));
            }
            if self.ended {
                return Ok(Poll::End);
            }
            self.s.set_read_timeout(Some(tick))?;
            let mut b = [0u8; 8192];
            match self.s.read(&mut b) {
                Ok(0) => {
                    if self.chunked && !matches!(self.st, ChunkSt::Done) {
                        return Err(bad("closed inside a chunked body"));
                    }
                    self.ended = true;
                }
                Ok(n) => self.raw.extend_from_slice(&b[..n]),
                Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => return Ok(Poll::Tick),
                Err(e) => return Err(e),
            }
        }
    }

    /// Decoded bytes available now, or None if more input is needed (or the body ended).
    fn decode(&mut self) -> io::Result<Option<Vec<u8>>> {
        if !self.chunked {
            return Ok(if self.raw.is_empty() { None } else { Some(std::mem::take(&mut self.raw)) });
        }
        let mut out = Vec::new();
        loop {
            match self.st {
                ChunkSt::Size => {
                    let Some(eol) = self.raw.windows(2).position(|w| w == b"\r\n") else {
                        if self.raw.len() > 64 {
                            return Err(bad("chunk header"));
                        }
                        break;
                    };
                    let size_s = std::str::from_utf8(&self.raw[..eol]).map_err(|_| bad("chunk size"))?;
                    let size = usize::from_str_radix(size_s.split(';').next().unwrap_or("").trim(), 16).map_err(|_| bad("chunk size"))?;
                    if size > MAX_CHUNK {
                        return Err(bad("chunk too large"));
                    }
                    self.raw.drain(..eol + 2);
                    self.st = if size == 0 { ChunkSt::Done } else { ChunkSt::Data(size) };
                }
                ChunkSt::Data(n) => {
                    if self.raw.is_empty() {
                        break;
                    }
                    let k = n.min(self.raw.len());
                    out.extend(self.raw.drain(..k));
                    self.st = if k == n { ChunkSt::DataEnd } else { ChunkSt::Data(n - k) };
                }
                ChunkSt::DataEnd => {
                    if self.raw.len() < 2 {
                        break;
                    }
                    if &self.raw[..2] != b"\r\n" {
                        return Err(bad("chunk terminator"));
                    }
                    self.raw.drain(..2);
                    self.st = ChunkSt::Size;
                }
                ChunkSt::Done => {
                    self.ended = true;
                    break;
                }
            }
        }
        Ok(if out.is_empty() { None } else { Some(out) })
    }
}

fn bad(m: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, m.to_string())
}

pub fn parse_response(raw: &[u8]) -> io::Result<(u16, Vec<u8>)> {
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").ok_or_else(|| bad("no header end"))?;
    let head = std::str::from_utf8(&raw[..split]).map_err(|_| bad("header not utf8"))?;
    let body = &raw[split + 4..];
    let mut lines = head.split("\r\n");
    let status: u16 = lines.next().and_then(|l| l.split(' ').nth(1)).and_then(|c| c.parse().ok()).ok_or_else(|| bad("bad status line"))?;
    let mut chunked = false;
    let mut len: Option<usize> = None;
    for l in lines {
        let low = l.to_ascii_lowercase();
        if low.starts_with("transfer-encoding:") && low.contains("chunked") {
            chunked = true;
        }
        if let Some(v) = low.strip_prefix("content-length:") {
            len = v.trim().parse().ok();
        }
    }
    if chunked {
        return Ok((status, dechunk(body)?));
    }
    let n = len.unwrap_or(body.len()).min(body.len());
    Ok((status, body[..n].to_vec()))
}

fn dechunk(mut b: &[u8]) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let eol = b.windows(2).position(|w| w == b"\r\n").ok_or_else(|| bad("chunk header"))?;
        let size_s = std::str::from_utf8(&b[..eol]).map_err(|_| bad("chunk size"))?;
        let size = usize::from_str_radix(size_s.split(';').next().unwrap_or("").trim(), 16).map_err(|_| bad("chunk size"))?;
        b = &b[eol + 2..];
        if size == 0 {
            return Ok(out);
        }
        if b.len() < size + 2 {
            return Err(bad("short chunk"));
        }
        out.extend_from_slice(&b[..size]);
        b = &b[size + 2..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowed_classes() {
        for ok in ["127.0.0.1:1", "10.1.2.3:1", "172.16.0.1:1", "172.31.255.1:1", "192.168.1.5:1", "[::1]:1"] {
            assert!(parse_addr(ok).is_ok(), "{ok}");
        }
    }

    #[test]
    fn refused_classes() {
        for bad in [
            "8.8.8.8:53", "172.15.0.1:1", "172.32.0.1:1", "192.169.0.1:1", "11.0.0.1:1", "169.254.1.1:1",
            "100.64.0.1:1", "0.0.0.0:1", "[::]:1", "[fe80::1]:1", "[fd00::1]:1", "[::ffff:8.8.8.8]:1",
            "localhost:80", "example.com:80", "127.0.0.1", "",
        ] {
            assert!(parse_addr(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn loopback_rule_is_stricter() {
        assert!(parse_loopback("127.0.0.1:9").is_ok());
        assert!(parse_loopback("192.168.1.2:9").is_err());
    }

    #[test]
    fn connect_and_listen_recheck() {
        let a: SocketAddr = "8.8.8.8:53".parse().unwrap();
        assert_eq!(connect(&a, Duration::from_millis(50)).unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(listen(&a).unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        let any: SocketAddr = "0.0.0.0:0".parse().unwrap();
        assert!(listen(&any).is_err());
    }

    #[test]
    fn chunked_and_plain() {
        let (c, b) = parse_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n").unwrap();
        assert_eq!((c, b.as_slice()), (200, &b"abcde"[..]));
        let (c, b) = parse_response(b"HTTP/1.1 403 X\r\nContent-Length: 2\r\n\r\nokEXTRA").unwrap();
        assert_eq!((c, b.as_slice()), (403, &b"ok"[..]));
        assert!(parse_response(b"garbage").is_err());
    }
}

#[cfg(all(test, target_os = "linux"))]
mod send_timeout_tests {
    use super::*;
    use std::os::fd::AsRawFd;

    fn get_sndtimeo(s: &impl AsRawFd) -> (i64, i64) {
        #[repr(C)]
        struct Timeval {
            sec: i64,
            usec: i64,
        }
        unsafe extern "C" {
            fn getsockopt(fd: i32, level: i32, name: i32, val: *mut Timeval, len: *mut u32) -> i32;
        }
        let mut tv = Timeval { sec: -1, usec: -1 };
        let mut len = std::mem::size_of::<Timeval>() as u32;
        // SAFETY: a valid descriptor, and pointers to live values of the stated size.
        assert_eq!(unsafe { getsockopt(s.as_raw_fd(), 1, 21, &mut tv, &mut len) }, 0);
        (tv.sec, tv.usec)
    }

    #[test]
    fn a_listener_send_timeout_reaches_the_connections_it_accepts() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let c = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (before, _) = l.accept().unwrap();
        assert_eq!(get_sndtimeo(&before), (0, 0));
        drop((c, before));
        set_send_timeout(&l, Duration::from_millis(2500)).unwrap();
        let c = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (after, _) = l.accept().unwrap();
        assert_eq!(get_sndtimeo(&after), (2, 500_000));
        drop(c);
    }

    // ---- the writer side ----
    use std::sync::mpsc::sync_channel;
    use std::time::Instant;

    /// A client that never reads: the writer must give up inside the send timeout, not hang.
    fn stalled_writer_ends(set_timeout: bool) -> Option<Duration> {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (mut server, _) = l.accept().unwrap();
        if set_timeout {
            set_send_timeout(&server, Duration::from_secs(1)).unwrap();
        }
        let (tx, rx) = sync_channel::<Vec<u8>>(32);
        let feeder = std::thread::spawn(move || {
            for _ in 0..64 {
                if tx.send(vec![b'x'; 1 << 20]).is_err() {
                    return;
                }
            }
        });
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let t0 = Instant::now();
        std::thread::spawn(move || {
            let r = crate::daemon::write_events(&mut server, &rx);
            let _ = done_tx.send(r.is_err());
        });
        let out = match done_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(errored) => {
                assert!(errored, "the writer finished without an error against a client that never read");
                Some(t0.elapsed())
            }
            Err(_) => None,
        };
        drop(client); // lets a stuck writer (the falsified case) finish
        let _ = feeder.join();
        out
    }

    #[test]
    fn f3_a_writer_blocked_on_a_client_that_never_reads_is_cut_off_by_the_send_timeout() {
        let took = stalled_writer_ends(true).expect("the writer was still blocked after 5 s");
        println!("F3: writer ended {took:?} after start (send timeout 1 s)");
        assert!(took < Duration::from_secs(6), "{took:?}");
    }

    #[test]
    fn f3_without_the_send_timeout_the_same_writer_stays_blocked() {
        // The control: proves the test above measures the timeout and not something else.
        assert!(stalled_writer_ends(false).is_none(), "the writer ended with no send timeout set");
    }
}

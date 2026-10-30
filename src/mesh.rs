//! Sealed messaging between boxes on one LAN, with a static peer list. One TCP connection carries
//! one arrowmem-core sealed object (exactly OBJECT_SIZE bytes) and gets a one byte answer.
//! Sealing, opening and the replay window are arrowmem-core's. A sender whose signing key is not
//! in the peer list is refused even if the object opens.

use crate::config::{Config, Peer};
use crate::keys::Identity;
use crate::vault::{Kind, Vault};
use crate::{hex, net};
use arrowmem_core::{Error as CoreError, OBJECT_SIZE, ReplayWindow, open, seal};
use hpke::Deserializable;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

/// The unwrapped identity, or None while the daemon is locked. Shared by the API and the listener.
pub type IdSlot = Arc<RwLock<Option<Arc<Identity>>>>;
use std::time::{Duration, Instant};

pub const ACK_OK: u8 = 1;
pub const ACK_REFUSED: u8 = 0;
const IO_TIMEOUT: Duration = Duration::from_secs(3);
/// Whole-connection budget for the receiving side: a peer that trickles bytes cannot hold a slot
/// longer than this, however it paces them.
pub const CONN_DEADLINE: Duration = Duration::from_secs(3);
/// At most this many connections are served at once. The next one is closed without an answer.
pub const MAX_CONNS: usize = 8;

#[derive(Debug, PartialEq, Eq)]
pub enum MeshError {
    Core(String),
    UnknownSender,
    Replay,
    Store(String),
}

/// Receiving side state: a replay window per peer, persisted under `<vault>/mesh/`.
pub struct Receiver {
    dir: PathBuf,
    windows: HashMap<[u8; 33], ReplayWindow>,
}

fn peer_file(dir: &std::path::Path, sign_pub: &[u8; 33]) -> PathBuf {
    dir.join(format!("replay-{}", hex::enc(&arrowmem_core::content_id(sign_pub)[..8])))
}

impl Receiver {
    pub fn new(vault_dir: &std::path::Path, peers: &[Peer]) -> Result<Receiver, String> {
        let dir = vault_dir.join("mesh");
        std::fs::create_dir_all(&dir).map_err(|e| format!("mesh dir: {}", e.kind()))?;
        crate::fsio::clear_stale_tmp(&dir); // a crash before the rename leaves the old file intact plus a .tmp
        let mut windows = HashMap::new();
        for p in peers {
            if let Ok(b) = std::fs::read(peer_file(&dir, &p.sign_pub)) {
                let a: [u8; 24] = b.try_into().map_err(|_| "replay file malformed".to_string())?;
                windows.insert(p.sign_pub, ReplayWindow::from_bytes(&a));
            }
        }
        Ok(Receiver { dir, windows })
    }

    /// Check one inbound object. On success the message is in the vault and the window is saved.
    pub fn accept(&mut self, obj: &[u8], id: &Identity, peers: &[Peer], vault: &mut Vault) -> Result<String, MeshError> {
        let v = open(obj, &id.seal_sk, &id.seal_pk).map_err(|e| MeshError::Core(format!("{e:?}")))?;
        let sp: [u8; 33] = v.sender().to_sec1_point(true).as_bytes().try_into().map_err(|_| MeshError::UnknownSender)?;
        let peer = peers.iter().find(|p| p.sign_pub == sp).ok_or(MeshError::UnknownSender)?;
        let mut w = match self.windows.get(&sp) {
            Some(w) => *w,
            None => ReplayWindow::starting_at(v.counter()), // a new peer's window starts at its first object
        };
        let first = !self.windows.contains_key(&sp);
        if !first {
            w.check_and_mark(v.counter()).map_err(|e| if e == CoreError::Replay { MeshError::Replay } else { MeshError::Core(format!("{e:?}")) })?;
        }
        let text = std::str::from_utf8(v.body()).map_err(|_| MeshError::Core("not utf8".into()))?;
        vault.append(id, Kind::PeerIn, &format!("peer-{}", peer.name), text).map_err(MeshError::Store)?;
        crate::fsio::write_atomic(&peer_file(&self.dir, &sp), &w.to_bytes()).map_err(|e| MeshError::Store(format!("{}", e.kind())))?;
        self.windows.insert(sp, w);
        Ok(peer.name.clone())
    }
}

/// Send counter: monotonic, saved BEFORE the object leaves, so a crash can skip a number but never reuse one.
pub struct Sender {
    file: PathBuf,
    next: u64,
}

impl Sender {
    pub fn new(vault_dir: &std::path::Path) -> Result<Sender, String> {
        let dir = vault_dir.join("mesh");
        std::fs::create_dir_all(&dir).map_err(|e| format!("mesh dir: {}", e.kind()))?;
        crate::fsio::clear_stale_tmp(&dir);
        let file = dir.join("send-counter");
        let next = match std::fs::read(&file) {
            Ok(b) => u64::from_be_bytes(b.try_into().map_err(|_| "send counter malformed".to_string())?),
            Err(_) => 1,
        };
        Ok(Sender { file, next })
    }

    pub fn send(&mut self, id: &Identity, peer: &Peer, text: &str) -> Result<(), String> {
        let counter = self.next;
        let obj = seal(&id.sign, &<arrowmem_core::SealPublicKey as Deserializable>::from_bytes(&peer.seal_pub).map_err(|_| "bad peer sealing key")?, counter, text.as_bytes())
            .map_err(|e| format!("seal: {e:?}"))?;
        crate::fsio::write_atomic(&self.file, &(counter + 1).to_be_bytes()).map_err(|e| format!("counter: {}", e.kind()))?;
        self.next += 1;
        let mut s = net::connect(&peer.addr, IO_TIMEOUT).map_err(|e| format!("connect: {}", e.kind()))?;
        s.write_all(&obj).map_err(|e| format!("send: {}", e.kind()))?;
        let mut ack = [0u8; 1];
        s.read_exact(&mut ack).map_err(|e| format!("no answer: {}", e.kind()))?;
        if ack[0] == ACK_OK { Ok(()) } else { Err("peer refused the object".into()) }
    }
}

/// True if a TCP connection to the peer opens. Sends nothing.
pub fn reachable(p: &Peer) -> bool {
    net::connect(&p.addr, Duration::from_millis(800)).is_ok()
}

/// One connection: read exactly one object under a total deadline, answer one byte.
fn serve_conn(mut s: std::net::TcpStream, rx: &Mutex<Receiver>, peers: &[Peer], id: &Identity, slot: &IdSlot, vault: &Mutex<Vault>, received: &AtomicU64) {
    let _ = s.set_nonblocking(false);
    let _ = s.set_write_timeout(Some(IO_TIMEOUT));
    let deadline = Instant::now() + CONN_DEADLINE;
    let mut buf = vec![0u8; OBJECT_SIZE]; // exactly one object; anything past it is never read
    let mut n = 0;
    while n < buf.len() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() || s.set_read_timeout(Some(left)).is_err() {
            break;
        }
        match s.read(&mut buf[n..]) {
            Ok(0) | Err(_) => break,
            Ok(k) => n += k,
        }
    }
    if n == 0 {
        return; // a reachability probe or a stalled peer: no answer owed
    }
    let ok = n == OBJECT_SIZE && {
        let mut r = rx.lock().unwrap_or_else(|e| e.into_inner());
        let mut vg = vault.lock().unwrap_or_else(|e| e.into_inner());
        // Re-read the slot under the vault mutex, which lock_now also takes: no write after a lock.
        slot.read().unwrap_or_else(|e| e.into_inner()).is_some() && r.accept(&buf[..n], id, peers, &mut vg).is_ok()
    };
    if ok {
        received.fetch_add(1, Ordering::Relaxed);
    }
    let _ = s.write_all(&[if ok { ACK_OK } else { ACK_REFUSED }]);
}

pub struct Listener {
    pub addr: std::net::SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Listener {
    pub fn start(cfg: &Config, id: IdSlot, vault: Arc<Mutex<Vault>>, received: Arc<AtomicU64>) -> Result<Listener, String> {
        let l: TcpListener = net::listen(&cfg.mesh_listen).map_err(|e| format!("mesh listen: {}", e.kind()))?;
        let addr = l.local_addr().map_err(|e| e.to_string())?;
        l.set_nonblocking(true).map_err(|e| e.to_string())?;
        let rx = Arc::new(Mutex::new(Receiver::new(&cfg.vault_dir, &cfg.peers)?));
        let peers = Arc::new(cfg.peers.clone());
        let stop = Arc::new(AtomicBool::new(false));
        let active = Arc::new(AtomicUsize::new(0));
        let (st, act) = (stop.clone(), active.clone());
        let handle = std::thread::spawn(move || {
            while !st.load(Ordering::SeqCst) {
                match l.accept() {
                    Ok((s, from)) => {
                        // Only an allowed source class may talk to us at all.
                        if !net::ip_allowed(from.ip()) {
                            continue;
                        }
                        // Bounded concurrency: over the cap the connection is closed unanswered.
                        if act.fetch_add(1, Ordering::SeqCst) >= MAX_CONNS {
                            act.fetch_sub(1, Ordering::SeqCst);
                            continue;
                        }
                        // Locked: close the connection unread and unanswered. Nothing is accepted without the key.
                        let Some(idv) = id.read().unwrap_or_else(|e| e.into_inner()).clone() else {
                            act.fetch_sub(1, Ordering::SeqCst);
                            continue;
                        };
                        let (rx, peers, id, slot, vault, act, received) = (rx.clone(), peers.clone(), idv, id.clone(), vault.clone(), act.clone(), received.clone());
                        std::thread::spawn(move || {
                            serve_conn(s, &rx, &peers, &id, &slot, &vault, &received);
                            act.fetch_sub(1, Ordering::SeqCst);
                        });
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(25)),
                }
            }
            // Stopping waits for in-flight connections; each ends within CONN_DEADLINE plus a write timeout.
            let until = Instant::now() + CONN_DEADLINE + IO_TIMEOUT + Duration::from_secs(1);
            while act.load(Ordering::SeqCst) > 0 && Instant::now() < until {
                std::thread::sleep(Duration::from_millis(10));
            }
        });
        Ok(Listener { addr, stop, handle: Some(handle) })
    }

    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer_for(name: &str, id: &Identity) -> Peer {
        Peer { name: name.into(), addr: "127.0.0.1:1".parse().unwrap(), sign_pub: id.sign_pub(), seal_pub: id.seal_pub() }
    }

    struct Rig {
        a: Identity,
        b: Identity,
        rx: Receiver,
        vault: Vault,
        peers: Vec<Peer>,
        send_dir: PathBuf,
    }

    fn rig(tag: &str) -> Rig {
        let (a, b) = (Identity::generate().unwrap(), Identity::generate().unwrap());
        let vdir = crate::testutil::tmp(tag);
        let peers = vec![peer_for("alice", &a)];
        Rig { rx: Receiver::new(&vdir, &peers).unwrap(), vault: Vault::open(vdir.join("v")).unwrap(), peers, send_dir: crate::testutil::tmp("snd"), a, b }
    }

    fn obj(r: &Rig, counter: u64, text: &str) -> Vec<u8> {
        seal(&r.a.sign, &r.b.seal_pk, counter, text.as_bytes()).unwrap()
    }

    #[test]
    fn accepts_known_sender_and_stores() {
        let mut r = rig("m1");
        let o = obj(&r, 5, "hi bob");
        assert_eq!(r.rx.accept(&o, &r.b, &r.peers, &mut r.vault).unwrap(), "alice");
        let e = r.vault.read(&r.b, "peer-alice").unwrap();
        assert_eq!(e[0].text, "hi bob");
    }

    #[test]
    fn replay_refused_and_survives_restart() {
        let mut r = rig("m2");
        let o1 = obj(&r, 5, "one");
        let o2 = obj(&r, 6, "two");
        r.rx.accept(&o1, &r.b, &r.peers, &mut r.vault).unwrap();
        r.rx.accept(&o2, &r.b, &r.peers, &mut r.vault).unwrap();
        assert_eq!(r.rx.accept(&o2, &r.b, &r.peers, &mut r.vault), Err(MeshError::Replay));
        // a fresh Receiver over the same directory still refuses it
        let dir = r.rx.dir.parent().unwrap().to_path_buf();
        let mut rx2 = Receiver::new(&dir, &r.peers).unwrap();
        assert_eq!(rx2.accept(&o2, &r.b, &r.peers, &mut r.vault), Err(MeshError::Replay));
        assert_eq!(r.vault.read(&r.b, "peer-alice").unwrap().len(), 2);
    }

    #[test]
    fn unknown_sender_refused_even_though_it_opens() {
        let mut r = rig("m3");
        let stranger = Identity::generate().unwrap();
        let o = seal(&stranger.sign, &r.b.seal_pk, 1, b"let me in").unwrap();
        assert_eq!(r.rx.accept(&o, &r.b, &r.peers, &mut r.vault), Err(MeshError::UnknownSender));
        assert_eq!(r.vault.record_count(), 0);
    }

    #[test]
    fn wrong_recipient_and_tamper_refused() {
        let mut r = rig("m4");
        let c = Identity::generate().unwrap();
        let o = seal(&r.a.sign, &c.seal_pk, 1, b"x").unwrap();
        assert!(matches!(r.rx.accept(&o, &r.b, &r.peers, &mut r.vault), Err(MeshError::Core(_))));
        let mut o2 = obj(&r, 2, "y");
        o2[700] ^= 1;
        assert!(matches!(r.rx.accept(&o2, &r.b, &r.peers, &mut r.vault), Err(MeshError::Core(_))));
        assert_eq!(r.vault.record_count(), 0);
    }

    #[test]
    fn send_counter_persists_and_never_repeats() {
        let r = rig("m5");
        let mut s = Sender::new(&r.send_dir).unwrap();
        let mut dead = peer_for("bob", &r.b);
        dead.addr = "127.0.0.1:1".parse().unwrap();
        assert!(s.send(&r.a, &dead, "x").is_err()); // nothing listens, but a number was spent
        let s2 = Sender::new(&r.send_dir).unwrap();
        assert_eq!(s2.next, 2);
    }

    #[test]
    fn crash_before_rename_leaves_old_state_and_is_cleaned_up() {
        let mut r = rig("m6");
        let (o1, o2) = (obj(&r, 5, "one"), obj(&r, 6, "two"));
        r.rx.accept(&o1, &r.b, &r.peers, &mut r.vault).unwrap();
        let dir = r.rx.dir.parent().unwrap().to_path_buf();
        // Simulated torn write: the crash happened while writing the new state to the .tmp file.
        let pf = peer_file(&dir.join("mesh"), &r.peers[0].sign_pub);
        let mut tmp = pf.as_os_str().to_owned();
        tmp.push(".tmp");
        std::fs::write(&tmp, [1u8, 2, 3]).unwrap();
        let mut sc = dir.join("mesh").join("send-counter").as_os_str().to_owned();
        sc.push(".tmp");
        std::fs::write(&sc, [9u8]).unwrap();
        let mut rx2 = Receiver::new(&dir, &r.peers).unwrap(); // starts, does not refuse
        assert!(!std::path::Path::new(&tmp).exists());
        assert_eq!(rx2.accept(&o1, &r.b, &r.peers, &mut r.vault), Err(MeshError::Replay)); // old window intact
        assert!(rx2.accept(&o2, &r.b, &r.peers, &mut r.vault).is_ok());
        Sender::new(&dir).unwrap();
        assert!(!std::path::Path::new(&sc).exists());
    }

    #[test]
    fn a_torn_final_file_is_refused_not_trusted() {
        let mut r = rig("m7");
        let o1 = obj(&r, 5, "one");
        r.rx.accept(&o1, &r.b, &r.peers, &mut r.vault).unwrap();
        let dir = r.rx.dir.parent().unwrap().to_path_buf();
        let pf = peer_file(&dir.join("mesh"), &r.peers[0].sign_pub);
        let b = std::fs::read(&pf).unwrap();
        std::fs::write(&pf, &b[..10]).unwrap(); // a file torn by an old non-atomic writer
        assert!(Receiver::new(&dir, &r.peers).is_err());
        let sc = dir.join("mesh").join("send-counter");
        std::fs::write(&sc, [0u8, 0, 1]).unwrap();
        assert!(Sender::new(&dir).is_err());
    }

    #[test]
    fn write_uses_tmp_fsync_rename_not_in_place_truncate() {
        // Source-level guard: no plain fs::write of the state files remains in this module's code.
        let src = include_str!("mesh.rs");
        let code = src.split("#[cfg(test)]").next().unwrap();
        assert!(!code.contains("std::fs::write("));
        assert!(code.matches("write_atomic(").count() >= 2);
    }
}

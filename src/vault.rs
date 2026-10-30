//! The vault: one sealed object per record, using arrowmem-core `seal` and `open`. Each record is
//! sealed to the box's own sealing key and signed by its own signing key, so a record on disk is
//! 1114 bytes of ciphertext, and a flipped bit is refused on open. A message longer than one
//! body (885 bytes) is split into chunks.
//!
//! Record body: kind(1) msg_id(8) chunk_idx(2) chunk_total(2) name_len(1) name text.
//! Limits stated plainly: file names show how many records exist and in what order. `read` checks
//! the numbering and message continuity (see `Vault::read`).
//!
//! Head record: `<vault>/head` is one arrowmem-core sealed object (sealed to and signed by the
//! box, counter = the last record number) whose body is 0xFF, the last record number (8 bytes
//! big endian) and a chain value. chain(0) is 32 zero bytes and
//! chain(k) = content_id(chain(k-1) || content_id(record k)), with arrowmem-core's `content_id`.
//! `append` rewrites it after every record. A read or an append refuses a vault that holds fewer
//! records than the head says (deleted from the end), whose chain at the head's number differs
//! (a record changed, swapped or reordered up to there), or that has records but no head. Records
//! past the head are accepted: a crash between a record's rename and the head's rename leaves
//! exactly that, and the next append re-seals the head over them. Not detected: restoring an old
//! head together with the matching old records (a whole-vault rollback), and wiping the whole vault.

use crate::config::valid_name;
use crate::keys::Identity;
use arrowmem_core::{MAX_BODY, OBJECT_SIZE, content_id, open, seal};
use std::fs;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::io::Write;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    User = 0,
    Assistant = 1,
    PeerIn = 2,
    PeerOut = 3,
}

impl Kind {
    fn from(b: u8) -> Option<Kind> {
        Some(match b {
            0 => Kind::User,
            1 => Kind::Assistant,
            2 => Kind::PeerIn,
            3 => Kind::PeerOut,
            _ => return None,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Entry {
    pub kind: Kind,
    pub msg_id: u64,
    pub text: String,
}

pub struct Vault {
    dir: PathBuf,
    next: u64,
    /// (record count, chain value) as last verified or written by this process.
    state: Option<(u64, [u8; 32])>,
}

/// First body byte of the head record. No record can carry it: `Kind::from(0xFF)` is None.
const HEAD_MARK: u8 = 0xFF;
const ZERO_CHAIN: [u8; 32] = [0; 32];

fn chain_step(prev: &[u8; 32], obj: &[u8]) -> [u8; 32] {
    let mut b = Vec::with_capacity(64);
    b.extend_from_slice(prev);
    b.extend_from_slice(&content_id(obj));
    content_id(&b)
}

const HEAD: usize = 1 + 8 + 2 + 2 + 1;

impl Vault {
    pub fn open(dir: PathBuf) -> Result<Vault, String> {
        fs::create_dir_all(dir.join("r")).map_err(|e| format!("vault dir: {}", e.kind()))?;
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
        crate::fsio::clear_stale_tmp(&dir.join("r")); // a crash between create and rename would block that number forever
        let mut max = 0u64;
        for e in fs::read_dir(dir.join("r")).map_err(|e| format!("vault dir: {}", e.kind()))?.flatten() {
            if let Some(n) = e.file_name().to_str().and_then(|s| s.strip_suffix(".obj")).and_then(|s| u64::from_str_radix(s, 16).ok()) {
                max = max.max(n);
            }
        }
        let _ = fs::remove_file(dir.join("head.tmp"));
        Ok(Vault { dir, next: max + 1, state: None })
    }

    pub fn dir(&self) -> &std::path::Path {
        &self.dir
    }

    pub fn record_count(&self) -> usize {
        fs::read_dir(self.dir.join("r")).map(|d| d.flatten().filter(|e| e.file_name().to_string_lossy().ends_with(".obj")).count()).unwrap_or(0)
    }

    /// Append one message under a conversation name. Returns the message id.
    pub fn append(&mut self, id: &Identity, kind: Kind, conv: &str, text: &str) -> Result<u64, String> {
        if !valid_name(conv) {
            return Err("bad conversation name".into());
        }
        let per = MAX_BODY - HEAD - conv.len();
        let chunks: Vec<&[u8]> = if text.is_empty() { vec![&[][..]] } else { text.as_bytes().chunks(per).collect() };
        if chunks.len() > u16::MAX as usize {
            return Err("message too long".into());
        }
        let (mut count, mut chain) = match self.state {
            Some(s) if s.0 == self.record_count() as u64 => s,
            _ => self.chain_state(id)?,
        };
        let msg_id = self.next;
        for (i, c) in chunks.iter().enumerate() {
            let mut body = Vec::with_capacity(MAX_BODY);
            body.push(kind as u8);
            body.extend_from_slice(&msg_id.to_be_bytes());
            body.extend_from_slice(&(i as u16).to_be_bytes());
            body.extend_from_slice(&(chunks.len() as u16).to_be_bytes());
            body.push(conv.len() as u8);
            body.extend_from_slice(conv.as_bytes());
            body.extend_from_slice(c);
            let counter = self.next;
            let obj = seal(&id.sign, &id.seal_pk, counter, &body).map_err(|e| format!("seal: {e:?}"))?;
            debug_assert_eq!(obj.len(), OBJECT_SIZE);
            let tmp = self.dir.join(format!("r/{counter:016x}.tmp"));
            let fin = self.dir.join(format!("r/{counter:016x}.obj"));
            {
                let mut f = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp).map_err(|e| format!("write: {}", e.kind()))?;
                f.write_all(&obj).and_then(|_| f.sync_all()).map_err(|e| format!("write: {}", e.kind()))?;
            }
            fs::rename(&tmp, &fin).map_err(|e| format!("write: {}", e.kind()))?;
            self.next += 1;
            count += 1;
            chain = chain_step(&chain, &obj);
            self.write_head(id, count, &chain)?;
            self.state = Some((count, chain));
        }
        Ok(msg_id)
    }

    fn write_head(&self, id: &Identity, last: u64, chain: &[u8; 32]) -> Result<(), String> {
        let mut body = Vec::with_capacity(41);
        body.push(HEAD_MARK);
        body.extend_from_slice(&last.to_be_bytes());
        body.extend_from_slice(chain);
        let obj = seal(&id.sign, &id.seal_pk, last, &body).map_err(|e| format!("seal head: {e:?}"))?;
        crate::fsio::write_atomic(&self.dir.join("head"), &obj).map_err(|e| format!("head: {}", e.kind()))
    }

    /// Check the sealed head against the record files and return (record count, chain value) over
    /// all of them. Errors: no head but records exist; head does not open, is not this box's, or
    /// is malformed; fewer records than the head's number; chain mismatch at the head's number;
    /// a gap in the numbering.
    pub fn chain_state(&self, id: &Identity) -> Result<(u64, [u8; 32]), String> {
        let files = self.numbered_files()?;
        let head = match fs::read(self.dir.join("head")) {
            Ok(obj) => {
                let v = open(&obj, &id.seal_sk, &id.seal_pk).map_err(|e| format!("head record refused: {e:?}"))?;
                if v.sender() != id.sign.verifying_key() {
                    return Err("head record signed by another key".into());
                }
                let b = v.body();
                if b.len() != 41 || b[0] != HEAD_MARK {
                    return Err("head record malformed".into());
                }
                let last = u64::from_be_bytes(b[1..9].try_into().unwrap());
                if v.counter() != last {
                    return Err("head record number does not match its sealed counter".into());
                }
                let mut c = [0u8; 32];
                c.copy_from_slice(&b[9..]);
                Some((last, c))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(format!("head: {}", e.kind())),
        };
        let Some((last, want)) = head else {
            return if files.is_empty() { Ok((0, ZERO_CHAIN)) } else { Err("head record missing but records exist".into()) };
        };
        if (files.len() as u64) < last {
            return Err("records missing from the end of the vault".into());
        }
        let mut chain = ZERO_CHAIN;
        if last == 0 && want != ZERO_CHAIN {
            return Err("head record chain mismatch".into());
        }
        for (i, (n, p)) in files.iter().enumerate() {
            if *n != i as u64 + 1 {
                return Err("record missing or out of sequence".into());
            }
            let obj = fs::read(p).map_err(|e| format!("read: {}", e.kind()))?;
            chain = chain_step(&chain, &obj);
            if *n == last && chain != want {
                return Err("head record chain mismatch".into());
            }
        }
        Ok((files.len() as u64, chain))
    }

    /// Every record file in order, with its number from the file name. The name must be the
    /// canonical 16 hex digits, so two names cannot stand for one number.
    fn numbered_files(&self) -> Result<Vec<(u64, PathBuf)>, String> {
        let mut files = Vec::new();
        for e in fs::read_dir(self.dir.join("r")).map_err(|e| format!("vault dir: {}", e.kind()))?.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if !name.ends_with(".obj") {
                continue;
            }
            let n = name.strip_suffix(".obj").and_then(|s| u64::from_str_radix(s, 16).ok()).filter(|n| name == format!("{n:016x}.obj"));
            files.push((n.ok_or("record file name is not a record number")?, e.path()));
        }
        files.sort();
        Ok(files)
    }

    /// Read one conversation, oldest first. The whole vault is checked on every read, not only the
    /// conversation asked for: any record that fails to open, or was not signed by this box's own
    /// key, is an error, and so is any of these (the sealed counter is signed, the file name is not):
    ///  - a file whose name differs from the counter sealed inside it (copy, rename, reorder, swap);
    ///  - a gap in the numbering, or numbering that does not start at 1 (a deleted record);
    ///  - chunks that do not continue one message: same msg_id, kind, total and conversation, idx up by one.
    ///
    /// Records deleted from the END are caught by the sealed head record (see `chain_state`).
    pub fn read(&self, id: &Identity, conv: &str) -> Result<Vec<Entry>, String> {
        Ok(self.read_all(id)?.into_iter().filter(|(c, _)| c == conv).map(|(_, e)| e).collect())
    }

    /// Every message in the vault, oldest first, each with its conversation name. Same checks as `read`.
    pub fn read_all(&self, id: &Identity) -> Result<Vec<(String, Entry)>, String> {
        struct Pending {
            kind: Kind,
            msg_id: u64,
            total: u16,
            next_idx: u16,
            name: Vec<u8>,
            parts: Vec<u8>,
        }
        self.chain_state(id)?;
        let me = id.sign.verifying_key();
        let mut out: Vec<(String, Entry)> = Vec::new();
        let mut pending: Option<Pending> = None;
        for (i, (n, p)) in self.numbered_files()?.into_iter().enumerate() {
            if n != i as u64 + 1 {
                return Err("record missing or out of sequence".into());
            }
            let obj = fs::read(&p).map_err(|e| format!("read: {}", e.kind()))?;
            let v = open(&obj, &id.seal_sk, &id.seal_pk).map_err(|e| format!("record refused: {e:?}"))?;
            if v.sender() != me {
                return Err("record signed by another key".into());
            }
            if v.counter() != n {
                return Err("record number does not match its sealed counter".into());
            }
            let b = v.body();
            if b.len() < HEAD {
                return Err("record malformed".into());
            }
            let kind = Kind::from(b[0]).ok_or("record malformed")?;
            let msg_id = u64::from_be_bytes(b[1..9].try_into().unwrap());
            let idx = u16::from_be_bytes([b[9], b[10]]);
            let total = u16::from_be_bytes([b[11], b[12]]);
            let nl = b[13] as usize;
            if b.len() < HEAD + nl || total == 0 || idx >= total {
                return Err("record malformed".into());
            }
            let name = b[HEAD..HEAD + nl].to_vec();
            let chunk = &b[HEAD + nl..];
            match pending.as_mut() {
                Some(pd) if idx != 0 => {
                    if (pd.msg_id, pd.total, pd.next_idx, pd.kind) != (msg_id, total, idx, kind) || pd.name != name {
                        return Err("message chunks out of order or spliced".into());
                    }
                    pd.parts.extend_from_slice(chunk);
                    pd.next_idx += 1;
                }
                _ => {
                    // A new message. A half-written one left by a crash is dropped here, but only
                    // when this record starts at its own number, as append always does.
                    if idx != 0 || msg_id != n {
                        return Err("record does not start a message in sequence".into());
                    }
                    pending = Some(Pending { kind, msg_id, total, next_idx: 1, name, parts: chunk.to_vec() });
                }
            }
            if pending.as_ref().is_some_and(|pd| pd.next_idx == pd.total) {
                let pd = pending.take().unwrap();
                let text = String::from_utf8(pd.parts).map_err(|_| "record not utf8")?;
                let name = String::from_utf8(pd.name).map_err(|_| "record malformed")?;
                out.push((name, Entry { kind: pd.kind, msg_id: pd.msg_id, text }));
            }
        }
        Ok(out)
    }
}

impl Vault {
    /// Unlocked means: the oldest record, if any, opens under this identity.
    pub fn probe(&self, id: &Identity) -> Result<(), String> {
        let mut files: Vec<_> = fs::read_dir(self.dir.join("r"))
            .map_err(|e| format!("vault dir: {}", e.kind()))?
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".obj"))
            .map(|e| e.path())
            .collect();
        files.sort();
        match files.first() {
            None => Ok(()),
            Some(p) => {
                let obj = fs::read(p).map_err(|e| format!("read: {}", e.kind()))?;
                open(&obj, &id.seal_sk, &id.seal_pk).map(|_| ()).map_err(|e| format!("{e:?}"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup(tag: &str) -> (Vault, Identity) {
        (Vault::open(crate::testutil::tmp(tag)).unwrap(), Identity::generate().unwrap())
    }

    #[test]
    fn round_trip_in_order() {
        let (mut v, id) = setup("v1");
        v.append(&id, Kind::User, "c1", "hello").unwrap();
        v.append(&id, Kind::Assistant, "c1", "hi there").unwrap();
        v.append(&id, Kind::User, "other", "elsewhere").unwrap();
        let e = v.read(&id, "c1").unwrap();
        assert_eq!(e.len(), 2);
        assert_eq!((e[0].kind, e[0].text.as_str()), (Kind::User, "hello"));
        assert_eq!((e[1].kind, e[1].text.as_str()), (Kind::Assistant, "hi there"));
        assert_eq!(v.record_count(), 3);
    }

    #[test]
    fn long_message_is_chunked_and_rejoined() {
        let (mut v, id) = setup("v2");
        let long = "x".repeat(MAX_BODY * 3 + 17);
        v.append(&id, Kind::PeerIn, "c", &long).unwrap();
        assert!(v.record_count() >= 4);
        assert_eq!(v.read(&id, "c").unwrap()[0].text, long);
    }

    #[test]
    fn plaintext_is_not_on_disk_and_files_are_fixed_size() {
        let (mut v, id) = setup("v3");
        v.append(&id, Kind::User, "c", "needle-in-a-haystack").unwrap();
        for e in fs::read_dir(v.dir().join("r")).unwrap().flatten() {
            let b = fs::read(e.path()).unwrap();
            assert_eq!(b.len(), OBJECT_SIZE);
            assert!(!b.windows(6).any(|w| w == b"needle"));
        }
    }

    #[test]
    fn tamper_is_refused_not_skipped() {
        let (mut v, id) = setup("v4");
        v.append(&id, Kind::User, "c", "hello").unwrap();
        let p = v.dir().join("r/0000000000000001.obj");
        let mut b = fs::read(&p).unwrap();
        b[500] ^= 1;
        fs::write(&p, b).unwrap();
        assert!(v.read(&id, "c").is_err());
    }

    #[test]
    fn other_key_cannot_read() {
        let (mut v, id) = setup("v5");
        v.append(&id, Kind::User, "c", "hello").unwrap();
        let other = Identity::generate().unwrap();
        assert!(v.read(&other, "c").is_err());
    }

    #[test]
    fn counter_resumes_after_reopen() {
        let (mut v, id) = setup("v6");
        v.append(&id, Kind::User, "c", "a").unwrap();
        let dir = v.dir().to_path_buf();
        let mut v2 = Vault::open(dir).unwrap();
        let m = v2.append(&id, Kind::User, "c", "b").unwrap();
        assert_eq!(m, 2);
        assert_eq!(v2.read(&id, "c").unwrap().len(), 2);
    }

    #[test]
    fn bad_names_refused() {
        let (mut v, id) = setup("v7");
        assert!(v.append(&id, Kind::User, "../x", "a").is_err());
        assert!(v.append(&id, Kind::User, "", "a").is_err());
    }

    fn rec(v: &Vault, n: u64) -> PathBuf {
        v.dir().join(format!("r/{n:016x}.obj"))
    }

    fn three_msgs() -> (Vault, Identity) {
        let (mut v, id) = setup("m3");
        v.append(&id, Kind::User, "c", "first").unwrap(); // 1
        v.append(&id, Kind::User, "c", "second").unwrap(); // 2
        v.append(&id, Kind::User, "c", "third").unwrap(); // 3
        assert_eq!(v.read(&id, "c").unwrap().len(), 3);
        (v, id)
    }

    #[test]
    fn m3_deleting_a_middle_or_first_record_is_refused() {
        let (v, id) = three_msgs();
        fs::remove_file(rec(&v, 2)).unwrap();
        assert!(v.read(&id, "c").is_err());
        let (v, id) = three_msgs();
        fs::remove_file(rec(&v, 1)).unwrap();
        assert!(v.read(&id, "c").is_err());
    }

    #[test]
    fn m3_reordering_is_refused() {
        let (v, id) = three_msgs();
        let (a, b) = (fs::read(rec(&v, 1)).unwrap(), fs::read(rec(&v, 2)).unwrap());
        fs::write(rec(&v, 1), b).unwrap();
        fs::write(rec(&v, 2), a).unwrap();
        assert!(v.read(&id, "c").is_err());
    }

    #[test]
    fn m3_duplicating_a_record_to_a_new_number_is_refused() {
        let (v, id) = three_msgs();
        fs::copy(rec(&v, 2), rec(&v, 4)).unwrap();
        assert!(v.read(&id, "c").is_err());
    }

    #[test]
    fn m3_splicing_chunks_between_two_long_messages_is_refused() {
        let (mut v, id) = setup("m3splice");
        let long1 = "a".repeat(MAX_BODY * 2); // records 1..=3
        v.append(&id, Kind::User, "c", &long1).unwrap();
        let first_after = v.record_count() as u64 + 1;
        let long2 = "b".repeat(MAX_BODY * 2);
        v.append(&id, Kind::User, "c", &long2).unwrap();
        assert_eq!(v.read(&id, "c").unwrap().len(), 2);
        // swap the matching middle chunk of each message
        let (m1, m2) = (2u64, first_after + 1);
        let (a, b) = (fs::read(rec(&v, m1)).unwrap(), fs::read(rec(&v, m2)).unwrap());
        fs::write(rec(&v, m1), b).unwrap();
        fs::write(rec(&v, m2), a).unwrap();
        assert!(v.read(&id, "c").is_err());
    }

    #[test]
    fn m3_a_forged_continuity_with_valid_counters_is_still_caught() {
        // Records re-sealed by the box's own key with the right counters but a chunk from another message
        // (what an attacker holding the key could do) fail the msg_id/idx check, independent of counters.
        let (mut v, id) = setup("m3forge");
        v.append(&id, Kind::User, "c", &"a".repeat(MAX_BODY * 2)).unwrap(); // 1..=3
        let mut body = Vec::new();
        body.push(Kind::User as u8);
        body.extend_from_slice(&999u64.to_be_bytes()); // wrong msg_id
        body.extend_from_slice(&1u16.to_be_bytes());
        body.extend_from_slice(&3u16.to_be_bytes());
        body.push(1);
        body.extend_from_slice(b"c");
        body.extend_from_slice(b"x");
        let obj = seal(&id.sign, &id.seal_pk, 2, &body).unwrap();
        fs::write(rec(&v, 2), obj).unwrap();
        assert!(v.read(&id, "c").is_err());
    }

    #[test]
    fn m3_a_half_written_message_from_a_crash_is_dropped_not_fatal() {
        let (mut v, id) = setup("m3torn");
        v.append(&id, Kind::User, "c", "ok").unwrap(); // 1
        v.append(&id, Kind::User, "c", &"a".repeat(MAX_BODY * 2)).unwrap(); // 2..=4
        // The crash: chunk 4 never landed, so the head still describes records 1..=3.
        fs::remove_file(rec(&v, 4)).unwrap();
        let mut chain = ZERO_CHAIN;
        for n in 1..=3 {
            chain = chain_step(&chain, &fs::read(rec(&v, n)).unwrap());
        }
        v.write_head(&id, 3, &chain).unwrap();
        let mut v2 = Vault::open(v.dir().to_path_buf()).unwrap();
        v2.append(&id, Kind::User, "c", "after").unwrap(); // 4
        let e = v2.read(&id, "c").unwrap();
        assert_eq!(e.iter().map(|x| x.text.as_str()).collect::<Vec<_>>(), ["ok", "after"]);
    }

    fn head_path(v: &Vault) -> PathBuf {
        v.dir().join("head")
    }

    #[test]
    fn head_tail_deletion_is_refused() {
        // Delete from the END, one record and then several: the case m3 could not see.
        let (v, id) = three_msgs();
        fs::remove_file(rec(&v, 3)).unwrap();
        let e = v.read(&id, "c").err().unwrap();
        assert!(e.contains("missing from the end"), "{e}");
        fs::remove_file(rec(&v, 2)).unwrap();
        assert!(v.read(&id, "c").is_err());
        // And a vault in that state refuses to append, so a later write cannot launder the loss.
        let mut v2 = Vault::open(v.dir().to_path_buf()).unwrap();
        assert!(v2.append(&id, Kind::User, "c", "new").is_err());
        // An open vault that already cached its state notices a tail deletion at the next append too.
        let (mut v, id) = three_msgs();
        fs::remove_file(rec(&v, 3)).unwrap();
        assert!(v.append(&id, Kind::User, "c", "new").is_err());
    }

    #[test]
    fn head_missing_with_records_is_refused_and_empty_vault_is_fine() {
        let (v, id) = three_msgs();
        fs::remove_file(head_path(&v)).unwrap();
        assert!(v.read(&id, "c").err().unwrap().contains("head record missing"));
        let (v, id) = setup("headempty");
        assert_eq!(v.read(&id, "c").unwrap().len(), 0);
    }

    #[test]
    fn head_chain_detects_a_swapped_record_even_if_numbers_and_signatures_hold() {
        // Replace record 2 with another validly sealed record at counter 2 (the box's own key):
        // every per-record check passes except the head's chain.
        let (v, id) = three_msgs();
        let mut body = vec![0u8, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 1, 1];
        body.push(b'c');
        body.extend_from_slice(b"forged");
        fs::write(rec(&v, 2), seal(&id.sign, &id.seal_pk, 2, &body).unwrap()).unwrap();
        let e = v.read(&id, "c").err().unwrap();
        assert!(e.contains("chain mismatch"), "{e}");
    }

    #[test]
    fn head_is_sealed_tamper_and_another_boxes_head_are_refused() {
        let (v, id) = three_msgs();
        let mut h = fs::read(head_path(&v)).unwrap();
        h[500] ^= 1;
        fs::write(head_path(&v), &h).unwrap();
        assert!(v.read(&id, "c").is_err());
        // A head sealed by a different identity.
        let (v, id) = three_msgs();
        let other = Identity::generate().unwrap();
        v.write_head(&other, 3, &ZERO_CHAIN).unwrap();
        assert!(v.read(&id, "c").is_err());
        // A record copied over the head's place (wrong body mark) is refused.
        let (v, id) = three_msgs();
        fs::copy(rec(&v, 3), head_path(&v)).unwrap();
        assert!(v.read(&id, "c").err().unwrap().contains("head record malformed"));
    }

    #[test]
    fn head_rolling_forward_after_a_crash_between_record_and_head_is_accepted() {
        let (mut v, id) = three_msgs();
        // Crash after record 4 landed but before its head: put the head back at 3.
        v.append(&id, Kind::User, "c", "fourth").unwrap();
        let mut chain = ZERO_CHAIN;
        for n in 1..=3 {
            chain = chain_step(&chain, &fs::read(rec(&v, n)).unwrap());
        }
        v.write_head(&id, 3, &chain).unwrap();
        let mut v2 = Vault::open(v.dir().to_path_buf()).unwrap();
        assert_eq!(v2.read(&id, "c").unwrap().len(), 4);
        v2.append(&id, Kind::User, "c", "fifth").unwrap();
        assert_eq!(v2.read(&id, "c").unwrap().len(), 5);
        assert_eq!(Vault::open(v.dir().to_path_buf()).unwrap().chain_state(&id).unwrap().0, 5);
    }

    #[test]
    fn stale_tmp_is_cleared_on_open() {
        let (v, _id) = setup("m4tmp");
        let t = v.dir().join("r/0000000000000001.tmp");
        fs::write(&t, b"torn").unwrap();
        let mut v2 = Vault::open(v.dir().to_path_buf()).unwrap();
        assert!(!t.exists());
        v2.append(&Identity::generate().unwrap(), Kind::User, "c", "x").unwrap(); // number 1 is usable
    }
}

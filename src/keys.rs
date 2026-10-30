//! The box identity: one ECDSA P-256 signing key and one HPKE P-256 sealing key, both made by
//! arrowmem-core's own types. Kept in a file that must be mode 0600 and is wrapped at rest:
//! Argon2id (RFC 9106) derives a 256-bit key from a passphrase, AES-256-GCM seals the two
//! private keys. Both primitives are maintained crates; nothing here is hand-rolled.

use crate::hex;
use arrowmem_core::{SealPrivateKey, SealPublicKey, new_seal_keypair};
use hpke::{Deserializable, Serializable};
use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::elliptic_curve::Generate;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

pub struct Identity {
    pub sign: SigningKey,
    pub seal_sk: SealPrivateKey,
    pub seal_pk: SealPublicKey,
}

impl Identity {
    pub fn generate() -> Result<Identity, String> {
        let sign = SigningKey::try_generate_from_rng(&mut getrandom::SysRng).map_err(|_| "no random bytes")?;
        let (seal_sk, seal_pk) = new_seal_keypair();
        Ok(Identity { sign, seal_sk, seal_pk })
    }

    pub fn sign_pub(&self) -> [u8; 33] {
        let v: &VerifyingKey = self.sign.verifying_key();
        v.to_sec1_point(true).as_bytes().try_into().expect("33 bytes")
    }

    pub fn seal_pub(&self) -> [u8; 65] {
        self.seal_pk.to_bytes().as_slice().try_into().expect("65 bytes")
    }

    /// Create the file, never overwrite one. Mode 0600. The two private keys are wrapped under
    /// `pass` with Argon2id (RFC 9106, `argon2` crate) and AES-256-GCM (`aes-gcm` crate).
    pub fn save_new(&self, path: &Path, pass: &str) -> Result<(), String> {
        self.save_new_with(path, pass, Kdf::PRODUCTION)
    }

    pub fn save_new_with(&self, path: &Path, pass: &str, kdf: Kdf) -> Result<(), String> {
        if pass.is_empty() {
            return Err("empty passphrase refused".into());
        }
        if let Some(d) = path.parent() {
            std::fs::create_dir_all(d).map_err(|e| format!("mkdir: {}", e.kind()))?;
            let _ = std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700));
        }
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 12];
        getrandom::fill(&mut salt).map_err(|_| "no random bytes")?;
        getrandom::fill(&mut nonce).map_err(|_| "no random bytes")?;
        let aad = format!("{HEADER}\nkdf argon2id m={} t={} p={}\nsalt {}\n", kdf.m_kib, kdf.t, kdf.p, hex::enc(&salt));
        let mut plain = Vec::with_capacity(64);
        plain.extend_from_slice(self.sign.to_bytes().as_slice());
        plain.extend_from_slice(self.seal_sk.to_bytes().as_slice());
        let mut key = derive(pass, &salt, kdf)?;
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| "cipher setup")?;
        let ct = cipher.encrypt(Nonce::from_slice(&nonce), Payload { msg: &plain, aad: aad.as_bytes() }).map_err(|_| "wrap failed")?;
        key.fill(0);
        plain.fill(0);
        let body = format!("{aad}nonce {}\nct {}\n", hex::enc(&nonce), hex::enc(&ct));
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| format!("key file: {}", e.kind()))?;
        f.write_all(body.as_bytes()).and_then(|_| f.sync_all()).map_err(|e| format!("key file: {}", e.kind()))
    }

    /// Load and unwrap; refuse a file readable by group or others. A wrong passphrase and a
    /// damaged file are deliberately the same error.
    pub fn load(path: &Path, pass: &str) -> Result<Identity, String> {
        Self::load_with_floor(path, pass, Kdf::PRODUCTION)
    }

    /// As `load`, but the key file's Argon2id cost must be at least `floor` in every field.
    /// Production code passes `Kdf::PRODUCTION` (the RFC 9106 second option); only tests with
    /// `Kdf::TEST` files pass a lower floor.
    pub fn load_with_floor(path: &Path, pass: &str, floor: Kdf) -> Result<Identity, String> {
        let md = std::fs::metadata(path).map_err(|e| format!("key file: {}", e.kind()))?;
        if md.permissions().mode() & 0o077 != 0 {
            return Err("key file is readable by others; chmod 600".into());
        }
        let t = std::fs::read_to_string(path).map_err(|e| format!("key file: {}", e.kind()))?;
        let mut l = t.lines();
        match l.next() {
            Some(HEADER) => {}
            Some("arrowmesh-identity-v1") => return Err("key file is an old plain-text identity; it is no longer loaded".into()),
            _ => return Err("key file: wrong header".into()),
        }
        let kdf_line = l.next().ok_or("key file: malformed")?;
        let salt_line = l.next().ok_or("key file: malformed")?;
        let kdf = Kdf::parse(kdf_line).ok_or("key file: bad kdf line")?;
        if kdf.m_kib < floor.m_kib || kdf.t < floor.t || kdf.p < floor.p {
            return Err("key file: argon2id cost is below the RFC 9106 second option; refused".into());
        }
        let salt = salt_line.strip_prefix("salt ").and_then(hex::dec).filter(|b| b.len() == 16).ok_or("key file: bad salt")?;
        let nonce = l.next().and_then(|s| s.strip_prefix("nonce ")).and_then(hex::dec).filter(|b| b.len() == 12).ok_or("key file: bad nonce")?;
        let ct = l.next().and_then(|s| s.strip_prefix("ct ")).and_then(hex::dec).filter(|b| b.len() == 64 + 16).ok_or("key file: bad ciphertext")?;
        let aad = format!("{HEADER}\n{kdf_line}\n{salt_line}\n");
        let mut key = derive(pass, &salt, kdf)?;
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| "cipher setup")?;
        let opened = cipher.decrypt(Nonce::from_slice(&nonce), Payload { msg: &ct, aad: aad.as_bytes() });
        key.fill(0);
        let mut plain = opened.map_err(|_| "wrong passphrase or damaged key file".to_string())?;
        let sign = SigningKey::from_slice(&plain[..32]).map_err(|_| "key file: bad signing key");
        let seal_sk = SealPrivateKey::from_bytes(&plain[32..]).map_err(|_| "key file: bad sealing key");
        plain.fill(0);
        let (sign, seal_sk) = (sign?, seal_sk?);
        let seal_pk = <hpke::kem::DhP256HkdfSha256 as hpke::Kem>::sk_to_pk(&seal_sk);
        Ok(Identity { sign, seal_sk, seal_pk })
    }
}

/// The passphrase delivered as a systemd credential: `<dir>/arrowmesh-passphrase`, where `dir` is
/// `$CREDENTIALS_DIRECTORY` (N2). One trailing newline is dropped. `None` if the file is absent.
pub fn passphrase_from_credential(dir: &Path) -> Option<Result<String, String>> {
    let t = match std::fs::read_to_string(dir.join("arrowmesh-passphrase")) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => return Some(Err(format!("credential: {}", e.kind()))),
    };
    let t = t.strip_suffix('\n').unwrap_or(&t).to_string();
    Some(if t.is_empty() { Err("credential is empty".into()) } else { Ok(t) })
}

const HEADER: &str = "arrowmesh-identity-v2";

/// Argon2id cost, stored in the file so it can be raised later without breaking old files.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Kdf {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl Kdf {
    /// RFC 9106 section 4 second recommended option: 64 MiB, 3 passes, 4 lanes.
    pub const PRODUCTION: Kdf = Kdf { m_kib: 64 * 1024, t: 3, p: 4 };
    /// Cheap, for tests only.
    pub const TEST: Kdf = Kdf { m_kib: 64, t: 1, p: 1 };

    pub fn parse(line: &str) -> Option<Kdf> {
        let rest = line.strip_prefix("kdf argon2id ")?;
        let mut it = rest.split(' ');
        let m = it.next()?.strip_prefix("m=")?.parse().ok()?;
        let t = it.next()?.strip_prefix("t=")?.parse().ok()?;
        let p = it.next()?.strip_prefix("p=")?.parse().ok()?;
        // Upper bounds only, so a hostile file cannot make load allocate gigabytes.
        (it.next().is_none() && m <= 1024 * 1024 && (1..=16).contains(&t) && (1..=16).contains(&p)).then_some(Kdf { m_kib: m, t, p })
    }
}

fn derive(pass: &str, salt: &[u8], kdf: Kdf) -> Result<[u8; 32], String> {
    let params = Params::new(kdf.m_kib, kdf.t, kdf.p, Some(32)).map_err(|_| "bad kdf parameters")?;
    let mut out = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params).hash_password_into(pass.as_bytes(), salt, &mut out).map_err(|_| "kdf failed")?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PW: &str = "correct horse battery";

    fn mk(tag: &str) -> (Identity, std::path::PathBuf) {
        let p = crate::testutil::tmp(tag).join("id.key");
        let a = Identity::generate().unwrap();
        a.save_new_with(&p, PW, Kdf::TEST).unwrap();
        (a, p)
    }

    #[test]
    fn wrap_unwrap_round_trip_same_keys_and_mode() {
        let (a, p) = mk("keys");
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        let b = Identity::load_with_floor(&p, PW, Kdf::TEST).unwrap();
        assert_eq!(a.sign_pub(), b.sign_pub());
        assert_eq!(a.seal_pub(), b.seal_pub());
        assert_eq!(a.sign.to_bytes(), b.sign.to_bytes());
    }

    #[test]
    fn wrong_or_empty_passphrase_fails() {
        let (_, p) = mk("keys5");
        assert!(Identity::load_with_floor(&p, "wrong", Kdf::TEST).is_err());
        assert!(Identity::load_with_floor(&p, "", Kdf::TEST).is_err());
        assert!(Identity::generate().unwrap().save_new_with(&p.with_extension("x"), "", Kdf::TEST).is_err());
    }

    #[test]
    fn file_holds_no_raw_key_bytes_and_tamper_is_refused() {
        let (a, p) = mk("keys6");
        let raw = std::fs::read(&p).unwrap();
        for k in [a.sign.to_bytes().to_vec(), a.seal_sk.to_bytes().to_vec()] {
            assert!(!raw.windows(32).any(|w| w == k.as_slice()));
            assert!(!String::from_utf8_lossy(&raw).contains(&hex::enc(&k)));
        }
        // Change the kdf cost in the authenticated header: must not load even with the right passphrase.
        let t = String::from_utf8(raw).unwrap().replace("t=1", "t=2");
        std::fs::write(&p, t).unwrap();
        assert!(Identity::load_with_floor(&p, PW, Kdf::TEST).is_err());
    }

    #[test]
    fn old_plain_file_refused_with_a_clear_reason() {
        let p = crate::testutil::tmp("keys7").join("id.key");
        std::fs::write(&p, "arrowmesh-identity-v1\nsign 00\nseal 00\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(Identity::load_with_floor(&p, PW, Kdf::TEST).err().unwrap().contains("plain-text"));
    }

    #[test]
    fn never_overwrites() {
        let (_, p) = mk("keys2");
        assert!(Identity::generate().unwrap().save_new_with(&p, PW, Kdf::TEST).is_err());
    }

    #[test]
    fn loose_mode_refused() {
        let (_, p) = mk("keys3");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Identity::load_with_floor(&p, PW, Kdf::TEST).is_err());
    }

    #[test]
    fn garbage_refused() {
        let d = crate::testutil::tmp("keys4");
        let p = d.join("id.key");
        std::fs::write(&p, "nope").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(Identity::load_with_floor(&p, PW, Kdf::TEST).is_err());
    }

    #[test]
    fn signing_key_zeroizes_on_drop_sealing_key_not_provable_by_type() {
        // hpke's P-256 PrivateKey does not implement ZeroizeOnDrop at the type level, so only the
        // signing key is asserted here; the sealing key's erasure is stated as unproven in the README.
        fn zod<T: zeroize::ZeroizeOnDrop>() {}
        zod::<SigningKey>();
    }

    #[test]
    fn argon2_cost_below_the_rfc_9106_second_option_is_refused() {
        let (_, p) = mk("keysfloor");
        // The test file is Kdf::TEST: loads under a test floor, refused under production.
        assert!(Identity::load_with_floor(&p, PW, Kdf::TEST).is_ok());
        let e = Identity::load(&p, PW).err().unwrap();
        assert!(e.contains("below the RFC 9106"), "{e}");
        // Each field alone: a file at the production cost except one weak field is refused.
        for (m, t, pp) in [(32 * 1024, 3, 4), (65536, 2, 4), (65536, 3, 3)] {
            let kdf = Kdf { m_kib: m, t, p: pp };
            let q = p.with_file_name(format!("w{m}-{t}-{pp}.key"));
            Identity::generate().unwrap().save_new_with(&q, PW, kdf).unwrap();
            assert!(Identity::load(&q, PW).err().unwrap().contains("below the RFC 9106"), "{m} {t} {pp}");
        }
        // At the floor exactly it loads.
        let q = p.with_file_name("exact.key");
        Identity::generate().unwrap().save_new_with(&q, PW, Kdf::PRODUCTION).unwrap();
        assert!(Identity::load(&q, PW).is_ok());
    }

    #[test]
    fn credential_file_is_read_and_a_missing_or_empty_one_is_distinguished() {
        let d = crate::testutil::tmp("cred");
        assert!(passphrase_from_credential(&d).is_none());
        std::fs::write(d.join("arrowmesh-passphrase"), "from the credential\n").unwrap();
        assert_eq!(passphrase_from_credential(&d), Some(Ok("from the credential".to_string())));
        std::fs::write(d.join("arrowmesh-passphrase"), "\n").unwrap();
        assert!(matches!(passphrase_from_credential(&d), Some(Err(_))));
    }

    #[test]
    fn production_cost_is_the_rfc_9106_second_option() {
        assert_eq!(Kdf::PRODUCTION, Kdf { m_kib: 65536, t: 3, p: 4 });
        assert_eq!(Kdf::parse("kdf argon2id m=65536 t=3 p=4"), Some(Kdf::PRODUCTION));
        assert_eq!(Kdf::parse("kdf argon2id m=99999999 t=3 p=4"), None);
    }
}

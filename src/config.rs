//! Config: flat `key = value` lines, `#` comments. Every address is checked by `net` on load.
//!
//! ```text
//! model_path = /path/to/model.gguf     # omit to attach to a llama.cpp server already running
//! llama_bin = llama-server
//! llama_addr = 127.0.0.1:8081          # loopback only
//! chat_addr = 127.0.0.1:8088           # loopback only
//! mesh_listen = 127.0.0.1:8090         # loopback or RFC1918
//! gate_model = false
//! vault_dir = /home/you/.local/share/arrowmesh/vault
//! key_file = /home/you/.local/share/arrowmesh/identity.key
//! token_file = /home/you/.local/share/arrowmesh/api-token   # loopback API bearer token, mode 600
//! peer = "name 192.168.1.20:8090 <signing key hex> <sealing key hex>"
//! ```

use crate::{hex, net};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct Peer {
    pub name: String,
    pub addr: SocketAddr,
    pub sign_pub: [u8; 33],
    pub seal_pub: [u8; 65],
}

#[derive(Clone, Debug)]
pub struct Config {
    pub model_path: Option<String>,
    pub llama_bin: String,
    pub llama_addr: SocketAddr,
    pub chat_addr: SocketAddr,
    pub mesh_listen: SocketAddr,
    pub gate_model: bool,
    pub vault_dir: PathBuf,
    pub key_file: PathBuf,
    pub token_file: PathBuf,
    /// Key for the model server (mode 600). Created at first start when arrowmesh launches the model; read when attaching.
    pub llama_key_file: PathBuf,
    /// When true, attach mode without a readable llama_key_file refuses to start (the tray sets it). Default false.
    pub llama_key_required: bool,
    pub peers: Vec<Peer>,
    /// How long a response write may block on a client that is not reading (not a file setting).
    pub send_timeout: Duration,
}

/// Only the literal `true` or `false`. True, 1, yes, " true" are errors, never silently false.
fn parse_bool(v: &str) -> Result<bool, ()> {
    match v {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(()),
    }
}

/// Text after the first `=`, outer whitespace and one pair of quotes removed, nothing else trimmed.
fn raw_v_of(line: &str) -> &str {
    line.split_once('=').map(|x| x.1).unwrap_or("")
}

fn v_untrimmed(v: &str) -> &str {
    let v = v.trim_start_matches(' ').trim_end_matches(['\t', '\r', '\n']);
    let v = v.strip_prefix('"').unwrap_or(v);
    v.strip_suffix('"').unwrap_or(v)
}

pub fn valid_name(n: &str) -> bool {
    !n.is_empty() && n.len() <= 32 && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

impl Config {
    pub fn defaults(home: &Path) -> Config {
        let data = home.join(".local/share/arrowmesh");
        Config {
            model_path: None,
            llama_bin: "llama-server".into(),
            llama_addr: "127.0.0.1:8081".parse().unwrap(),
            chat_addr: "127.0.0.1:8088".parse().unwrap(),
            mesh_listen: "127.0.0.1:8090".parse().unwrap(),
            gate_model: false,
            vault_dir: data.join("vault"),
            key_file: data.join("identity.key"),
            token_file: data.join("api-token"),
            llama_key_file: data.join("llama-api-key"),
            llama_key_required: false,
            peers: Vec::new(),
            send_timeout: crate::stream::WRITE_TIMEOUT,
        }
    }

    pub fn parse(text: &str, home: &Path) -> Result<Config, String> {
        let mut c = Config::defaults(home);
        for (i, raw) in text.lines().enumerate() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let at = |m: &str| format!("line {}: {m}", i + 1);
            let (k, v) = line.split_once('=').ok_or_else(|| at("expected key = value"))?;
            let (k, v) = (k.trim(), v.trim().trim_matches('"').trim());
            // Booleans take the unquoted text untrimmed, so "true " inside quotes is not "true".
            let vb = v_untrimmed(raw_v_of(line));
            match k {
                "model_path" => c.model_path = Some(v.to_string()),
                "llama_bin" => c.llama_bin = v.to_string(),
                "llama_addr" => c.llama_addr = net::parse_loopback(v).map_err(|e| at(&format!("llama_addr: {e}")))?,
                "chat_addr" => c.chat_addr = net::parse_loopback(v).map_err(|e| at(&format!("chat_addr: {e}")))?,
                "mesh_listen" => c.mesh_listen = net::parse_addr(v).map_err(|e| at(&format!("mesh_listen: {e}")))?,
                "gate_model" => c.gate_model = parse_bool(vb).map_err(|_| at("gate_model must be exactly true or false"))?,
                "vault_dir" => c.vault_dir = PathBuf::from(v),
                "key_file" => c.key_file = PathBuf::from(v),
                "token_file" => c.token_file = PathBuf::from(v),
                "llama_key_file" => c.llama_key_file = PathBuf::from(v),
                "llama_key_required" => c.llama_key_required = parse_bool(vb).map_err(|_| at("llama_key_required must be exactly true or false"))?,
                "peer" => c.peers.push(parse_peer(v).map_err(|e| at(&format!("peer: {e}")))?),
                _ => return Err(at("unknown key")),
            }
        }
        let mut names: Vec<&str> = c.peers.iter().map(|p| p.name.as_str()).collect();
        names.sort();
        names.dedup();
        if names.len() != c.peers.len() {
            return Err("duplicate peer name".into());
        }
        Ok(c)
    }

    pub fn load(path: &Path, home: &Path) -> Result<Config, String> {
        let t = std::fs::read_to_string(path).map_err(|e| format!("cannot read config: {}", e.kind()))?;
        let mut c = Config::parse(&t, home)?;
        // Peers added through the API wait in a sidecar file next to the identity key until a restart.
        for p in read_pending(&c.key_file) {
            if c.peers.iter().any(|q| q.name == p.name) {
                return Err("duplicate peer name".into());
            }
            c.peers.push(p);
        }
        Ok(c)
    }
}

/// Peers added through the loopback API: one `name addr signing_hex sealing_hex` line each,
/// public keys only. Read at start; a malformed line is skipped.
pub fn pending_peers_path(key_file: &Path) -> PathBuf {
    key_file.parent().map(Path::to_path_buf).unwrap_or_default().join("peers.added")
}

pub fn read_pending(key_file: &Path) -> Vec<Peer> {
    let t = std::fs::read_to_string(pending_peers_path(key_file)).unwrap_or_default();
    t.lines().filter_map(|l| parse_peer(l.trim()).ok()).collect()
}

pub fn parse_peer(v: &str) -> Result<Peer, String> {
    let f: Vec<&str> = v.split_whitespace().collect();
    if f.len() != 4 {
        return Err("expected: name addr signing_hex sealing_hex".into());
    }
    if !valid_name(f[0]) {
        return Err("bad name".into());
    }
    let addr = net::parse_addr(f[1])?;
    let sign = hex::dec(f[2]).filter(|b| b.len() == 33).ok_or("signing key must be 33 bytes of hex")?;
    let seal = hex::dec(f[3]).filter(|b| b.len() == 65).ok_or("sealing key must be 65 bytes of hex")?;
    Ok(Peer { name: f[0].into(), addr, sign_pub: sign.try_into().unwrap(), seal_pub: seal.try_into().unwrap() })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn home() -> PathBuf {
        PathBuf::from("/h")
    }

    #[test]
    fn defaults_when_empty() {
        let c = Config::parse("# nothing\n", &home()).unwrap();
        assert_eq!(c.chat_addr.to_string(), "127.0.0.1:8088");
        assert!(c.vault_dir.starts_with("/h"));
    }

    #[test]
    fn refuses_public_and_hostnames() {
        for l in [
            "llama_addr = 8.8.8.8:80", "llama_addr = 192.168.1.2:80", "chat_addr = 10.0.0.1:80",
            "mesh_listen = 0.0.0.0:80", "mesh_listen = example.com:80", "mesh_listen = 1.2.3.4:80",
        ] {
            assert!(Config::parse(l, &home()).is_err(), "{l}");
        }
        assert!(Config::parse("mesh_listen = 192.168.1.2:80", &home()).is_ok());
    }

    #[test]
    fn peer_checks() {
        let k33 = "02".to_string() + &"11".repeat(32);
        let k65 = "04".to_string() + &"22".repeat(64);
        let ok = format!("peer = \"bob 192.168.1.9:8090 {k33} {k65}\"");
        assert_eq!(Config::parse(&ok, &home()).unwrap().peers[0].name, "bob");
        let pub_ip = format!("peer = \"bob 8.8.8.8:8090 {k33} {k65}\"");
        assert!(Config::parse(&pub_ip, &home()).is_err());
        let host = format!("peer = \"bob bob.local:8090 {k33} {k65}\"");
        assert!(Config::parse(&host, &home()).is_err());
        let short = format!("peer = \"bob 10.0.0.2:8090 {k33} 04ab\"");
        assert!(Config::parse(&short, &home()).is_err());
        assert!(Config::parse(&format!("{ok}\n{ok}"), &home()).is_err());
    }

    #[test]
    fn strict_bool_per_key() {
        for key in ["gate_model", "llama_key_required"] {
            for bad in ["True", "1", "yes", "TRUE", "\"true \"", "\" true\"", "", "on"] {
                let r = Config::parse(&format!("{key} = {bad}"), &home());
                let e = r.expect_err(&format!("{key} = {bad}"));
                assert!(e.contains(key), "{e}");
            }
            let get = |v: &str| {
                let c = Config::parse(&format!("{key} = {v}"), &home()).unwrap();
                if key == "gate_model" { c.gate_model } else { c.llama_key_required }
            };
            assert!(get("true") && get("\"true\"") && !get("false"));
        }
    }

    #[test]
    fn unknown_key_refused() {
        assert!(Config::parse("upstream = https://x", &home()).is_err());
    }
}

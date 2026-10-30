//! `arrowmesh install`: a systemd user unit, a config skeleton, an identity key. Idempotent; never
//! overwrites an existing config, key or API token file. It does not start anything and does not
//! call systemctl.

use crate::config::Config;
use crate::keys::{Identity, Kdf};
use std::path::{Path, PathBuf};

pub struct Installed {
    pub unit: PathBuf,
    pub config: PathBuf,
    pub key: PathBuf,
    pub token: PathBuf,
    pub wrote_config: bool,
    pub wrote_key: bool,
    pub wrote_token: bool,
}

pub fn unit_text(exe: &Path, config: &Path) -> String {
    format!(
        "[Unit]\nDescription=Arrowmesh device brain\nAfter=network.target\n\n[Service]\nExecStart={} run --config {}\nRestart=on-failure\nRestartSec=3\n\
         NoNewPrivileges=yes\nLimitCORE=0\nPrivateTmp=yes\nProtectSystem=strict\nProtectHome=read-only\nReadWritePaths=%h/.local/share/arrowmesh\n\
         RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX\nIPAddressDeny=any\nIPAddressAllow=localhost 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16\n\n[Install]\nWantedBy=default.target\n",
        exe.display(),
        config.display()
    )
}

pub fn skeleton(cfg: &Config) -> String {
    format!(
        "# Arrowmesh config. Every address must be an IP literal: loopback, or RFC1918 for the mesh.\n\
         # Uncomment model_path to let arrowmesh launch llama.cpp; leave it out to attach to one already running.\n\
         # model_path = /path/to/model.gguf\n\
         llama_bin = {}\nllama_addr = {}\nchat_addr = {}\nmesh_listen = {}\ngate_model = false\n\
         vault_dir = {}\nkey_file = {}\ntoken_file = {}\nllama_key_file = {}\n\
         # One line per peer, from `arrowmesh pubkeys` on that box:\n\
         # peer = \"name 192.168.1.20:8090 <signing key hex> <sealing key hex>\"\n",
        cfg.llama_bin, cfg.llama_addr, cfg.chat_addr, cfg.mesh_listen, cfg.vault_dir.display(), cfg.key_file.display(), cfg.token_file.display(), cfg.llama_key_file.display()
    )
}

/// `phrase` wraps a NEW identity key (Argon2id, production cost). An existing key is left alone.
pub fn run(home: &Path, exe: &Path, phrase: &str) -> Result<Installed, String> {
    run_with(home, exe, phrase, Kdf::PRODUCTION)
}

pub fn run_with(home: &Path, exe: &Path, phrase: &str, kdf: Kdf) -> Result<Installed, String> {
    let cfg_dir = home.join(".config/arrowmesh");
    let unit_dir = home.join(".config/systemd/user");
    std::fs::create_dir_all(&cfg_dir).map_err(|e| format!("mkdir: {}", e.kind()))?;
    std::fs::create_dir_all(&unit_dir).map_err(|e| format!("mkdir: {}", e.kind()))?;
    let defaults = Config::defaults(home);
    let config = cfg_dir.join("config");
    let wrote_config = !config.exists();
    if wrote_config {
        std::fs::write(&config, skeleton(&defaults)).map_err(|e| format!("config: {}", e.kind()))?;
    }
    let unit = unit_dir.join("arrowmesh.service");
    std::fs::write(&unit, unit_text(exe, &config)).map_err(|e| format!("unit: {}", e.kind()))?;
    let wrote_key = !defaults.key_file.exists();
    if wrote_key {
        Identity::generate()?.save_new_with(&defaults.key_file, phrase, kdf)?;
    }
    let wrote_token = !defaults.token_file.exists();
    if wrote_token {
        crate::token::create_new(&defaults.token_file)?;
    }
    Ok(Installed { unit, config, key: defaults.key_file, token: defaults.token_file, wrote_config, wrote_key, wrote_token })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const PHRASE: &str = "install test phrase";

    #[test]
    fn install_writes_all_four_and_skeleton_parses() {
        let home = crate::testutil::tmp("inst");
        let r = run_with(&home, Path::new("/usr/local/bin/arrowmesh"), PHRASE, Kdf::TEST).unwrap();
        assert!(r.wrote_config && r.wrote_key && r.wrote_token);
        assert_eq!(std::fs::metadata(&r.token).unwrap().permissions().mode() & 0o777, 0o600);
        let unit = std::fs::read_to_string(&r.unit).unwrap();
        assert!(unit.contains("ExecStart=/usr/local/bin/arrowmesh run --config"));
        let cfg = Config::load(&r.config, &home).unwrap();
        assert!(Identity::load_with_floor(&cfg.key_file, PHRASE, Kdf::TEST).is_ok());
        assert!(Identity::load_with_floor(&cfg.key_file, "not it", Kdf::TEST).is_err());
        assert_eq!(cfg.token_file, r.token);
        assert!(crate::token::load(&cfg.token_file).is_ok());
    }

    #[test]
    fn second_run_keeps_config_and_key() {
        let home = crate::testutil::tmp("inst2");
        let a = run_with(&home, Path::new("/x"), PHRASE, Kdf::TEST).unwrap();
        let t1 = std::fs::read(&a.token).unwrap();
        let k1 = std::fs::read(&a.key).unwrap();
        std::fs::write(&a.config, "chat_addr = 127.0.0.1:9999\n").unwrap();
        let b = run_with(&home, Path::new("/x"), PHRASE, Kdf::TEST).unwrap();
        assert!(!b.wrote_config && !b.wrote_key && !b.wrote_token);
        assert_eq!(std::fs::read(&b.token).unwrap(), t1);
        assert_eq!(std::fs::read(&b.key).unwrap(), k1);
        assert!(std::fs::read_to_string(&b.config).unwrap().contains("9999"));
    }
}

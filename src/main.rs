use arrowmesh::config::Config;
use arrowmesh::{daemon, hex, install, keys::Identity, status};
use std::path::PathBuf;
use std::process::ExitCode;

fn home() -> Result<PathBuf, String> {
    std::env::var_os("HOME").map(PathBuf::from).ok_or_else(|| "HOME is not set".into())
}

fn config_path(args: &[String], home: &std::path::Path) -> PathBuf {
    match args.iter().position(|a| a == "--config") {
        Some(i) if i + 1 < args.len() => PathBuf::from(&args[i + 1]),
        _ => home.join(".config/arrowmesh/config"),
    }
}

/// The identity passphrase: a systemd credential (`$CREDENTIALS_DIRECTORY/arrowmesh-passphrase`), else the ARROWMESH_PASSPHRASE environment variable, else a prompt on the
/// terminal (asked twice when `confirm`). Never read from a config file, never printed.
fn passphrase(confirm: bool) -> Result<String, String> {
    if let Some(dir) = std::env::var_os("CREDENTIALS_DIRECTORY")
        && let Some(r) = arrowmesh::keys::passphrase_from_credential(std::path::Path::new(&dir))
    {
        return r;
    }
    if let Ok(v) = std::env::var("ARROWMESH_PASSPHRASE") {
        return if v.is_empty() { Err("ARROWMESH_PASSPHRASE is empty".into()) } else { Ok(v) };
    }
    let a = rpassword::prompt_password("identity passphrase: ").map_err(|_| "no passphrase: set ARROWMESH_PASSPHRASE or run on a terminal".to_string())?;
    if a.is_empty() {
        return Err("empty passphrase refused".into());
    }
    if confirm && rpassword::prompt_password("again: ").map_err(|e| e.to_string())? != a {
        return Err("passphrases differ".into());
    }
    Ok(a)
}

fn real() -> Result<ExitCode, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let home = home()?;
    match args.first().map(String::as_str) {
        Some("install") => {
            let exe = std::env::current_exe().map_err(|e| e.to_string())?;
            // Ask only when a new key is going to be written.
            let phrase = if Config::defaults(&home).key_file.exists() { "unused".to_string() } else { passphrase(true)? };
            let r = install::run(&home, &exe, &phrase)?;
            println!("unit: {}", r.unit.display());
            println!("config: {} ({})", r.config.display(), if r.wrote_config { "written" } else { "kept" });
            println!("identity key: {} ({})", r.key.display(), if r.wrote_key { "created, wrapped with your passphrase, mode 600" } else { "kept" });
            println!("api token: {} ({})", r.token.display(), if r.wrote_token { "created, mode 600" } else { "kept" });
            println!("next: systemctl --user daemon-reload && systemctl --user enable --now arrowmesh");
            Ok(ExitCode::SUCCESS)
        }
        Some("run") => {
            arrowmesh::hardening::no_core_dumps()?;
            let cfg = Config::load(&config_path(&args, &home), &home)?;
            let gate = daemon::gate_for(&cfg);
            // The vault starts sealed. No passphrase is read from env, file or argv; the app sends it to /v1/vault/unlock.
            let unkeyed = cfg.model_path.is_none() && !cfg.llama_key_file.exists();
            let run = daemon::start_locked(cfg, gate)?;
            eprintln!("arrowmesh: up, vault locked (chat {}, mesh {})", run.chat_addr, run.mesh_addr);
            if unkeyed {
                eprintln!("arrowmesh: warning, attached model server with no llama_key_file, upstream calls carry no key");
            }
            loop {
                std::thread::sleep(std::time::Duration::from_secs(3600));
            }
        }
        Some("status") => {
            let cfg = Config::load(&config_path(&args, &home), &home)?;
            // No passphrase obtainable (no env var, no terminal) means the vault reports locked.
            let phrase = passphrase(false).ok();
            let id = phrase.as_deref().and_then(|p| Identity::load(&cfg.key_file, p).ok());
            let r = status::collect(&cfg, id.as_ref());
            print!("{}", r.render());
            Ok(if r.all_up() { ExitCode::SUCCESS } else { ExitCode::from(1) })
        }
        Some("pubkeys") => {
            let cfg = Config::load(&config_path(&args, &home), &home)?;
            let id = Identity::load(&cfg.key_file, &passphrase(false)?)?;
            println!("signing {}\nsealing {}", hex::enc(&id.sign_pub()), hex::enc(&id.seal_pub()));
            Ok(ExitCode::SUCCESS)
        }
        _ => {
            eprintln!("usage: arrowmesh install | run [--config P] | status [--config P] | pubkeys [--config P]");
            Ok(ExitCode::from(2))
        }
    }
}

fn main() -> ExitCode {
    match real() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("arrowmesh: {e}");
            ExitCode::from(1)
        }
    }
}

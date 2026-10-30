//! `arrowmesh status`: counts and yes/no only. No names, no addresses, no content.

use crate::config::Config;
use crate::gatepath::Gate;
use crate::keys::Identity;
use crate::vault::Vault;
use crate::{mesh, net};
use std::time::Duration;

#[derive(Debug, PartialEq, Eq)]
pub struct Report {
    pub model_up: bool,
    pub gate_up: bool,
    pub vault_unlocked: bool,
    pub vault_records: usize,
    pub peers_total: usize,
    pub peers_reachable: usize,
}

pub fn model_up(cfg: &Config) -> bool {
    matches!(net::http(&cfg.llama_addr, "GET", "/health", None, Duration::from_secs(2)), Ok((200, _)))
}

/// The gate is up when its rules still block a known-bad canary and pass a plain sentence
/// (and, if the model layer is switched on, the model answers).
pub fn gate_up(cfg: &Config) -> bool {
    let g = Gate::new(None);
    let rules = g.check("card 4111 1111 1111 1111").is_err() && g.check("the build is green").is_ok();
    rules && (!cfg.gate_model || model_up(cfg))
}

/// `id` is the already-unwrapped identity if the caller has one; nothing here runs the KDF, so a
/// status call costs no Argon2id (N1). Without it the vault reports locked.
pub fn collect(cfg: &Config, id: Option<&Identity>) -> Report {
    // The CLI is its own process, so its own open (and temp sweep) cannot race a daemon append here.
    let (unlocked, records) = match Vault::open(cfg.vault_dir.clone()) {
        Ok(v) => vault_facts(&v, id),
        Err(_) => (false, 0),
    };
    assemble(cfg, unlocked, records)
}

/// The daemon's status: reads the shared vault under its mutex. It never opens a second handle and
/// never sweeps temp files; that sweep runs once, at boot (F2).
pub fn collect_shared(cfg: &Config, vault: &std::sync::Mutex<Vault>, id: Option<&Identity>) -> Report {
    let (unlocked, records) = vault_facts(&vault.lock().unwrap_or_else(|e| e.into_inner()), id);
    assemble(cfg, unlocked, records)
}

fn vault_facts(v: &Vault, id: Option<&Identity>) -> (bool, usize) {
    (id.is_some_and(|id| v.probe(id).is_ok()), v.record_count())
}

fn assemble(cfg: &Config, unlocked: bool, records: usize) -> Report {
    Report {
        model_up: model_up(cfg),
        gate_up: gate_up(cfg),
        vault_unlocked: unlocked,
        vault_records: records,
        peers_total: cfg.peers.len(),
        peers_reachable: cfg.peers.iter().filter(|p| mesh::reachable(p)).count(),
    }
}

impl Report {
    pub fn all_up(&self) -> bool {
        self.model_up && self.gate_up && self.vault_unlocked && self.peers_reachable == self.peers_total
    }

    pub fn render(&self) -> String {
        let ud = |b: bool| if b { "up" } else { "down" };
        format!(
            "model: {}\ngate: {}\nvault: {} ({} records)\npeers: {} of {} reachable\n",
            ud(self.model_up),
            ud(self.gate_up),
            if self.vault_unlocked { "unlocked" } else { "locked" },
            self.vault_records,
            self.peers_reachable,
            self.peers_total
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_is_counts_only() {
        let r = Report { model_up: true, gate_up: true, vault_unlocked: false, vault_records: 3, peers_total: 2, peers_reachable: 1 };
        assert_eq!(r.render(), "model: up\ngate: up\nvault: locked (3 records)\npeers: 1 of 2 reachable\n");
        assert!(!r.all_up());
    }

    #[test]
    fn gate_canary_works_with_rules_only() {
        let cfg = Config::defaults(std::path::Path::new("/h"));
        assert!(gate_up(&cfg));
    }

    #[test]
    fn nothing_running_reports_down_not_a_crash() {
        let mut cfg = Config::defaults(&crate::testutil::tmp("st"));
        cfg.llama_addr = "127.0.0.1:1".parse().unwrap();
        let r = collect(&cfg, None);
        assert!(!r.model_up && !r.vault_unlocked && !r.all_up());
    }
}

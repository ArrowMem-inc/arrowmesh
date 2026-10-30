//! The only door text goes through before it leaves for the model or a peer, and again before a
//! model reply is delivered. Fails closed: a scan that errors, panics or cannot reach its model
//! layer is a refusal. Verdicts expose category names only, and only names of a safe shape.

use gate::{ModelConfig, Verdict};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

type ScanFn = Arc<dyn Fn(&str) -> Verdict + Send + Sync>;

pub struct Gate {
    scan: ScanFn,
    /// Rules layer only. Used for the cumulative prefix scans of a streamed reply, where the model
    /// layer must not run (it runs once, on the whole reply, through `scan`).
    rules: ScanFn,
    verdicts: AtomicU64,
}

fn safe_category(c: &str) -> bool {
    let mut p = c.split(':');
    let ok = |s: Option<&str>| s.is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'));
    ok(p.next()) && ok(p.next()) && p.next().is_none()
}

impl Gate {
    /// Rules layer always; the model layer too when `model` is given (loopback only, enforced by arrowmem-gate).
    pub fn new(model: Option<ModelConfig>) -> Gate {
        Gate { scan: Arc::new(move |t| gate::scan_with(t, model.as_ref())), rules: Arc::new(|t| gate::scan_with(t, None)), verdicts: AtomicU64::new(0) }
    }

    /// Install any scan function (tests use this to prove a panicking scan fails closed).
    pub fn with_scan(f: impl Fn(&str) -> Verdict + Send + Sync + 'static) -> Gate {
        let f: ScanFn = Arc::new(f);
        Gate { scan: f.clone(), rules: f, verdicts: AtomicU64::new(0) }
    }

    /// Install separate rules-only and full scan functions (tests use this to count model calls).
    pub fn with_scans(rules: impl Fn(&str) -> Verdict + Send + Sync + 'static, full: impl Fn(&str) -> Verdict + Send + Sync + 'static) -> Gate {
        Gate { scan: Arc::new(full), rules: Arc::new(rules), verdicts: AtomicU64::new(0) }
    }

    /// How many whole-text verdicts (pass or block) this gate has given since it was built. A count, never content.
    pub fn verdicts(&self) -> u64 {
        self.verdicts.load(Ordering::Relaxed)
    }

    /// Ok means pass. Err carries category names (never matched text). Counted in `verdicts`.
    pub fn check(&self, text: &str) -> Result<(), Vec<String>> {
        self.verdicts.fetch_add(1, Ordering::Relaxed);
        Self::run(&self.scan, text)
    }

    /// As `check`, rules layer only, same fail-closed wrapper. Not counted: it is a prefix scan, not a verdict on a text.
    pub fn check_rules(&self, text: &str) -> Result<(), Vec<String>> {
        Self::run(&self.rules, text)
    }

    fn run(scan: &ScanFn, text: &str) -> Result<(), Vec<String>> {
        match catch_unwind(AssertUnwindSafe(|| scan(text))) {
            Ok(v) if v.pass && !v.model_unreachable => Ok(()),
            Ok(v) => {
                let mut cats: Vec<String> = v.reasons.into_iter().map(|c| if safe_category(&c) { c } else { "gate:blocked".into() }).collect();
                if cats.is_empty() {
                    cats.push("gate:blocked".into());
                }
                Err(cats)
            }
            Err(_) => Err(vec!["gate:internal_error".into()]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verdict(pass: bool, reasons: &[&str], unreachable: bool) -> Verdict {
        Verdict { pass, reasons: reasons.iter().map(|s| s.to_string()).collect(), model_unreachable: unreachable }
    }

    #[test]
    fn real_rules_block_an_email_and_pass_plain_text() {
        let g = Gate::new(None);
        assert!(g.check("the build is green").is_ok());
        let e = g.check(concat!("write to jane.doe@gm", "ail.com about it")).unwrap_err();
        assert!(e.iter().any(|c| c == "personal:email"), "{e:?}");
    }

    #[test]
    fn panic_fails_closed() {
        let g = Gate::with_scan(|_| panic!("boom"));
        assert_eq!(g.check("hello").unwrap_err(), vec!["gate:internal_error".to_string()]);
    }

    #[test]
    fn pass_flag_with_unreachable_model_is_still_a_refusal() {
        let g = Gate::with_scan(|_| verdict(true, &[], true));
        assert!(g.check("x").is_err());
    }

    #[test]
    fn empty_reasons_on_fail_still_yield_a_category() {
        let g = Gate::with_scan(|_| verdict(false, &[], false));
        assert_eq!(g.check("x").unwrap_err(), vec!["gate:blocked".to_string()]);
    }

    #[test]
    fn unsafe_category_text_is_replaced() {
        let g = Gate::with_scan(|_| verdict(false, &["topic:secret word here"], false));
        assert_eq!(g.check("x").unwrap_err(), vec!["gate:blocked".to_string()]);
    }

    #[test]
    fn dead_model_layer_blocks() {
        let g = Gate::new(Some(ModelConfig::new("http://127.0.0.1:1/v1/chat/completions")));
        let e = g.check("plain business text").unwrap_err();
        assert_eq!(e, vec!["model:unreachable".to_string()]);
    }

    #[test]
    fn non_loopback_model_layer_blocks() {
        let g = Gate::new(Some(ModelConfig::new("http://192.168.1.5:8080/v1/chat/completions")));
        assert!(g.check("plain business text").is_err());
    }
}

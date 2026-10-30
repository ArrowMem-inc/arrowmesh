//! Launches a local llama.cpp server and keeps it running. Restarts on exit with a backoff,
//! kills the child on shutdown. The child's output is discarded: nothing it prints is kept.

use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{Duration, Instant};

pub struct Supervisor {
    stop: Arc<AtomicBool>,
    pub starts: Arc<AtomicU32>,
    handle: Option<std::thread::JoinHandle<()>>,
}

/// The command line for llama.cpp's server (R15). Host is always 127.0.0.1. The key file is the
/// only way in (every path but /health needs it), the web UI and the slots endpoint are off
/// (POST /props is off by default and stays off), the CORS allow list is empty and credentials
/// are off, so a web page cannot read or drive the model. Flags checked against the pinned
/// binary's `--help`: --api-key-file, --no-webui, --no-slots, --cors-origins, --no-cors-credentials.
pub fn llama_args(model_path: &str, port: u16, key_file: &std::path::Path) -> Vec<String> {
    let mut a: Vec<String> = ["-m", model_path, "--host", "127.0.0.1", "--port"].iter().map(|s| s.to_string()).collect();
    a.push(port.to_string());
    a.push("--api-key-file".into());
    a.push(key_file.to_string_lossy().into_owned());
    for f in ["--no-webui", "--no-slots", "--no-cors-credentials"] {
        a.push(f.into());
    }
    a.push("--cors-origins".into());
    a.push(String::new());
    a
}

impl Supervisor {
    pub fn start(bin: String, args: Vec<String>, backoff_base: Duration) -> Supervisor {
        let stop = Arc::new(AtomicBool::new(false));
        let starts = Arc::new(AtomicU32::new(0));
        let (st, sc) = (stop.clone(), starts.clone());
        let handle = std::thread::spawn(move || {
            let mut fails = 0u32;
            while !st.load(Ordering::SeqCst) {
                let t0 = Instant::now();
                let child: Option<Child> = Command::new(&bin).args(&args).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().ok();
                sc.fetch_add(1, Ordering::SeqCst);
                if let Some(mut c) = child {
                    loop {
                        if st.load(Ordering::SeqCst) {
                            let _ = c.kill();
                            let _ = c.wait();
                            return;
                        }
                        match c.try_wait() {
                            Ok(Some(_)) | Err(_) => break,
                            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
                        }
                    }
                }
                fails = if t0.elapsed() > Duration::from_secs(60) { 0 } else { (fails + 1).min(6) };
                let wait = backoff_base * 2u32.pow(fails.saturating_sub(1));
                let until = Instant::now() + wait;
                while Instant::now() < until && !st.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        });
        Supervisor { stop, starts, handle: Some(handle) }
    }

    pub fn shutdown(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_bind_loopback() {
        let a = llama_args("/m.gguf", 8081, std::path::Path::new("/k/llama-api-key"));
        let at = |f: &str| a.iter().position(|x| x == f).unwrap_or_else(|| panic!("missing {f}"));
        assert_eq!(a[at("--host") + 1], "127.0.0.1");
        assert_eq!(a[at("--port") + 1], "8081");
        assert_eq!(a[at("--api-key-file") + 1], "/k/llama-api-key");
        assert_eq!(a[at("--cors-origins") + 1], "");
        for f in ["--no-webui", "--no-slots", "--no-cors-credentials"] {
            at(f);
        }
        // Never an inline key (it would show in the process list), never a wildcard, any-address bind or opt-in endpoint.
        assert!(!a.iter().any(|x| x == "--api-key" || x == "*" || x == "0.0.0.0" || x == "--props" || x == "--metrics"));
    }

    #[test]
    fn restarts_a_child_that_exits() {
        let s = Supervisor::start("sh".into(), vec!["-c".into(), "exit 0".into()], Duration::from_millis(20));
        let t0 = Instant::now();
        while s.starts.load(Ordering::SeqCst) < 3 && t0.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(s.starts.load(Ordering::SeqCst) >= 3);
    }

    #[test]
    fn shutdown_kills_a_long_child_quickly() {
        let mut s = Supervisor::start("sleep".into(), vec!["300".into()], Duration::from_millis(20));
        std::thread::sleep(Duration::from_millis(200));
        let t0 = Instant::now();
        s.shutdown();
        assert!(t0.elapsed() < Duration::from_secs(3));
        assert_eq!(s.starts.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn missing_binary_does_not_spin() {
        let s = Supervisor::start("/nonexistent/llama".into(), vec![], Duration::from_millis(100));
        std::thread::sleep(Duration::from_millis(500));
        assert!(s.starts.load(Ordering::SeqCst) <= 5);
    }
}

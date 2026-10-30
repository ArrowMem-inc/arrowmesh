use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

static N: AtomicU32 = AtomicU32::new(0);

/// A fresh empty directory under the system temp dir.
pub fn tmp(tag: &str) -> PathBuf {
    let n = N.fetch_add(1, Ordering::SeqCst);
    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let p = std::env::temp_dir().join(format!("arrowmesh-{tag}-{}-{n}-{t}", std::process::id()));
    std::fs::create_dir_all(&p).unwrap();
    p
}

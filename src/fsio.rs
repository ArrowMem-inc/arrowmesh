//! Atomic small-file writes: temp file, fsync, rename, fsync of the directory.
//! A crash leaves either the old file or the new one, never a torn one.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

fn tmp_path(path: &Path) -> PathBuf {
    let mut n = path.as_os_str().to_owned();
    n.push(".tmp");
    PathBuf::from(n)
}

pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = tmp_path(path);
    {
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    if let Some(d) = path.parent() {
        std::fs::File::open(d)?.sync_all()?;
    }
    Ok(())
}

/// Remove leftover `.tmp` files in a directory (a crash between create and rename).
pub fn clear_stale_tmp(dir: &Path) {
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            if e.file_name().to_string_lossy().ends_with(".tmp") {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_whole_and_leaves_no_tmp() {
        let d = crate::testutil::tmp("fsio");
        let p = d.join("f");
        write_atomic(&p, b"one").unwrap();
        write_atomic(&p, b"two!").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"two!");
        assert!(!tmp_path(&p).exists());
    }
}

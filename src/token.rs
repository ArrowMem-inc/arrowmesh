//! The loopback API bearer token: 32 random bytes as hex in a mode 600 file that `install` writes.
//! Compared in constant time on every request (see app.rs).

use crate::hex;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

pub const MIN_LEN: usize = 64;

/// Create the token file, never overwrite one. Mode 0600. Returns the token.
pub fn create_new(path: &Path) -> Result<String, String> {
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d).map_err(|e| format!("mkdir: {}", e.kind()))?;
    }
    let mut raw = [0u8; 32];
    getrandom::fill(&mut raw).map_err(|_| "no random bytes".to_string())?;
    let t = hex::enc(&raw);
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).map_err(|e| format!("token file: {}", e.kind()))?;
    f.write_all(t.as_bytes()).and_then(|_| f.sync_all()).map_err(|e| format!("token file: {}", e.kind()))?;
    Ok(t)
}

/// The model server key: load it, or create it at first start. Same file rules as the API token.
pub fn load_or_create(path: &Path) -> Result<String, String> {
    if path.exists() { load(path) } else { create_new(path) }
}

/// Load; refuse a file readable by group or others, or one too short to be a real token.
pub fn load(path: &Path) -> Result<String, String> {
    let md = std::fs::metadata(path).map_err(|e| format!("token file: {}", e.kind()))?;
    if md.permissions().mode() & 0o077 != 0 {
        return Err("token file is readable by others; chmod 600".into());
    }
    let t = std::fs::read_to_string(path).map_err(|e| format!("token file: {}", e.kind()))?;
    let t = t.trim().to_string();
    if t.len() < MIN_LEN {
        return Err("token file: token too short".into());
    }
    Ok(t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_load_mode_and_no_overwrite() {
        let p = crate::testutil::tmp("tok").join("api-token");
        let t = create_new(&p).unwrap();
        assert_eq!(t.len(), 64);
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(load(&p).unwrap(), t);
        assert!(create_new(&p).is_err());
    }

    #[test]
    fn loose_mode_and_short_token_refused() {
        let p = crate::testutil::tmp("tok2").join("api-token");
        create_new(&p).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load(&p).is_err());
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&p, "abc").unwrap();
        assert!(load(&p).is_err());
    }
}

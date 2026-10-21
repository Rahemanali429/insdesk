//! Persistence for a device's long-term identity key.

use anyhow::{Context, Result};
use insdesk_crypto::Identity;
use std::fs;
use std::path::Path;

/// Load the identity from `path`, or generate a new one and save it there.
///
/// The key file stores only the 32-byte secret as hex. On Unix the file is
/// created with `0600` permissions so other users cannot read it.
pub fn load_or_create(path: &Path) -> Result<Identity> {
    if path.exists() {
        let hex = fs::read_to_string(path)
            .with_context(|| format!("reading key file {}", path.display()))?;
        let identity = Identity::from_secret_hex(hex.trim())
            .with_context(|| format!("parsing key file {}", path.display()))?;
        Ok(identity)
    } else {
        let identity = Identity::generate().context("generating identity")?;
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).ok();
            }
        }
        fs::write(path, identity.secret_hex())
            .with_context(|| format!("writing key file {}", path.display()))?;
        restrict_permissions(path);
        Ok(identity)
    }
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_mode(0o600);
        let _ = fs::set_permissions(path, perms);
    }
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) {}

//! Linux: a systemd system service with data under /var/lib (not built yet).

use std::path::{Path, PathBuf};

/// Group allowed to read usage data. Install will create it.
pub const READER_GROUP: &str = "netcheck";

pub fn data_dir() -> PathBuf {
    PathBuf::from("/var/lib/netcheck")
}

pub fn install(_bin: &Path, _db: &Path) -> Result<(), String> {
    Err("install is not supported on Linux yet".into())
}

pub fn uninstall() -> Result<(), String> {
    Err("uninstall is not supported on Linux yet".into())
}

//! Windows: a service with data under %ProgramData% (not built yet).

use crate::classify::Prefix;
use std::path::{Path, PathBuf};

pub fn data_dir() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("netcheck")
}

pub fn install(_bin: &Path, _db: &Path) -> Result<(), String> {
    Err("install is not supported on Windows yet".into())
}

pub fn uninstall() -> Result<(), String> {
    Err("uninstall is not supported on Windows yet".into())
}

/// Not wired yet. The service control handler will set the stop flag.
pub fn on_stop_signal() {}

/// Not wired yet. Will read GetAdaptersAddresses.
pub fn local_prefixes() -> Vec<Prefix> {
    Vec::new()
}

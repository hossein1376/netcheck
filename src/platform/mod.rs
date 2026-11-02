//! Everything that differs by OS apart from the meter: data location, service
//! install, stop signals, and local subnet discovery.

use std::fs::{File, TryLockError};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::{local_prefixes, on_stop_signal};

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::{data_dir, install, uninstall};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{data_dir, install, uninstall};

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{data_dir, install, local_prefixes, on_stop_signal, uninstall};

static STOP: AtomicBool = AtomicBool::new(false);

/// True once the OS asked the daemon to stop.
pub fn stop_requested() -> bool {
    STOP.load(Ordering::SeqCst)
}

/// Held for the life of the daemon. Released when dropped or on exit.
pub struct InstanceLock {
    _file: File,
}

/// Take an exclusive lock on `path`, or fail if another daemon holds it.
pub fn lock_instance(path: &Path) -> Result<InstanceLock, String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|err| err.to_string())?;
        }
    }
    let file = File::create(path).map_err(|err| format!("open {}: {err}", path.display()))?;
    match file.try_lock() {
        Ok(()) => Ok(InstanceLock { _file: file }),
        Err(TryLockError::WouldBlock) => Err("another netcheck daemon is already running".into()),
        Err(TryLockError::Error(err)) => Err(format!("lock {}: {err}", path.display())),
    }
}

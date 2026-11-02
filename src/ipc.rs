//! The daemon's local API: `top` over a Unix socket. Windows will use a named
//! pipe; until then these calls fail there.

use crate::live::{LiveWindow, TopReport};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
#[cfg(unix)]
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
#[cfg(unix)]
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
#[cfg(unix)]
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub fn socket_path(db: &Path) -> PathBuf {
    db.with_file_name("netcheck.sock")
}

#[cfg(not(unix))]
pub fn serve(_db: &Path, _live: Arc<Mutex<LiveWindow>>, _watched: Arc<AtomicU64>) -> Result<(), String> {
    Ok(())
}

#[cfg(not(unix))]
pub fn fetch_top(_db: &Path) -> Result<TopReport, String> {
    Err("top is not supported on this OS yet".into())
}

/// Serve `top`. Each request stamps `watched`, which keeps the meter at live
/// cadence for a while.
#[cfg(unix)]
pub fn serve(db: &Path, live: Arc<Mutex<LiveWindow>>, watched: Arc<AtomicU64>) -> Result<(), String> {
    let path = socket_path(db);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|err| err.to_string())?;
        }
    }
    if path.as_os_str().len() >= 104 {
        return Err(format!("socket path is too long: {}", path.display()));
    }
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).map_err(|err| format!("bind {}: {err}", path.display()))?;
    crate::platform::share_with_readers(&path);
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(stream) = conn else { continue };
            let live = Arc::clone(&live);
            let watched = Arc::clone(&watched);
            std::thread::spawn(move || handle(stream, &live, &watched));
        }
    });
    Ok(())
}

#[cfg(unix)]
pub fn fetch_top(db: &Path) -> Result<TopReport, String> {
    let path = socket_path(db);
    let mut stream = UnixStream::connect(&path).map_err(|_| "daemon is not running".to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|err| err.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|err| err.to_string())?;
    stream
        .write_all(b"top\n")
        .map_err(|err| err.to_string())?;
    let mut body = String::new();
    stream
        .read_to_string(&mut body)
        .map_err(|err| err.to_string())?;
    serde_json::from_str(body.trim()).map_err(|err| format!("bad top reply: {err}"))
}

#[cfg(unix)]
fn handle(mut stream: UnixStream, live: &Mutex<LiveWindow>, watched: &AtomicU64) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let mut buf = [0u8; 32];
    let Ok(n) = stream.read(&mut buf) else { return };
    let cmd = String::from_utf8_lossy(&buf[..n]);
    if cmd.trim() != "top" {
        return;
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    watched.store(now, Ordering::Relaxed);
    let Ok(mut window) = live.lock() else { return };
    let report = window.snapshot(now);
    drop(window);
    if let Ok(body) = serde_json::to_string(&report) {
        let _ = stream.write_all(body.as_bytes());
        let _ = stream.write_all(b"\n");
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::engine::{AppDelta, Buckets};
    use crate::live::LiveWindow;

    #[test]
    fn top_round_trip_over_the_socket() {
        let root = std::env::temp_dir().join(format!("netcheck-ipc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let db = root.join("netcheck.db");
        let live = Arc::new(Mutex::new(LiveWindow::new()));
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        live.lock().unwrap().push(
            now,
            &[AppDelta {
                app_key: "/usr/bin/curl".into(),
                display_name: "curl".into(),
                group_key: "/usr/bin/curl".into(),
                group_name: "curl".into(),
                hour: 1,
                buckets: Buckets {
                    internet_rx: 40,
                    internet_tx: 2,
                    ..Buckets::default()
                },
            }],
        );
        let watched = Arc::new(AtomicU64::new(0));
        serve(&db, Arc::clone(&live), Arc::clone(&watched)).unwrap();
        let report = fetch_top(&db).expect("top");
        assert!(watched.load(Ordering::Relaxed) >= now, "a top request marks the daemon as watched");
        assert_eq!(report.rows[0].name, "curl");
        assert_eq!(report.rows[0].rx, 40);
        let _ = std::fs::remove_dir_all(&root);
    }
}

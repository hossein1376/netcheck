use crate::engine::{default_exclude, AppDelta, Buckets, Engine, Sample};
use crate::frame::{read_magic, read_sample, FrameError};
use crate::ifaces::local_prefixes;
use crate::live::LiveWindow;
use crate::store::Store;
use serde::Serialize;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static STOP: AtomicBool = AtomicBool::new(false);

const FLUSH_EVERY: Duration = Duration::from_secs(30);
const STATUS_EVERY: Duration = Duration::from_secs(10);

extern "C" fn handle_stop(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

pub fn default_db_path() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join("Library/Application Support/netcheck/netcheck.db")
}

pub fn meter_path() -> PathBuf {
    if let Some(path) = std::env::var_os("NETCHECK_METER") {
        return PathBuf::from(path);
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let beside = dir.join("nstat_meter");
            if beside.exists() {
                return beside;
            }
        }
    }
    PathBuf::from(env!("NETCHECK_METER_DEFAULT"))
}

pub fn run_daemon(db: &Path) -> Result<(), String> {
    unsafe {
        libc::signal(libc::SIGINT, handle_stop as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, handle_stop as *const () as libc::sighandler_t);
    }

    // Held until exit. A second daemon would steal the socket and double count.
    let _lock = lock_instance(db)?;
    let store = Store::open(db).map_err(|err| err.to_string())?;
    let live = Arc::new(Mutex::new(LiveWindow::new()));
    crate::ipc::serve(db, Arc::clone(&live))?;
    let mut engine = Engine::new(default_exclude());
    let mut pending = Pending::default();
    let mut last_flush = Instant::now();
    let mut last_flush_unix = None;
    let mut backoff = Duration::from_secs(1);

    loop {
        if STOP.load(Ordering::SeqCst) {
            flush_pending(&store, &mut pending, db, None, "down", &mut last_flush_unix)?;
            return Ok(());
        }
        match supervise(
            &store,
            db,
            &mut engine,
            &mut pending,
            &mut last_flush,
            &mut last_flush_unix,
            &live,
            &mut backoff,
        ) {
            Ok(()) => return Ok(()),
            Err(err) => {
                eprintln!("meter stopped: {err}");
                write_status(db, "down", 0, last_flush_unix);
                if STOP.load(Ordering::SeqCst) {
                    flush_pending(&store, &mut pending, db, None, "down", &mut last_flush_unix)?;
                    return Ok(());
                }
                std::thread::sleep(backoff);
                backoff = (backoff * 2).min(Duration::from_secs(10));
            }
        }
    }
}

pub fn lock_path(db: &Path) -> PathBuf {
    db.with_file_name("netcheck.lock")
}

fn lock_instance(db: &Path) -> Result<File, String> {
    let path = lock_path(db);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|err| err.to_string())?;
        }
    }
    let file = File::create(&path).map_err(|err| format!("open {}: {err}", path.display()))?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(format!(
            "another netcheck daemon is already using {}",
            db.display()
        ));
    }
    Ok(file)
}

/// Deltas not yet written, merged per app and hour so a long database outage
/// holds one entry per app-hour instead of one per sample.
#[derive(Default)]
struct Pending {
    apps: HashMap<(i64, String), (String, Buckets)>,
    encap: HashMap<i64, (u64, u64)>,
}

impl Pending {
    fn add(&mut self, apps: Vec<AppDelta>) {
        for app in apps {
            let entry = self
                .apps
                .entry((app.hour, app.app_key))
                .or_insert_with(|| (app.display_name.clone(), Buckets::default()));
            entry.0 = app.display_name;
            entry.1.merge(&app.buckets);
        }
    }

    fn is_empty(&self) -> bool {
        self.apps.is_empty() && self.encap.is_empty()
    }
}

fn supervise(
    store: &Store,
    db: &Path,
    engine: &mut Engine,
    pending: &mut Pending,
    last_flush: &mut Instant,
    last_flush_unix: &mut Option<u64>,
    live: &Mutex<LiveWindow>,
    backoff: &mut Duration,
) -> Result<(), String> {
    let meter = meter_path();
    if !meter.exists() {
        return Err(format!("meter binary is missing at {}", meter.display()));
    }
    let mut child = Command::new(&meter)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("failed to start {}: {err}", meter.display()))?;
    if let Some(stderr) = child.stderr.take() {
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines() {
                if let Ok(line) = line {
                    eprintln!("meter: {line}");
                }
            }
        });
    }
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| "meter stdout is missing".to_string())?;
    read_magic(&mut stdout).map_err(|err| err.to_string())?;
    // Source ids restart with each meter run.
    engine.reset_flows();

    let mut prefixes = local_prefixes();
    let mut samples: u64 = 0;
    let mut last_status: Option<Instant> = None;
    loop {
        if STOP.load(Ordering::SeqCst) {
            let _ = child.kill();
            let _ = child.wait();
            flush_pending(store, pending, db, None, "down", last_flush_unix)?;
            return Ok(());
        }
        let sockets = match read_sample(&mut stdout) {
            Ok(sockets) => sockets,
            Err(err) => {
                let _ = child.kill();
                let _ = child.wait();
                if STOP.load(Ordering::SeqCst) {
                    flush_pending(store, pending, db, None, "down", last_flush_unix)?;
                    return Ok(());
                }
                return Err(frame_message(err));
            }
        };
        samples += 1;
        if samples == 1 {
            *backoff = Duration::from_secs(1);
        }
        if samples % 60 == 1 {
            prefixes = local_prefixes();
        }
        let count = sockets.len();
        let sample = Sample { sockets };
        let (apps, encap_rx, encap_tx) = engine.ingest(&sample, SystemTime::now(), &prefixes);
        let hour = apps.first().map(|app| app.hour).unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as i64 / 3600)
                .unwrap_or(0)
        });
        if encap_rx > 0 || encap_tx > 0 {
            let entry = pending.encap.entry(hour).or_insert((0, 0));
            entry.0 += encap_rx;
            entry.1 += encap_tx;
        }
        if let Ok(mut window) = live.lock() {
            window.push(unix_now(), &apps);
        }
        pending.add(apps);
        if last_flush.elapsed() >= FLUSH_EVERY {
            *last_flush = Instant::now();
            // A failed write keeps the deltas for the next try. The meter is fine.
            if let Err(err) = flush_pending(store, pending, db, Some(count), "up", last_flush_unix) {
                eprintln!("{err}");
            }
            last_status = Some(Instant::now());
        }
        if last_status.map_or(true, |at| at.elapsed() >= STATUS_EVERY) {
            write_status(db, "up", count, *last_flush_unix);
            last_status = Some(Instant::now());
        }
    }
}

fn frame_message(err: FrameError) -> String {
    err.to_string()
}

/// Write all pending deltas in one transaction. They are kept if it fails.
fn flush_pending(
    store: &Store,
    pending: &mut Pending,
    db: &Path,
    sockets: Option<usize>,
    meter: &str,
    last_flush_unix: &mut Option<u64>,
) -> Result<(), String> {
    if !pending.is_empty() {
        let apps: Vec<AppDelta> = pending
            .apps
            .iter()
            .map(|((hour, app_key), (display_name, buckets))| AppDelta {
                app_key: app_key.clone(),
                display_name: display_name.clone(),
                hour: *hour,
                buckets: *buckets,
            })
            .collect();
        store
            .flush(&apps, &pending.encap)
            .map_err(|err| format!("database write failed, will retry: {err}"))?;
        pending.apps.clear();
        pending.encap.clear();
    }
    let now = unix_now();
    *last_flush_unix = Some(now);
    let count = sockets.unwrap_or(0);
    if sockets.is_some() || meter == "down" {
        write_status(db, meter, count, *last_flush_unix);
    }
    Ok(())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Serialize)]
struct StatusFile {
    backend: &'static str,
    meter: String,
    last_sample_unix: u64,
    last_flush_unix: Option<u64>,
    last_socket_count: usize,
    db: String,
}

pub fn status_path(db: &Path) -> PathBuf {
    db.with_file_name("status.json")
}

fn write_status(db: &Path, meter: &str, sockets: usize, last_flush_unix: Option<u64>) {
    let status = StatusFile {
        backend: "networkstatistics",
        meter: meter.to_string(),
        last_sample_unix: unix_now(),
        last_flush_unix,
        last_socket_count: sockets,
        db: db.display().to_string(),
    };
    let Ok(body) = serde_json::to_string_pretty(&status) else {
        return;
    };
    let path = status_path(db);
    let tmp = path.with_extension("json.tmp");
    if std::fs::write(&tmp, body).is_ok() {
        let _ = std::fs::rename(&tmp, &path);
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use std::process::Stdio;

    #[test]
    fn a_second_daemon_cannot_take_the_lock() {
        let root = std::env::temp_dir().join(format!("netcheck-lock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let db = root.join("netcheck.db");
        let held = lock_instance(&db).expect("first lock");
        assert!(lock_instance(&db).is_err());
        drop(held);
        assert!(lock_instance(&db).is_ok());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn meter_sample_names_a_process() {
        let path = env!("NETCHECK_METER_DEFAULT");
        if path.is_empty() {
            return;
        }
        let mut child = Command::new(path)
            .arg("--once")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn meter");
        let pid = child.id() as i32;
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(8));
            unsafe { libc::kill(pid, libc::SIGKILL) };
        });
        let mut stdout = child.stdout.take().expect("stdout");
        read_magic(&mut stdout).expect("magic");
        let found = loop {
            match read_sample(&mut stdout) {
                Ok(rows) if rows.is_empty() => continue,
                Ok(rows) => break rows,
                Err(err) => panic!("meter frame: {err}"),
            }
        };
        let _ = child.kill();
        let _ = child.wait();
        assert!(
            found.iter().any(|sock| sock.pid > 0 && !sock.name.is_empty()),
            "expected a named process, got {} rows",
            found.len()
        );
    }
}

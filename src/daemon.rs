use crate::engine::{default_exclude, AppDelta, Engine, Sample};
use crate::live::LiveWindow;
use crate::meter::{self, Cadence, Meter, SocketCount};
use crate::classify::Prefix;
use crate::platform::{self, local_prefixes, stop_requested};
use crate::store::Store;
use serde::Serialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const FLUSH_EVERY: Duration = Duration::from_secs(30);
const STATUS_EVERY: Duration = Duration::from_secs(10);
/// How long the meter stays at live cadence after a `top` request.
const LIVE_FOR: u64 = 60;

pub fn default_db_path() -> PathBuf {
    platform::data_dir().join("netcheck.db")
}

pub fn lock_path(db: &Path) -> PathBuf {
    db.with_file_name("netcheck.lock")
}

pub fn status_path(db: &Path) -> PathBuf {
    db.with_file_name("status.json")
}

pub fn run_daemon(db: &Path) -> Result<(), String> {
    platform::on_stop_signal();
    // Held until exit. A second daemon would steal the socket and double count.
    let _lock = platform::lock_instance(&lock_path(db))
        .map_err(|err| format!("{err} for {}", db.display()))?;
    let store = Store::open(db).map_err(|err| err.to_string())?;
    let live = Arc::new(Mutex::new(LiveWindow::new()));
    let watched = Arc::new(AtomicU64::new(0));
    crate::ipc::serve(db, Arc::clone(&live), Arc::clone(&watched))?;
    let mut daemon = Daemon {
        store,
        db,
        live,
        watched,
        engine: Engine::new(default_exclude()),
        pending: Pending::default(),
        last_flush: Instant::now(),
        last_flush_unix: None,
        backend: "none",
    };
    let mut backoff = Duration::from_secs(1);

    loop {
        if stop_requested() {
            return daemon.flush("down", None);
        }
        let err = match meter::open() {
            Ok(meter) => match daemon.run_meter(meter, &mut backoff) {
                Ok(()) => return Ok(()),
                Err(err) => err,
            },
            Err(err) => err,
        };
        eprintln!("meter stopped: {err}");
        daemon.write_status("down", 0);
        if stop_requested() {
            return daemon.flush("down", None);
        }
        std::thread::sleep(backoff);
        backoff = (backoff * 2).min(Duration::from_secs(10));
    }
}

struct Daemon<'a> {
    store: Store,
    db: &'a Path,
    live: Arc<Mutex<LiveWindow>>,
    /// Unix time of the last live-data request.
    watched: Arc<AtomicU64>,
    engine: Engine,
    pending: Pending,
    last_flush: Instant,
    last_flush_unix: Option<u64>,
    backend: &'static str,
}

impl Daemon<'_> {
    /// Ingest samples until the meter fails or a stop is requested.
    fn run_meter(&mut self, mut meter: Box<dyn Meter>, backoff: &mut Duration) -> Result<(), String> {
        self.backend = meter.backend();
        // Source ids restart with each meter run.
        self.engine.reset_flows();
        let mut prefixes = local_prefixes();
        let mut samples: u64 = 0;
        let mut last_status: Option<Instant> = None;
        let mut cadence = Cadence::Idle;
        loop {
            if stop_requested() {
                // Collect the last interval before the meter goes away.
                if let Ok(sockets) = meter.snapshot_now() {
                    self.ingest(sockets, &prefixes);
                }
                drop(meter);
                return self.flush("down", None);
            }
            let wanted = if unix_now().saturating_sub(self.watched.load(Ordering::Relaxed)) < LIVE_FOR {
                Cadence::Live
            } else {
                Cadence::Idle
            };
            if wanted != cadence {
                meter.set_cadence(wanted)?;
                cadence = wanted;
            }
            let sockets = match meter.next_sample() {
                Ok(sockets) => sockets,
                Err(err) => {
                    drop(meter);
                    if stop_requested() {
                        return self.flush("down", None);
                    }
                    return Err(err);
                }
            };
            samples += 1;
            if samples == 1 {
                *backoff = Duration::from_secs(1);
            }
            if samples % 60 == 1 {
                prefixes = local_prefixes();
            }
            let count = self.ingest(sockets, &prefixes);
            if self.last_flush.elapsed() >= FLUSH_EVERY {
                self.last_flush = Instant::now();
                // A failed write keeps the deltas for the next try. The meter is fine.
                if let Err(err) = self.flush("up", Some(count)) {
                    eprintln!("{err}");
                }
                last_status = Some(Instant::now());
            }
            if last_status.map_or(true, |at| at.elapsed() >= STATUS_EVERY) {
                self.write_status("up", count);
                last_status = Some(Instant::now());
            }
        }
    }

    /// Fold one snapshot into pending deltas and the live window. Returns the
    /// number of sockets it reported.
    fn ingest(&mut self, sockets: Vec<SocketCount>, prefixes: &[Prefix]) -> usize {
        let count = sockets.len();
        let now = SystemTime::now();
        let (apps, encap_rx, encap_tx) = self.engine.ingest(&Sample { sockets }, now, prefixes);
        if encap_rx > 0 || encap_tx > 0 {
            let entry = self.pending.encap.entry(crate::engine::hour_index(now)).or_insert((0, 0));
            entry.0 += encap_rx;
            entry.1 += encap_tx;
        }
        if let Ok(mut window) = self.live.lock() {
            window.push(unix_now(), &apps);
        }
        self.pending.add(apps);
        count
    }

    /// Write all pending deltas in one transaction. They are kept if it fails.
    fn flush(&mut self, meter: &str, sockets: Option<usize>) -> Result<(), String> {
        if !self.pending.is_empty() {
            let apps: Vec<AppDelta> = self.pending.apps.values().cloned().collect();
            self.store
                .flush(&apps, &self.pending.encap)
                .map_err(|err| format!("database write failed, will retry: {err}"))?;
            self.pending.apps.clear();
            self.pending.encap.clear();
        }
        self.last_flush_unix = Some(unix_now());
        if sockets.is_some() || meter == "down" {
            self.write_status(meter, sockets.unwrap_or(0));
        }
        Ok(())
    }

    fn write_status(&self, meter: &str, sockets: usize) {
        let status = StatusFile {
            backend: self.backend,
            meter: meter.to_string(),
            last_sample_unix: unix_now(),
            last_flush_unix: self.last_flush_unix,
            last_socket_count: sockets,
            db: self.db.display().to_string(),
        };
        let Ok(body) = serde_json::to_string_pretty(&status) else {
            return;
        };
        let path = status_path(self.db);
        let tmp = path.with_extension("json.tmp");
        if std::fs::write(&tmp, body).is_ok() {
            let _ = std::fs::rename(&tmp, &path);
        }
    }
}

/// Deltas not yet written, merged per app and hour so a long database outage
/// holds one entry per app-hour instead of one per sample.
#[derive(Default)]
struct Pending {
    apps: HashMap<(i64, String), AppDelta>,
    encap: HashMap<i64, (u64, u64)>,
}

impl Pending {
    fn add(&mut self, apps: Vec<AppDelta>) {
        for app in apps {
            match self.apps.get_mut(&(app.hour, app.app_key.clone())) {
                Some(entry) => {
                    entry.buckets.merge(&app.buckets);
                    entry.display_name = app.display_name;
                    entry.group_key = app.group_key;
                    entry.group_name = app.group_name;
                }
                None => {
                    self.apps.insert((app.hour, app.app_key.clone()), app);
                }
            }
        }
    }

    fn is_empty(&self) -> bool {
        self.apps.is_empty() && self.encap.is_empty()
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_second_daemon_cannot_take_the_lock() {
        let root = std::env::temp_dir().join(format!("netcheck-lock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let path = lock_path(&root.join("netcheck.db"));
        let held = platform::lock_instance(&path).expect("first lock");
        assert!(platform::lock_instance(&path).is_err());
        drop(held);
        assert!(platform::lock_instance(&path).is_ok());
        let _ = std::fs::remove_dir_all(&root);
    }
}

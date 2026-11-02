//! The meter contract. Each OS supplies a [`Meter`] that reports cumulative
//! per-socket counters. Everything after that is shared. See docs/DESIGN.md.

use std::net::SocketAddr;

pub mod frame;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::meter_path;

/// Cumulative bytes split by the kind of link they crossed. Bytes on a VPN
/// tunnel, loopback, or an unknown link are in the totals but none of these.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct Links {
    pub wifi_rx: u64,
    pub wifi_tx: u64,
    pub wired_rx: u64,
    pub wired_tx: u64,
    pub cellular_rx: u64,
    pub cellular_tx: u64,
}

impl Links {
    /// Each field minus `earlier`'s, saturating at zero.
    pub fn since(&self, earlier: &Links) -> Links {
        Links {
            wifi_rx: self.wifi_rx.saturating_sub(earlier.wifi_rx),
            wifi_tx: self.wifi_tx.saturating_sub(earlier.wifi_tx),
            wired_rx: self.wired_rx.saturating_sub(earlier.wired_rx),
            wired_tx: self.wired_tx.saturating_sub(earlier.wired_tx),
            cellular_rx: self.cellular_rx.saturating_sub(earlier.cellular_rx),
            cellular_tx: self.cellular_tx.saturating_sub(earlier.cellular_tx),
        }
    }

    pub fn add(&mut self, other: &Links) {
        self.wifi_rx += other.wifi_rx;
        self.wifi_tx += other.wifi_tx;
        self.wired_rx += other.wired_rx;
        self.wired_tx += other.wired_tx;
        self.cellular_rx += other.cellular_rx;
        self.cellular_tx += other.cellular_tx;
    }
}

/// One cumulative socket counter from a meter.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SocketCount {
    /// Meter-assigned id. Unique for one meter run.
    pub source: u64,
    /// The socket opened after the meter started, so its counters are all new usage.
    pub new: bool,
    /// The socket is closed. This is its last report.
    pub closed: bool,
    pub pid: u32,
    pub start_time: u64,
    pub proto: Proto,
    pub name: String,
    pub local: Option<SocketAddr>,
    pub remote: Option<SocketAddr>,
    pub rx: u64,
    pub tx: u64,
    /// Executable path, read by the meter when it first saw the socket.
    pub path: Option<String>,
    /// The process this socket works for, when that is another process
    /// (WebKit for Safari, nsurlsessiond for an app). 0 otherwise.
    pub effective_pid: u32,
    pub effective_path: Option<String>,
    /// The same bytes as `rx` and `tx`, split by link kind.
    pub links: Links,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum Proto {
    #[default]
    Tcp,
    Udp,
}

/// How often a meter takes snapshots. A closed socket waits for the next
/// snapshot either way, so a slower cadence loses no bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cadence {
    /// Nobody is watching: every 10 s.
    Idle,
    /// A live view is open: every second.
    Live,
}

/// A source of socket snapshots for one meter run.
///
/// Rules every meter keeps:
/// - A snapshot holds every socket on its first report, then only sockets
///   whose counters changed. A socket missing from a snapshot is unchanged.
/// - A closed socket is reported once more with `closed` set and its final
///   counters, then never again.
/// - `source` ids are unique for the life of the meter and never reused.
/// - Counters are cumulative from the later of socket open or meter start, and
///   never decrease. `new` is true when no counted byte predates the meter.
/// - The first snapshot comes within about a second of the start, at
///   [`Cadence::Idle`] after that.
///
/// Dropping the meter ends the run. A new meter starts a new run with new ids.
pub trait Meter {
    /// Short name of the OS source, shown in `netcheck status`.
    fn backend(&self) -> &'static str;

    /// Block until the next snapshot.
    fn next_sample(&mut self) -> Result<Vec<SocketCount>, String>;

    fn set_cadence(&mut self, cadence: Cadence) -> Result<(), String>;

    /// Take a snapshot now and return everything reported up to it. Used
    /// when a stop is noticed between snapshots, so the last interval is kept.
    fn snapshot_now(&mut self) -> Result<Vec<SocketCount>, String>;
}

/// Start this OS's meter.
pub fn open() -> Result<Box<dyn Meter>, String> {
    #[cfg(target_os = "macos")]
    {
        return Ok(Box::new(macos::NstatMeter::spawn()?));
    }
    #[cfg(target_os = "linux")]
    {
        return Ok(Box::new(linux::EbpfMeter::open()?));
    }
    #[allow(unreachable_code)]
    Err(format!("no meter for {} yet", std::env::consts::OS))
}

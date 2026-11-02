//! The meter contract. Each OS supplies a [`Meter`] that reports cumulative
//! per-socket counters. Everything after that is shared. See docs/DESIGN.md.

use std::net::SocketAddr;

pub mod frame;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::meter_path;

/// One cumulative socket counter from a meter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketCount {
    /// Meter-assigned id. Unique for one meter run.
    pub source: u64,
    /// The socket opened after the meter started, so its counters are all new usage.
    pub new: bool,
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Proto {
    Tcp,
    Udp,
}

/// A source of socket snapshots for one meter run.
///
/// Rules every meter keeps:
/// - `next_sample` blocks until the next snapshot, about once a second, and
///   returns every live socket.
/// - `source` ids are unique for the life of the meter and never reused.
/// - Counters are cumulative from the later of socket open or meter start, and
///   never decrease. `new` is true when no counted byte predates the meter.
/// - A closed socket appears in one more snapshot with its final counters.
///
/// Dropping the meter ends the run. A new meter starts a new run with new ids.
pub trait Meter {
    /// Short name of the OS source, shown in `netcheck status`.
    fn backend(&self) -> &'static str;

    fn next_sample(&mut self) -> Result<Vec<SocketCount>, String>;
}

/// Start this OS's meter.
pub fn open() -> Result<Box<dyn Meter>, String> {
    #[cfg(target_os = "macos")]
    {
        return Ok(Box::new(macos::NstatMeter::spawn()?));
    }
    #[allow(unreachable_code)]
    Err(format!("no meter for {} yet", std::env::consts::OS))
}

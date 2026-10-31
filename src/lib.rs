//! Core of netcheck. The OS meter only supplies cumulative socket counters.
//! Diff, classification, and storage live here.

mod classify;
mod daemon;
mod diff;
mod engine;
mod frame;
mod ifaces;
mod install;
mod ipc;
mod live;
mod procpath;
mod query;
mod store;

pub use classify::{classify, Prefix, Scope};
pub use daemon::{default_db_path, meter_path, run_daemon, status_path};
pub use install::{install, uninstall};
pub use ipc::fetch_top;
pub use diff::{Delta, Diff, FlowKey};
pub use engine::{Engine, Sample};
pub use frame::{decode_sample, SocketCount};
pub use query::{min_hour, parse_since, UsageRow};
pub use store::Store;

//! Core of netcheck. The OS meter only supplies cumulative socket counters.
//! Diff, classification, grouping, and storage live here.

mod classify;
mod daemon;
mod diff;
mod engine;
mod group;
mod ipc;
mod live;
pub mod meter;
pub mod platform;
mod query;
mod store;

pub use classify::{classify, Prefix, Scope};
pub use daemon::{default_db_path, lock_path, run_daemon, status_path};
pub use diff::{Delta, Diff, FlowKey};
pub use engine::{Engine, Sample};
pub use group::group_of;
pub use ipc::fetch_top;
pub use meter::{frame::decode_sample, Links, Meter, SocketCount};
pub use query::{min_hour, parse_since, TunnelRow, UsageRow};
pub use store::{By, Store, SCHEMA_VERSION};

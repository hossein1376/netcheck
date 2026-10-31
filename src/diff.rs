use crate::frame::{Proto, SocketCount};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub pid: u32,
    pub start_time: u64,
    pub proto: Proto,
    pub local: Option<SocketAddr>,
    pub remote: Option<SocketAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Delta {
    pub rx: u64,
    pub tx: u64,
    /// True the first time this flow is seen. `rx` and `tx` are zero then.
    pub fresh: bool,
}

#[derive(Debug)]
pub struct Diff {
    prev: HashMap<FlowKey, (u64, u64)>,
    /// Unix seconds when watching began. Older processes are baselined.
    watch_start: u64,
}

impl Diff {
    pub fn new() -> Self {
        let watch_start = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self {
            prev: HashMap::new(),
            watch_start,
        }
    }

    pub fn key_of(sock: &SocketCount) -> FlowKey {
        FlowKey {
            pid: sock.pid,
            start_time: sock.start_time,
            proto: sock.proto,
            local: sock.local,
            remote: sock.remote,
        }
    }

    /// Observe one cumulative counter. The first sight emits a zero delta.
    pub fn observe(&mut self, sock: &SocketCount) -> Delta {
        let key = Self::key_of(sock);
        let Some((prev_rx, prev_tx)) = self.prev.get(&key).copied() else {
            self.prev.insert(key, (sock.rx, sock.tx));
            // A process that started with the daemon has no pre-watch history.
            // Its first sample is the usage so far, including a transfer that
            // finishes inside one poll.
            if sock.start_time > 0 && sock.start_time.saturating_add(2) >= self.watch_start {
                return Delta {
                    rx: sock.rx,
                    tx: sock.tx,
                    fresh: false,
                };
            }
            return Delta {
                rx: 0,
                tx: 0,
                fresh: true,
            };
        };
        let delta = if sock.rx < prev_rx || sock.tx < prev_tx {
            Delta {
                rx: sock.rx,
                tx: sock.tx,
                fresh: false,
            }
        } else {
            Delta {
                rx: sock.rx - prev_rx,
                tx: sock.tx - prev_tx,
                fresh: false,
            }
        };
        self.prev.insert(key, (sock.rx, sock.tx));
        delta
    }

    /// Drop flows that were not in this sample. They emit nothing.
    pub fn finish_sample(&mut self, seen: &HashSet<FlowKey>) {
        self.prev.retain(|key, _| seen.contains(key));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sock(rx: u64, tx: u64) -> SocketCount {
        SocketCount {
            pid: 7,
            start_time: 10,
            proto: Proto::Tcp,
            name: "curl".into(),
            local: Some("10.0.0.2:9".parse().unwrap()),
            remote: Some("1.1.1.1:443".parse().unwrap()),
            rx,
            tx,
        }
    }

    #[test]
    fn first_sight_is_a_baseline() {
        let mut diff = Diff::new();
        let delta = diff.observe(&sock(50_000, 1_000));
        assert_eq!(delta, Delta { rx: 0, tx: 0, fresh: true });
    }

    #[test]
    fn later_sight_is_the_increase() {
        let mut diff = Diff::new();
        diff.observe(&sock(50_000, 1_000));
        let delta = diff.observe(&sock(51_500, 1_200));
        assert_eq!(delta, Delta { rx: 1_500, tx: 200, fresh: false });
    }

    #[test]
    fn a_drop_is_a_reused_socket() {
        let mut diff = Diff::new();
        diff.observe(&sock(50_000, 1_000));
        let delta = diff.observe(&sock(100, 40));
        assert_eq!(delta, Delta { rx: 100, tx: 40, fresh: false });
    }

    #[test]
    fn a_new_start_time_is_a_new_flow() {
        let mut diff = Diff::new();
        diff.observe(&sock(50_000, 1_000));
        let mut reused = sock(50_000, 1_000);
        reused.start_time = 11;
        let delta = diff.observe(&reused);
        assert!(delta.fresh);
        assert_eq!(delta.rx, 0);
    }

    #[test]
    fn a_flow_that_vanishes_emits_nothing() {
        let mut diff = Diff::new();
        let first = sock(10, 10);
        diff.observe(&first);
        diff.finish_sample(&HashSet::from([Diff::key_of(&first)]));
        diff.finish_sample(&HashSet::new());
        let again = diff.observe(&sock(80, 80));
        assert!(again.fresh, "a vanished flow must not bill its old life");
        assert_eq!(again.rx, 0);
    }
}

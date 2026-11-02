use crate::meter::SocketCount;
use std::collections::HashMap;

/// A meter source. Ids are unique within one meter run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub source: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Delta {
    pub rx: u64,
    pub tx: u64,
    /// True the first time a pre-existing flow is seen. `rx` and `tx` are zero then.
    pub fresh: bool,
}

/// Turns cumulative counters into deltas. Use one per meter run.
#[derive(Debug, Default)]
pub struct Diff {
    prev: HashMap<FlowKey, (u64, u64)>,
}

impl Diff {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn key_of(sock: &SocketCount) -> FlowKey {
        FlowKey {
            source: sock.source,
        }
    }

    /// Observe one cumulative counter.
    pub fn observe(&mut self, sock: &SocketCount) -> Delta {
        let key = Self::key_of(sock);
        let Some((prev_rx, prev_tx)) = self.prev.get(&key).copied() else {
            self.prev.insert(key, (sock.rx, sock.tx));
            // A socket opened after the meter started has no history before
            // the watch. Its counters so far are usage, including a transfer
            // that finishes inside one poll.
            if sock.new {
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

    /// Forget a closed flow after its final report.
    pub fn forget(&mut self, key: &FlowKey) {
        self.prev.remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::meter::Proto;

    fn sock(rx: u64, tx: u64) -> SocketCount {
        SocketCount {
            source: 1,
            new: false,
            closed: false,
            pid: 7,
            start_time: 10,
            proto: Proto::Tcp,
            name: "curl".into(),
            local: Some("10.0.0.2:9".parse().unwrap()),
            remote: Some("1.1.1.1:443".parse().unwrap()),
            rx,
            tx,
            path: None,
        }
    }

    #[test]
    fn first_sight_of_an_old_socket_is_a_baseline() {
        let mut diff = Diff::new();
        let delta = diff.observe(&sock(50_000, 1_000));
        assert_eq!(delta, Delta { rx: 0, tx: 0, fresh: true });
    }

    #[test]
    fn first_sight_of_a_new_socket_is_all_usage() {
        let mut diff = Diff::new();
        let mut born = sock(50_000, 1_000);
        born.new = true;
        let delta = diff.observe(&born);
        assert_eq!(delta, Delta { rx: 50_000, tx: 1_000, fresh: false });
        born.rx = 50_400;
        assert_eq!(diff.observe(&born).rx, 400);
    }

    #[test]
    fn later_sight_is_the_increase() {
        let mut diff = Diff::new();
        diff.observe(&sock(50_000, 1_000));
        let delta = diff.observe(&sock(51_500, 1_200));
        assert_eq!(delta, Delta { rx: 1_500, tx: 200, fresh: false });
    }

    #[test]
    fn a_drop_is_a_reset_counter() {
        let mut diff = Diff::new();
        diff.observe(&sock(50_000, 1_000));
        let delta = diff.observe(&sock(100, 40));
        assert_eq!(delta, Delta { rx: 100, tx: 40, fresh: false });
    }

    #[test]
    fn an_address_change_keeps_the_flow() {
        let mut diff = Diff::new();
        diff.observe(&sock(50_000, 1_000));
        let mut moved = sock(50_300, 1_000);
        moved.remote = Some("8.8.8.8:443".parse().unwrap());
        let delta = diff.observe(&moved);
        assert_eq!(delta, Delta { rx: 300, tx: 0, fresh: false });
    }

    #[test]
    fn a_flow_missing_from_snapshots_keeps_its_baseline() {
        let mut diff = Diff::new();
        diff.observe(&sock(10, 10));
        // Unchanged for a few snapshots, so not reported, then it moves.
        let later = diff.observe(&sock(80, 10));
        assert_eq!(later, Delta { rx: 70, tx: 0, fresh: false });
    }

    #[test]
    fn a_forgotten_flow_starts_over() {
        let mut diff = Diff::new();
        let first = sock(10, 10);
        diff.observe(&first);
        diff.forget(&Diff::key_of(&first));
        let again = diff.observe(&sock(80, 80));
        assert!(again.fresh, "a forgotten flow must not bill its old life");
    }
}

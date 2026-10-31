use crate::engine::AppDelta;
use serde::Serialize;
use std::collections::{HashMap, VecDeque};

const WINDOW_SECS: u64 = 60;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct TopRow {
    pub app_key: String,
    pub display_name: String,
    pub rx: u64,
    pub tx: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct TopReport {
    pub window_secs: u64,
    pub rows: Vec<TopRow>,
}

#[derive(Debug, Default)]
pub struct LiveWindow {
    ticks: VecDeque<Tick>,
}

#[derive(Debug)]
struct Tick {
    unix: u64,
    rows: Vec<TopRow>,
}

impl LiveWindow {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, unix: u64, apps: &[AppDelta]) {
        let rows: Vec<TopRow> = apps
            .iter()
            .filter_map(|app| {
                let rx = app.buckets.internet_rx + app.buckets.unscoped_rx;
                let tx = app.buckets.internet_tx + app.buckets.unscoped_tx;
                if rx == 0 && tx == 0 {
                    return None;
                }
                Some(TopRow {
                    app_key: app.app_key.clone(),
                    display_name: app.display_name.clone(),
                    rx,
                    tx,
                })
            })
            .collect();
        if rows.is_empty() {
            return;
        }
        self.ticks.push_back(Tick { unix, rows });
        self.expire(unix);
    }

    pub fn snapshot(&mut self, now: u64) -> TopReport {
        self.expire(now);
        let mut totals: HashMap<String, TopRow> = HashMap::new();
        let mut oldest = now;
        for tick in &self.ticks {
            oldest = oldest.min(tick.unix);
            for row in &tick.rows {
                let total = totals.entry(row.app_key.clone()).or_insert_with(|| TopRow {
                    app_key: row.app_key.clone(),
                    display_name: row.display_name.clone(),
                    rx: 0,
                    tx: 0,
                });
                total.display_name = row.display_name.clone();
                total.rx += row.rx;
                total.tx += row.tx;
            }
        }
        let window_secs = if self.ticks.is_empty() {
            WINDOW_SECS
        } else {
            (now.saturating_sub(oldest) + 1).clamp(1, WINDOW_SECS)
        };
        let mut rows: Vec<TopRow> = totals.into_values().collect();
        rows.sort_by(|a, b| (b.rx + b.tx).cmp(&(a.rx + a.tx)).then(a.display_name.cmp(&b.display_name)));
        TopReport { window_secs, rows }
    }

    fn expire(&mut self, now: u64) {
        while self
            .ticks
            .front()
            .is_some_and(|tick| now.saturating_sub(tick.unix) > WINDOW_SECS)
        {
            self.ticks.pop_front();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{AppDelta, Buckets};

    fn delta(name: &str, rx: u64, tx: u64) -> AppDelta {
        AppDelta {
            app_key: format!("/usr/bin/{name}"),
            display_name: name.into(),
            hour: 1,
            buckets: Buckets {
                internet_rx: rx,
                internet_tx: tx,
                ..Buckets::default()
            },
        }
    }

    #[test]
    fn sums_samples_inside_the_window() {
        let mut live = LiveWindow::new();
        live.push(1_000, &[delta("curl", 100, 10)]);
        live.push(1_010, &[delta("curl", 50, 5)]);
        let report = live.snapshot(1_030);
        assert_eq!(report.rows.len(), 1);
        assert_eq!(report.rows[0].rx, 150);
        assert_eq!(report.rows[0].tx, 15);
        assert_eq!(report.window_secs, 31);
    }

    #[test]
    fn drops_samples_older_than_60_seconds() {
        let mut live = LiveWindow::new();
        live.push(1_000, &[delta("curl", 100, 0)]);
        live.push(1_070, &[delta("curl", 7, 0)]);
        let report = live.snapshot(1_070);
        assert_eq!(report.rows[0].rx, 7);
    }
}

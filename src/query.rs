use crate::meter::Links;
use serde::Serialize;
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UsageRow {
    /// Group key or `app_key`, depending on how the rows were grouped.
    pub key: String,
    pub name: String,
    pub internet_rx: u64,
    pub internet_tx: u64,
    pub local_rx: u64,
    pub local_tx: u64,
    pub unscoped_rx: u64,
    pub unscoped_tx: u64,
    /// The same bytes across all scopes, split by link kind.
    #[serde(flatten)]
    pub links: Links,
}

/// VPN tunnel bytes over a window, kept out of app totals.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct TunnelRow {
    pub rx: u64,
    pub tx: u64,
    #[serde(flatten)]
    pub links: Links,
}

impl UsageRow {
    pub fn off_machine(&self) -> u64 {
        self.internet_rx + self.internet_tx + self.unscoped_rx + self.unscoped_tx
    }
}

/// Parse `30m`, `24h`, or `7d` into a start time before `now`.
pub fn parse_since(spec: &str, now: SystemTime) -> Result<SystemTime, String> {
    let spec = spec.trim();
    if spec.len() < 2 {
        return Err(format!("bad duration '{spec}'"));
    }
    let (num, unit) = spec.split_at(spec.len() - 1);
    let count: u64 = num
        .parse()
        .map_err(|_| format!("bad duration '{spec}'"))?;
    if count == 0 {
        return Err("duration must be greater than zero".into());
    }
    let seconds = match unit {
        "m" => count * 60,
        "h" => count * 3600,
        "d" => count * 86400,
        _ => return Err(format!("bad duration '{spec}'")),
    };
    now.checked_sub(Duration::from_secs(seconds))
        .ok_or_else(|| "duration is too large".into())
}

pub fn min_hour(since: SystemTime) -> i64 {
    let secs = since
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs() as i64;
    secs.div_euclid(3600)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: u64) -> SystemTime {
        std::time::UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn parses_hours_minutes_and_days() {
        let now = at(1_000_000);
        assert_eq!(parse_since("2h", now).unwrap(), at(1_000_000 - 7200));
        assert_eq!(parse_since("30m", now).unwrap(), at(1_000_000 - 1800));
        assert_eq!(parse_since("1d", now).unwrap(), at(1_000_000 - 86400));
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_since("noon", at(10)).is_err());
        assert!(parse_since("0h", at(10)).is_err());
    }
}

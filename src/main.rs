use clap::{Parser, Subcommand};
use netcheck::{
    default_db_path, fetch_top, min_hour, parse_since, platform, run_daemon, status_path, By, Links,
    Store, TunnelRow, UsageRow,
};
use std::path::PathBuf;
use std::time::SystemTime;

#[derive(Parser)]
#[command(name = "netcheck", about = "Per-app internet usage")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Record socket usage until stopped.
    Daemon {
        #[arg(long)]
        db: Option<PathBuf>,
    },
    /// Show stored usage. Totals cover whole hours that overlap the window.
    Usage {
        #[arg(long)]
        db: Option<PathBuf>,
        #[arg(long, default_value = "24h")]
        since: String,
        #[arg(long)]
        app: Option<String>,
        /// One row per executable instead of per app.
        #[arg(long)]
        by_exe: bool,
        /// Split totals by link: Wi-Fi, wired, cellular, other.
        #[arg(long)]
        links: bool,
        #[arg(long)]
        json: bool,
    },
    /// Show whether the daemon is sampling.
    Status {
        #[arg(long)]
        db: Option<PathBuf>,
    },
    /// Show off-machine usage over the last minute.
    Top {
        #[arg(long)]
        db: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Install the background service.
    Install,
    /// Stop the background service and remove its binaries.
    Uninstall,
}

fn main() {
    let cli = Cli::parse();
    let result = match cli.cmd {
        Cmd::Daemon { db } => {
            let db = db.unwrap_or_else(default_db_path);
            run_daemon(&db)
        }
        Cmd::Usage {
            db,
            since,
            app,
            by_exe,
            links,
            json,
        } => {
            let db = db.unwrap_or_else(default_db_path);
            let by = if by_exe { By::Executable } else { By::App };
            show_usage(&db, &since, app.as_deref(), by, links, json)
        }
        Cmd::Status { db } => {
            let db = db.unwrap_or_else(default_db_path);
            show_status(&db);
            Ok(())
        }
        Cmd::Top { db, json } => {
            let db = db.unwrap_or_else(default_db_path);
            show_top(&db, json)
        }
        Cmd::Install => std::env::current_exe()
            .map_err(|err| err.to_string())
            .and_then(|bin| platform::install(&bin, &default_db_path())),
        Cmd::Uninstall => platform::uninstall(),
    };
    if let Err(err) = result {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn show_usage(
    db: &std::path::Path,
    since: &str,
    app: Option<&str>,
    by: By,
    links: bool,
    json: bool,
) -> Result<(), String> {
    let start = parse_since(since, SystemTime::now())?;
    let store = Store::open_read(db)?;
    let rows = store
        .usage(min_hour(start), app, by)
        .map_err(|err| err.to_string())?;
    let tunnel = store.tunnel(min_hour(start)).map_err(|err| err.to_string())?;
    if json {
        let apps: Vec<UsageJson> = rows
            .iter()
            .map(|row| UsageJson {
                off_machine: row.off_machine(),
                row,
            })
            .collect();
        let body = serde_json::json!({ "apps": apps, "vpn_tunnel": tunnel });
        println!("{}", serde_json::to_string_pretty(&body).unwrap_or_default());
        return Ok(());
    }
    if rows.is_empty() {
        println!("No usage in that window yet.");
        return Ok(());
    }
    if links {
        show_links(&rows, &tunnel);
        return Ok(());
    }
    println!(
        "{:<24} {:>14} {:>14} {:>12} {:>12} {:>12} {:>12}",
        "APP", "INTERNET DOWN", "INTERNET UP", "LOCAL DOWN", "LOCAL UP", "UNSCOPED DN", "UNSCOPED UP"
    );
    for row in &rows {
        println!(
            "{:<24} {:>14} {:>14} {:>12} {:>12} {:>12} {:>12}",
            clip(&row.name, 24),
            fmt_bytes(row.internet_rx),
            fmt_bytes(row.internet_tx),
            fmt_bytes(row.local_rx),
            fmt_bytes(row.local_tx),
            fmt_bytes(row.unscoped_rx),
            fmt_bytes(row.unscoped_tx),
        );
    }
    println!("Off-machine is internet plus unscoped. Hours overlap the window.");
    Ok(())
}

fn show_links(rows: &[UsageRow], tunnel: &TunnelRow) {
    println!(
        "{:<24} {:>11} {:>11} {:>11} {:>11} {:>11} {:>11}",
        "APP", "DOWN", "UP", "WI-FI", "WIRED", "CELLULAR", "OTHER"
    );
    let line = |name: &str, rx: u64, tx: u64, l: &Links| {
        let wifi = l.wifi_rx + l.wifi_tx;
        let wired = l.wired_rx + l.wired_tx;
        let cellular = l.cellular_rx + l.cellular_tx;
        let other = (rx + tx).saturating_sub(wifi + wired + cellular);
        println!(
            "{:<24} {:>11} {:>11} {:>11} {:>11} {:>11} {:>11}",
            clip(name, 24),
            fmt_bytes(rx),
            fmt_bytes(tx),
            fmt_bytes(wifi),
            fmt_bytes(wired),
            fmt_bytes(cellular),
            fmt_bytes(other),
        );
    };
    for row in rows {
        let rx = row.internet_rx + row.local_rx + row.unscoped_rx;
        let tx = row.internet_tx + row.local_tx + row.unscoped_tx;
        line(&row.name, rx, tx, &row.links);
    }
    if tunnel.rx + tunnel.tx > 0 {
        line("(VPN tunnel)", tunnel.rx, tunnel.tx, &tunnel.links);
    }
    println!("Link columns are down plus up. OTHER is a VPN tunnel, loopback, or an unknown link.");
    println!("The VPN tunnel row is the encrypted copy of app traffic; it isn't in app totals.");
}

fn show_top(db: &std::path::Path, json: bool) -> Result<(), String> {
    let report = fetch_top(db)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report).unwrap_or_default());
        return Ok(());
    }
    if report.rows.is_empty() {
        println!("No off-machine usage in the last minute.");
        return Ok(());
    }
    println!(
        "{:<24} {:>12} {:>12} {:>12} {:>12}",
        "APP", "DOWN", "UP", "DOWN/s", "UP/s"
    );
    let secs = report.window_secs.max(1);
    for row in &report.rows {
        println!(
            "{:<24} {:>12} {:>12} {:>12} {:>12}",
            clip(&row.name, 24),
            fmt_bytes(row.rx),
            fmt_bytes(row.tx),
            fmt_bytes(row.rx / secs),
            fmt_bytes(row.tx / secs),
        );
    }
    println!("Last {secs}s. Off-machine is internet plus unscoped.");
    Ok(())
}

fn show_status(db: &std::path::Path) {
    let path = status_path(db);
    match std::fs::read_to_string(&path) {
        Ok(text) => println!("{text}"),
        Err(_) => println!("daemon: not running"),
    }
    match Store::open_read(db) {
        Ok(store) => {
            if let Ok(rows) = store.hour_rows() {
                println!("stored hour rows: {rows}");
            }
        }
        Err(err) => println!("{err}"),
    }
}

#[derive(serde::Serialize)]
struct UsageJson<'a> {
    #[serde(flatten)]
    row: &'a UsageRow,
    off_machine: u64,
}

fn clip(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_string();
    }
    let mut out: String = text.chars().take(width.saturating_sub(1)).collect();
    out.push('~');
    out
}

fn fmt_bytes(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

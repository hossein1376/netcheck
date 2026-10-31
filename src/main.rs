use clap::{Parser, Subcommand};
use netcheck::{
    default_db_path, fetch_top, install, meter_path, min_hour, parse_since, run_daemon, status_path,
    uninstall, Store, UsageRow,
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
    /// Install a LaunchAgent for this user.
    Install,
    /// Stop the LaunchAgent and remove its binaries.
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
            json,
        } => {
            let db = db.unwrap_or_else(default_db_path);
            show_usage(&db, &since, app.as_deref(), json)
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
            .and_then(|bin| install(&bin, &meter_path(), &default_db_path())),
        Cmd::Uninstall => uninstall(),
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
    json: bool,
) -> Result<(), String> {
    let start = parse_since(since, SystemTime::now())?;
    let store = Store::open_read(db).map_err(|_| format!("no database at {}", db.display()))?;
    let rows = store
        .usage(min_hour(start), app)
        .map_err(|err| err.to_string())?;
    if json {
        let body: Vec<UsageJson> = rows
            .iter()
            .map(|row| UsageJson {
                off_machine: row.off_machine(),
                row,
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&body).unwrap_or_default());
        return Ok(());
    }
    if rows.is_empty() {
        println!("No usage in that window yet.");
        return Ok(());
    }
    println!(
        "{:<24} {:>14} {:>14} {:>12} {:>12} {:>12} {:>12}",
        "APP", "INTERNET DOWN", "INTERNET UP", "LOCAL DOWN", "LOCAL UP", "UNSCOPED DN", "UNSCOPED UP"
    );
    for row in &rows {
        println!(
            "{:<24} {:>14} {:>14} {:>12} {:>12} {:>12} {:>12}",
            clip(&row.display_name, 24),
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
            clip(&row.display_name, 24),
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
    if let Ok(store) = Store::open_read(db) {
        if let Ok(rows) = store.hour_rows() {
            println!("stored hour rows: {rows}");
        }
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

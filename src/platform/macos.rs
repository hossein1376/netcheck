//! macOS: a per-user LaunchAgent with data under Application Support.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const LABEL: &str = "com.netcheck.agent";

pub fn data_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("Library/Application Support/netcheck")
}

pub fn render_plist(bin: &Path, db: &Path, log: &Path) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{label}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{bin}</string>
    <string>daemon</string>
    <string>--db</string>
    <string>{db}</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>{log}</string>
  <key>StandardErrorPath</key>
  <string>{log}</string>
</dict>
</plist>
"#,
        label = LABEL,
        bin = xml(&bin.display().to_string()),
        db = xml(&db.display().to_string()),
        log = xml(&log.display().to_string()),
    )
}

pub fn write_install(home: &Path, src_bin: &Path, src_meter: &Path, db: &Path) -> Result<PathBuf, String> {
    let bin_dir = home.join("Library/Application Support/netcheck/bin");
    fs::create_dir_all(&bin_dir).map_err(|err| err.to_string())?;
    let dest_bin = bin_dir.join("netcheck");
    let dest_meter = bin_dir.join("nstat_meter");
    copy_exe(src_bin, &dest_bin)?;
    copy_exe(src_meter, &dest_meter)?;

    let agents = home.join("Library/LaunchAgents");
    fs::create_dir_all(&agents).map_err(|err| err.to_string())?;
    let log = home.join("Library/Logs/netcheck.log");
    if let Some(parent) = log.parent() {
        fs::create_dir_all(parent).map_err(|err| err.to_string())?;
    }
    let plist_path = agents.join(format!("{LABEL}.plist"));
    let body = render_plist(&dest_bin, db, &log);
    fs::write(&plist_path, body).map_err(|err| err.to_string())?;
    Ok(plist_path)
}

pub fn install(src_bin: &Path, db: &Path) -> Result<(), String> {
    let src_meter = crate::meter::meter_path();
    println!("Installs a LaunchAgent for this user. It starts at login and restarts if it exits.");
    let home = home_dir()?;
    // Stop the old agent before its binaries are replaced.
    let _ = bootout(&home.join(format!("Library/LaunchAgents/{LABEL}.plist")));
    let plist = write_install(&home, src_bin, &src_meter, db)?;
    bootstrap(&plist)?;
    kickstart()?;
    println!("loaded {}", plist.display());
    Ok(())
}

pub fn uninstall() -> Result<(), String> {
    let home = home_dir()?;
    let plist = home.join(format!("Library/LaunchAgents/{LABEL}.plist"));
    let _ = bootout(&plist);
    if plist.exists() {
        fs::remove_file(&plist).map_err(|err| err.to_string())?;
    }
    let bin_dir = home.join("Library/Application Support/netcheck/bin");
    if bin_dir.exists() {
        fs::remove_dir_all(&bin_dir).map_err(|err| err.to_string())?;
    }
    println!("uninstalled {LABEL}");
    println!("left the usage database in place");
    Ok(())
}

fn copy_exe(src: &Path, dest: &Path) -> Result<(), String> {
    if same_file(src, dest) {
        return Ok(());
    }
    // Copy to a new file and rename over the old one. Writing into an executable
    // that has run leaves macOS with a stale code signature for it, and the next
    // launch is killed.
    let tmp = dest.with_extension("new");
    let _ = fs::remove_file(&tmp);
    fs::copy(src, &tmp).map_err(|err| format!("copy {} failed: {err}", src.display()))?;
    let mut perms = fs::metadata(&tmp).map_err(|err| err.to_string())?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&tmp, perms).map_err(|err| err.to_string())?;
    fs::rename(&tmp, dest).map_err(|err| format!("replace {} failed: {err}", dest.display()))?;
    Ok(())
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

fn home_dir() -> Result<PathBuf, String> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_dir())
        .ok_or_else(|| "HOME is not set".into())
}

fn domain() -> String {
    let uid = unsafe { libc::getuid() };
    format!("gui/{uid}")
}

fn bootout(plist: &Path) -> Result<(), String> {
    let status = Command::new("launchctl")
        .args(["bootout", &domain()])
        .arg(plist)
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|err| err.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("launchctl bootout exited {status}"))
    }
}

fn bootstrap(plist: &Path) -> Result<(), String> {
    let status = Command::new("launchctl")
        .args(["bootstrap", &domain()])
        .arg(plist)
        .status()
        .map_err(|err| err.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("launchctl bootstrap exited {status}"))
    }
}

fn kickstart() -> Result<(), String> {
    let status = Command::new("launchctl")
        .args(["kickstart", "-k", &format!("{}/{}", domain(), LABEL)])
        .status()
        .map_err(|err| err.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("launchctl kickstart exited {status}"))
    }
}

fn xml(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plist_points_at_the_binary_and_database() {
        let text = render_plist(
            Path::new("/Apps/netcheck"),
            Path::new("/Data/netcheck.db"),
            Path::new("/Logs/netcheck.log"),
        );
        assert!(text.contains(LABEL));
        assert!(text.contains("/Apps/netcheck"));
        assert!(text.contains(">daemon<"));
        assert!(text.contains("/Data/netcheck.db"));
        assert!(text.contains("<key>KeepAlive</key>"));
        assert!(text.contains("/Logs/netcheck.log"));
    }

    #[test]
    fn write_install_copies_the_binaries_and_plist() {
        let root = std::env::temp_dir().join(format!("netcheck-install-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let home = root.join("home");
        fs::create_dir_all(&home).unwrap();
        let src = root.join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("netcheck"), b"bin").unwrap();
        fs::write(src.join("nstat_meter"), b"meter").unwrap();
        let db = home.join("Library/Application Support/netcheck/netcheck.db");
        let plist = write_install(&home, &src.join("netcheck"), &src.join("nstat_meter"), &db).unwrap();
        let body = fs::read_to_string(&plist).unwrap();
        assert!(body.contains(LABEL));
        let bin_dir = home.join("Library/Application Support/netcheck/bin");
        assert_eq!(fs::read(bin_dir.join("netcheck")).unwrap(), b"bin");
        assert_eq!(fs::read(bin_dir.join("nstat_meter")).unwrap(), b"meter");
        assert!(body.contains(&bin_dir.join("netcheck").display().to_string()));

        // A reinstall replaces the file rather than writing into it.
        use std::os::unix::fs::MetadataExt;
        let before = fs::metadata(bin_dir.join("netcheck")).unwrap().ino();
        fs::write(src.join("netcheck"), b"bin2").unwrap();
        write_install(&home, &src.join("netcheck"), &src.join("nstat_meter"), &db).unwrap();
        let after = fs::metadata(bin_dir.join("netcheck")).unwrap();
        assert_eq!(fs::read(bin_dir.join("netcheck")).unwrap(), b"bin2");
        assert_ne!(after.ino(), before, "the running binary's inode must not be rewritten");
        let _ = fs::remove_dir_all(&root);
    }
}

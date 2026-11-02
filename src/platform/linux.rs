//! Linux: a systemd system service, since the eBPF meter needs root. Data
//! lives in /var/lib/netcheck and is readable by the netcheck group.

use super::unix::{copy_exe, require_root};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Group allowed to read usage data and ask the daemon for `top`.
pub const READER_GROUP: &str = "netcheck";
const UNIT: &str = "netcheck.service";

pub fn data_dir() -> PathBuf {
    PathBuf::from("/var/lib/netcheck")
}

pub fn render_unit(bin: &Path, db: &Path) -> String {
    format!(
        "[Unit]
Description=netcheck per-app network usage
After=network.target

[Service]
ExecStart=\"{bin}\" daemon --db \"{db}\"
Restart=always
RestartSec=2
Nice=10
CPUSchedulingPolicy=batch
IOSchedulingClass=idle

[Install]
WantedBy=multi-user.target
",
        bin = bin.display(),
        db = db.display(),
    )
}

/// Copy the binary, link it onto PATH, and write the unit under `root` (`/`
/// for a real install). Returns the unit's path.
pub fn write_install(root: &Path, src_bin: &Path, db: &Path) -> Result<PathBuf, String> {
    let lib = root.join("usr/local/lib/netcheck");
    fs::create_dir_all(&lib).map_err(|err| err.to_string())?;
    let dest_bin = lib.join("netcheck");
    copy_exe(src_bin, &dest_bin)?;

    let bin_dir = root.join("usr/local/bin");
    fs::create_dir_all(&bin_dir).map_err(|err| err.to_string())?;
    let link = bin_dir.join("netcheck");
    let _ = fs::remove_file(&link);
    std::os::unix::fs::symlink(&dest_bin, &link).map_err(|err| format!("link {}: {err}", link.display()))?;

    let units = root.join("etc/systemd/system");
    fs::create_dir_all(&units).map_err(|err| err.to_string())?;
    let unit = units.join(UNIT);
    // The unit runs the installed copy, which lives at the real path.
    let installed = Path::new("/").join(dest_bin.strip_prefix(root).unwrap_or(&dest_bin));
    fs::write(&unit, render_unit(&installed, db)).map_err(|err| err.to_string())?;
    Ok(unit)
}

pub fn install(src_bin: &Path, db: &Path) -> Result<(), String> {
    require_root("install")?;
    println!("Installs a systemd service that runs as root, starts at boot, and restarts if it exits.");
    ensure_reader_group()?;
    let unit = write_install(Path::new("/"), src_bin, db)?;
    if let Some(dir) = db.parent() {
        fs::create_dir_all(dir).map_err(|err| err.to_string())?;
        super::share_with_readers(dir);
    }
    systemctl(&["daemon-reload"])?;
    systemctl(&["enable", UNIT])?;
    systemctl(&["restart", UNIT])?;
    println!("installed {}", unit.display());
    println!("usage data is readable by the {READER_GROUP} group");
    Ok(())
}

pub fn uninstall() -> Result<(), String> {
    require_root("uninstall")?;
    let _ = systemctl(&["disable", "--now", UNIT]);
    let unit = Path::new("/etc/systemd/system").join(UNIT);
    if unit.exists() {
        fs::remove_file(&unit).map_err(|err| err.to_string())?;
    }
    let _ = systemctl(&["daemon-reload"]);
    let _ = fs::remove_file("/usr/local/bin/netcheck");
    let _ = fs::remove_dir_all("/usr/local/lib/netcheck");
    println!("uninstalled {UNIT}");
    println!("left the usage database in {}", data_dir().display());
    Ok(())
}

/// Create the reader group if needed and add the user who ran sudo.
fn ensure_reader_group() -> Result<(), String> {
    let exists = Command::new("getent")
        .args(["group", READER_GROUP])
        .output()
        .is_ok_and(|out| out.status.success());
    if !exists {
        run("groupadd", &["--system", READER_GROUP])?;
        println!("created the {READER_GROUP} group");
    }
    if let Ok(user) = std::env::var("SUDO_USER") {
        if user != "root" {
            run("usermod", &["--append", "--groups", READER_GROUP, &user])?;
            println!("added {user} to {READER_GROUP}; it takes effect at their next login");
        }
    }
    Ok(())
}

fn systemctl(args: &[&str]) -> Result<(), String> {
    run("systemctl", args)
}

fn run(program: &str, args: &[&str]) -> Result<(), String> {
    let status = Command::new(program)
        .args(args)
        .status()
        .map_err(|err| format!("{program}: {err}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{program} {} exited {status}", args.join(" ")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_install_lays_out_a_service() {
        let root = std::env::temp_dir().join(format!("netcheck-linux-install-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let src = root.join("netcheck-src");
        fs::write(&src, b"bin").unwrap();
        let db = Path::new("/var/lib/netcheck/netcheck.db");
        let unit = write_install(&root, &src, db).unwrap();
        let text = fs::read_to_string(&unit).unwrap();
        assert!(text.contains("ExecStart=\"/usr/local/lib/netcheck/netcheck\" daemon --db \"/var/lib/netcheck/netcheck.db\""));
        assert!(text.contains("Restart=always"));
        assert_eq!(fs::read(root.join("usr/local/lib/netcheck/netcheck")).unwrap(), b"bin");
        assert_eq!(
            fs::read_link(root.join("usr/local/bin/netcheck")).unwrap(),
            root.join("usr/local/lib/netcheck/netcheck")
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn install_refuses_without_root() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        assert!(install(Path::new("/nonexistent"), Path::new("/nonexistent.db"))
            .unwrap_err()
            .contains("sudo"));
    }
}

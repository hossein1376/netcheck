use std::path::PathBuf;
use std::process::Command;

fn main() {
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if os != "macos" {
        println!("cargo:rustc-env=NETCHECK_METER_DEFAULT=");
        return;
    }

    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let src = manifest.join("meter/macos/nstat_meter.m");
    println!("cargo:rerun-if-changed={}", src.display());

    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("nstat_meter");
    let status = Command::new("clang")
        .args([
            "-fobjc-arc",
            "-O2",
            "-Wall",
            "-Wextra",
            "-framework",
            "Foundation",
            "-framework",
            "CoreFoundation",
            "-F/System/Library/PrivateFrameworks",
            "-framework",
            "NetworkStatistics",
            "-lproc",
        ])
        .arg(&src)
        .arg("-o")
        .arg(&out)
        .status()
        .expect("clang is required to build the macOS meter");
    if !status.success() {
        panic!("nstat_meter failed to compile");
    }
    println!("cargo:rustc-env=NETCHECK_METER_DEFAULT={}", out.display());
}

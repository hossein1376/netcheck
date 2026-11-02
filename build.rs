use std::path::PathBuf;
use std::process::Command;

fn main() {
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if os == "linux" {
        build_linux_probe();
    }
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

/// Compile the eBPF probe; src/meter/linux.rs embeds the object.
fn build_linux_probe() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let src = manifest.join("meter/linux/netcheck.bpf.c");
    println!("cargo:rerun-if-changed={}", src.display());
    let (arch, multiarch) = match std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default().as_str() {
        "aarch64" => ("arm64", "aarch64-linux-gnu"),
        "x86_64" => ("x86", "x86_64-linux-gnu"),
        other => panic!("no eBPF probe build for {other}"),
    };
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("netcheck.bpf.o");
    let status = Command::new("clang")
        .args(["-O2", "-g", "-Wall", "-target", "bpf"])
        .arg(format!("-D__TARGET_ARCH_{arch}"))
        .arg(format!("-I/usr/include/{multiarch}"))
        .arg("-c")
        .arg(&src)
        .arg("-o")
        .arg(&out)
        .status()
        .expect("clang is required to build the eBPF probe");
    if !status.success() {
        panic!("the eBPF probe failed to compile");
    }
}

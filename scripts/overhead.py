#!/usr/bin/env python3
"""Measure the running netcheck daemon and meter (macOS and Linux).

Reads each process's resource counters before and after a window: on macOS
with proc_pid_rusage, on Linux from /proc plus the kernel's BPF statistics for
the probe. Run it with sudo, since the daemon runs as root. Three scenarios:

  idle   the machine as it is
  bulk   one loopback stream at full speed
  churn  many short loopback connections per second

Usage: python3 -I scripts/overhead.py [--idle 120] [--load 60] [--rate 200]
"""

import argparse
import ctypes
import json
import socket
import struct
import subprocess
import threading
import time

import os
import sys

LINUX = sys.platform.startswith("linux")
# The probe's programs, as named in meter/linux/netcheck.bpf.c.
PROBE_PROGRAMS = {"tcp_sent", "tcp_received", "udp_sent", "udp_received", "udp6_sent", "udp6_received", "released"}
PROBE = -1  # pseudo-pid for the probe's kernel time on Linux

if not LINUX:
    LIBSYSTEM = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
    RUSAGE_INFO_V4 = 4

    class Timebase(ctypes.Structure):
        _fields_ = [("numer", ctypes.c_uint32), ("denom", ctypes.c_uint32)]

    TIMEBASE = Timebase()
    LIBSYSTEM.mach_timebase_info(ctypes.byref(TIMEBASE))


def rusage(pid):
    if LINUX:
        return linux_usage(pid)
    return mac_rusage(pid)


def linux_usage(pid):
    """CPU, context switches, memory and disk writes from /proc. Voluntary
    switches stand in for wakeups: each is a sleep that later woke."""
    if pid == PROBE:
        return probe_usage()
    with open(f"/proc/{pid}/stat") as f:
        fields = f.read().rsplit(")", 1)[1].split()
    ticks = os.sysconf("SC_CLK_TCK")
    cpu_ns = (int(fields[11]) + int(fields[12])) * 1e9 / ticks
    voluntary = involuntary = 0
    for task in os.listdir(f"/proc/{pid}/task"):
        with open(f"/proc/{pid}/task/{task}/status") as f:
            for line in f:
                if line.startswith("voluntary_ctxt_switches"):
                    voluntary += int(line.split()[1])
                elif line.startswith("nonvoluntary_ctxt_switches"):
                    involuntary += int(line.split()[1])
    rss = 0
    with open(f"/proc/{pid}/status") as f:
        for line in f:
            if line.startswith("VmRSS:"):
                rss = int(line.split()[1]) * 1024
    written = 0
    with open(f"/proc/{pid}/io") as f:
        for line in f:
            if line.startswith("write_bytes:"):
                written = int(line.split()[1])
    return {
        "cpu_ns": cpu_ns,
        "idle_wakeups": voluntary,
        "interrupt_wakeups": involuntary,
        "footprint": rss,
        "disk_written": written,
    }


def probe_usage():
    """Time the kernel spent in the probe's programs (needs bpf_stats_enabled)."""
    out = subprocess.run(["bpftool", "prog", "show", "--json"], capture_output=True, text=True).stdout
    progs = [p for p in json.loads(out or "[]") if p.get("name") in PROBE_PROGRAMS]
    return {
        "cpu_ns": sum(p.get("run_time_ns", 0) for p in progs),
        "idle_wakeups": sum(p.get("run_cnt", 0) for p in progs),
        "interrupt_wakeups": 0,
        "footprint": 0,
        "disk_written": 0,
    }


def mac_rusage(pid):
    """Cumulative counters for one process. CPU times are Mach ticks."""
    buf = (ctypes.c_uint64 * 64)()
    if LIBSYSTEM.proc_pid_rusage(pid, RUSAGE_INFO_V4, ctypes.byref(buf)) != 0:
        raise OSError(f"proc_pid_rusage failed for pid {pid}")
    v = list(buf)[2:]  # skip the 16-byte UUID
    ticks = v[0] + v[1]
    return {
        "cpu_ns": ticks * TIMEBASE.numer / TIMEBASE.denom,
        "idle_wakeups": v[2],
        "interrupt_wakeups": v[3],
        "footprint": v[7],
        "disk_written": v[17],
    }


def find_pids():
    daemon = subprocess.run(
        ["pgrep", "-f", "netcheck daemon"], capture_output=True, text=True
    ).stdout.split()
    if len(daemon) != 1:
        raise SystemExit(f"expected one netcheck daemon, found {daemon}")
    if LINUX:
        # The meter runs inside the daemon; its kernel side is the probe.
        return {"daemon": int(daemon[0]), "probe": PROBE}
    meter = subprocess.run(
        ["pgrep", "-P", daemon[0]], capture_output=True, text=True
    ).stdout.split()
    if len(meter) != 1:
        raise SystemExit(f"expected one meter under the daemon, found {meter}")
    return {"daemon": int(daemon[0]), "meter": int(meter[0])}


def measure(pids, seconds):
    before = {name: rusage(pid) for name, pid in pids.items()}
    start = time.monotonic()
    time.sleep(seconds)
    elapsed = time.monotonic() - start
    after = {name: rusage(pid) for name, pid in pids.items()}
    out = {}
    for name in pids:
        a, b = after[name], before[name]
        out[name] = {
            "cpu_s_per_hour": (a["cpu_ns"] - b["cpu_ns"]) / 1e9 * 3600 / elapsed,
            "idle_wakeups_per_s": (a["idle_wakeups"] - b["idle_wakeups"]) / elapsed,
            "interrupt_wakeups_per_s": (a["interrupt_wakeups"] - b["interrupt_wakeups"]) / elapsed,
            "disk_kb_per_min": (a["disk_written"] - b["disk_written"]) / 1024 * 60 / elapsed,
            "footprint_mb": a["footprint"] / 1048576,
        }
    return out


class Bulk:
    """One loopback TCP stream sending as fast as it can."""

    def __init__(self):
        self.stop = threading.Event()
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.addr = self.listener.getsockname()
        self.threads = [threading.Thread(target=self.serve), threading.Thread(target=self.read)]

    def serve(self):
        conn, _ = self.listener.accept()
        chunk = b"x" * 65536
        with conn:
            while not self.stop.is_set():
                conn.sendall(chunk)

    def read(self):
        with socket.create_connection(self.addr) as conn:
            while not self.stop.is_set() and conn.recv(1 << 20):
                pass

    def __enter__(self):
        for t in self.threads:
            t.start()
        return self

    def __exit__(self, *exc):
        self.stop.set()
        for t in self.threads:
            t.join(timeout=5)
        self.listener.close()


class Churn:
    """Short loopback connections at a steady rate, 1 KB each. The client
    resets the connection after reading, so no socket lingers in TIME_WAIT."""

    def __init__(self, rate):
        self.rate = rate
        self.done = 0
        self.failed = 0
        self.stop = threading.Event()
        self.listener = socket.create_server(("127.0.0.1", 0), backlog=512)
        self.addr = self.listener.getsockname()
        self.threads = [threading.Thread(target=self.serve), threading.Thread(target=self.connect)]

    def serve(self):
        self.listener.settimeout(0.5)
        payload = b"y" * 1024
        while not self.stop.is_set():
            try:
                conn, _ = self.listener.accept()
            except socket.timeout:
                continue
            with conn:
                conn.sendall(payload)
                try:
                    conn.recv(1)  # wait for the client to close first
                except OSError:
                    pass

    def connect(self):
        gap = 1 / self.rate
        next_at = time.monotonic()
        reset = struct.pack("ii", 1, 0)
        while not self.stop.is_set():
            try:
                with socket.create_connection(self.addr, timeout=2) as conn:
                    got = 0
                    while got < 1024:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        got += len(chunk)
                    conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, reset)
                self.done += 1
            except OSError:
                # An occasional stalled connect on a busy loopback; count it.
                self.failed += 1
                next_at = time.monotonic()
            next_at += gap
            time.sleep(max(0, next_at - time.monotonic()))

    def __enter__(self):
        for t in self.threads:
            t.start()
        return self

    def __exit__(self, *exc):
        self.stop.set()
        for t in self.threads:
            t.join(timeout=5)
        self.listener.close()


def show(name, result):
    print(f"\n{name}")
    if LINUX:
        # daemon: voluntary / involuntary context switches; probe: program runs.
        print(f"  {'':8} {'CPU s/h':>9} {'vol cs/s':>10} {'invol cs/s':>10} {'disk KB/min':>12} {'MB':>6}")
    else:
        print(f"  {'':8} {'CPU s/h':>9} {'idle wk/s':>10} {'intr wk/s':>10} {'disk KB/min':>12} {'MB':>6}")
    for proc, r in result.items():
        print(
            f"  {proc:8} {r['cpu_s_per_hour']:9.2f} {r['idle_wakeups_per_s']:10.2f} "
            f"{r['interrupt_wakeups_per_s']:10.2f} "
            f"{r['disk_kb_per_min']:12.1f} {r['footprint_mb']:6.1f}"
        )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--idle", type=float, default=120)
    parser.add_argument("--load", type=float, default=60)
    parser.add_argument("--rate", type=int, default=200, help="churn connections per second")
    parser.add_argument("--json", help="also write results to this file")
    args = parser.parse_args()

    pids = find_pids()
    stats_flag = "/proc/sys/kernel/bpf_stats_enabled"
    restore_stats = None
    if LINUX:
        with open(stats_flag) as f:
            restore_stats = f.read().strip()
        with open(stats_flag, "w") as f:
            f.write("1")
    results = {"pids": pids, "seconds": {"idle": args.idle, "load": args.load}, "rate": args.rate}
    results["idle"] = measure(pids, args.idle)
    show(f"idle ({args.idle:.0f} s)", results["idle"])
    with Bulk():
        results["bulk"] = measure(pids, args.load)
    show(f"bulk loopback stream ({args.load:.0f} s)", results["bulk"])
    with Churn(args.rate) as churn:
        results["churn"] = measure(pids, args.load)
    results["churn_rate"] = churn.done / args.load
    results["churn_failed"] = churn.failed
    show(
        f"churn, {results['churn_rate']:.0f} connections/s achieved, "
        f"{churn.failed} failed ({args.load:.0f} s)",
        results["churn"],
    )
    if LINUX:
        with open(stats_flag, "w") as f:
            f.write(restore_stats)
        print("\nprobe: CPU is kernel time in the probe; vol cs/s is program runs per second.")
    if args.json:
        with open(args.json, "w") as f:
            json.dump(results, f, indent=2)


if __name__ == "__main__":
    main()

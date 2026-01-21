#!/usr/bin/env python3

import argparse
import shutil
import subprocess
import socket
import ipaddress
import json
import os
import time
import tempfile
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------- PLATFORM DETECTION ----------------
IS_WINDOWS = platform.system() == "Windows"


def is_admin():
    if IS_WINDOWS:
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            return False
    else:
        return os.geteuid() == 0


def tool_exists(tool):
    return shutil.which(tool) is not None


# ---------------- PARSERS ----------------
def parse_ports(value):
    if "-" in value:
        a, b = map(int, value.split("-"))
        return list(range(a, b + 1))
    return [int(value)]


def parse_targets(value):
    try:
        net = ipaddress.ip_network(value, strict=False)
        return [str(ip) for ip in net.hosts()]
    except ValueError:
        return [value]


# ---------------- NMAP ----------------
def scan_with_nmap(protocol, ports, target):
    print("[*] Using nmap")

    port_arg = ",".join(map(str, ports))
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
    tmp.close()

    cmd = ["nmap"]

    if protocol == "tcp":
        if is_admin():
            cmd.append("-sS")
        else:
            print("[!] No admin/root — using TCP connect scan")
            cmd.append("-sT")
    else:
        cmd.append("-sU")

    cmd += ["-p", port_arg, "-oJ", tmp.name, target]

    if not IS_WINDOWS and not is_admin() and "-sS" in cmd:
        cmd.insert(0, "sudo")

    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    open_ports = []

    with open(tmp.name, "r", encoding="utf-8") as f:
        data = json.load(f)

    for host in data.get("host", []):
        for port in host.get("ports", []):
            if port["state"]["state"] == "open":
                open_ports.append(port["portid"])

    os.unlink(tmp.name)
    return sorted(set(open_ports))


# ---------------- NETCAT / NCAT ----------------
def scan_with_nc(protocol, ports, targets, timeout):
    nc_bin = "ncat" if IS_WINDOWS else "nc"
    print(f"[*] Using {nc_bin}")

    open_ports = set()

    for target in targets:
        for port in ports:
            if protocol == "tcp":
                cmd = [nc_bin, "-z", "-w", str(timeout), target, str(port)]
            else:
                cmd = [nc_bin, "-u", "-z", "-w", str(timeout), target, str(port)]

            r = subprocess.run(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            if r.returncode == 0:
                open_ports.add(port)

    return sorted(open_ports)


# ---------------- PYTHON SOCKET FALLBACK ----------------
def tcp_scan(target, port, timeout):
    try:
        with socket.socket() as s:
            s.settimeout(timeout)
            return port if s.connect_ex((target, port)) == 0 else None
    except Exception:
        return None


def udp_scan(target, port, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(b"\x00", (target, port))
            s.recvfrom(1024)
            return port
    except Exception:
        return None


def scan_with_python(protocol, ports, targets, threads, timeout):
    print("[*] Using Python sockets (fallback)")
    open_ports = set()

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = []

        for t in targets:
            for p in ports:
                fn = tcp_scan if protocol == "tcp" else udp_scan
                futures.append(pool.submit(fn, t, p, timeout))

        for f in as_completed(futures):
            r = f.result()
            if r:
                open_ports.add(r)

    return sorted(open_ports)


# ---------------- DISPATCH ----------------
def run_scan(args, ports, targets):
    if tool_exists("nmap"):
        return scan_with_nmap(args.P, ports, args.t)

    nc_bin = "ncat" if IS_WINDOWS else "nc"
    if tool_exists(nc_bin):
        return scan_with_nc(args.P, ports, targets, args.timeout)

    return scan_with_python(
        args.P, ports, targets, args.threads, args.timeout
    )


# ---------------- MAIN ----------------
def main():
    parser = argparse.ArgumentParser("Cross-platform adaptive port scanner")

    parser.add_argument("-P", choices=["tcp", "udp"], required=True)
    parser.add_argument("-p", required=True)
    parser.add_argument("-t", required=True)
    parser.add_argument("--threads", type=int, default=100)
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--interval", type=int)

    args = parser.parse_args()

    ports = parse_ports(args.p)
    targets = parse_targets(args.t)

    previous = None

    while True:
        print("\n[*] Running scan...")
        current = run_scan(args, ports, targets)

        print(f"[+] Open ports: {current}")

        if previous is not None:
            new = set(current) - set(previous)
            closed = set(previous) - set(current)

            if new:
                print(f"[+] New open ports: {sorted(new)}")
            if closed:
                print(f"[-] Closed ports: {sorted(closed)}")
            if not new and not closed:
                print("[*] No change detected")

        previous = current

        if not args.interval:
            break

        print(f"[*] Waiting {args.interval} seconds...\n")
        time.sleep(args.interval)


if __name__ == "__main__":
    main()

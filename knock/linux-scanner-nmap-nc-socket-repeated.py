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
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm


# -------------------- HELPERS --------------------
def tool_exists(tool):
    return shutil.which(tool) is not None


def is_root():
    return os.geteuid() == 0


def parse_ports(value):
    if "-" in value:
        start, end = map(int, value.split("-"))
        return list(range(start, end + 1))
    return [int(value)]


def parse_targets(value):
    try:
        net = ipaddress.ip_network(value, strict=False)
        return [str(ip) for ip in net.hosts()]
    except ValueError:
        return [value]


# -------------------- NMAP BACKEND --------------------
def scan_with_nmap(protocol, ports, target):
    print("[*] Using nmap")

    port_arg = ",".join(map(str, ports))
    output_file = tempfile.NamedTemporaryFile(delete=False, suffix=".json").name

    cmd = ["nmap"]

    if protocol == "tcp":
        cmd += ["-sS"]
    else:
        cmd += ["-sU"]

    cmd += ["-p", port_arg, "-oJ", output_file, target]

    if protocol == "tcp" and not is_root():
        cmd.insert(0, "sudo")

    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    open_ports = []

    with open(output_file) as f:
        data = json.load(f)

    for host in data.get("host", []):
        for port in host.get("ports", []):
            if port["state"]["state"] == "open":
                open_ports.append(port["portid"])

    os.unlink(output_file)
    return sorted(set(open_ports))


# -------------------- NETCAT BACKEND --------------------
def scan_with_nc(protocol, ports, targets):
    print("[*] Using netcat")
    open_ports = set()

    for target in targets:
        for port in tqdm(ports, desc=f"Scanning {target}", unit="port"):
            if protocol == "tcp":
                cmd = ["nc", "-z", "-w1", target, str(port)]
            else:
                cmd = ["nc", "-u", "-z", "-w1", target, str(port)]

            result = subprocess.run(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )

            if result.returncode == 0:
                open_ports.add(port)

    return sorted(open_ports)


# -------------------- PYTHON SOCKET BACKEND --------------------
def tcp_connect_scan(target, port, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return port if s.connect_ex((target, port)) == 0 else None
    except Exception:
        return None


def udp_scan(target, port, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(b"\x00", (target, port))
            try:
                s.recvfrom(1024)
                return port
            except socket.timeout:
                return None
    except Exception:
        return None


def scan_with_python(protocol, ports, targets, threads, timeout):
    print("[*] Using Python sockets (fallback)")
    open_ports = set()

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []

        for target in targets:
            for port in ports:
                if protocol == "tcp":
                    futures.append(
                        executor.submit(tcp_connect_scan, target, port, timeout)
                    )
                else:
                    futures.append(
                        executor.submit(udp_scan, target, port, timeout)
                    )

        for f in tqdm(as_completed(futures), total=len(futures), unit="probe"):
            result = f.result()
            if result:
                open_ports.add(result)

    return sorted(open_ports)


# -------------------- SCAN DISPATCHER --------------------
def run_scan(args, ports, targets):
    if tool_exists("nmap"):
        return scan_with_nmap(args.P, ports, args.t)
    elif tool_exists("nc"):
        return scan_with_nc(args.P, ports, targets)
    else:
        return scan_with_python(
            args.P, ports, targets, args.threads, args.timeout
        )


# -------------------- MAIN --------------------
def main():
    parser = argparse.ArgumentParser(
        description="Adaptive Linux port scanner with change detection"
    )

    parser.add_argument("-P", choices=["tcp", "udp"], required=True)
    parser.add_argument("-p", required=True, help="Port or range (e.g. 80 or 1-1024)")
    parser.add_argument("-t", required=True, help="Target IP / hostname / CIDR")

    parser.add_argument("--threads", type=int, default=100)
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument(
        "--interval",
        type=int,
        help="Repeat scan every N seconds and notify on changes"
    )

    args = parser.parse_args()

    ports = parse_ports(args.p)
    targets = parse_targets(args.t)

    previous_open_ports = None

    while True:
        print("\n[*] Running scan...")
        open_ports = run_scan(args, ports, targets)

        print(f"[+] Open ports: {open_ports}")

        if previous_open_ports is not None:
            prev = set(previous_open_ports)
            curr = set(open_ports)

            new_ports = curr - prev
            closed_ports = prev - curr

            if new_ports:
                print(f"[+] New open ports detected: {sorted(new_ports)}")

            if closed_ports:
                print(f"[-] Ports closed: {sorted(closed_ports)}")

            if not new_ports and not closed_ports:
                print("[*] No change in open ports")

        previous_open_ports = open_ports

        if not args.interval:
            break

        print(f"[*] Waiting {args.interval} seconds before next scan...\n")
        time.sleep(args.interval)


if __name__ == "__main__":
    main()

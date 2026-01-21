#!/usr/bin/env python3

import argparse, socket, shutil, subprocess, json, os, time, tempfile, platform, ipaddress
from concurrent.futures import ThreadPoolExecutor

IS_WINDOWS = platform.system() == "Windows"


def is_admin():
    if IS_WINDOWS:
        import ctypes
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            return False
    return os.geteuid() == 0


def tool_exists(t):
    return shutil.which(t) is not None


def parse_ports(spec):
    ports = set()
    for part in spec.split(","):
        if "-" in part:
            a, b = map(int, part.split("-"))
            ports.update(range(a, b + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


def parse_targets(t):
    try:
        net = ipaddress.ip_network(t, strict=False)
        return [str(ip) for ip in net.hosts()]
    except ValueError:
        return [t]


def scan_with_nmap(proto, ports, target):
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
    tmp.close()

    scan = "-sS" if proto == "tcp" and is_admin() else "-sT" if proto == "tcp" else "-sU"
    cmd = ["nmap", scan, "-p", ",".join(map(str, ports)), "-oJ", tmp.name, target]

    if not IS_WINDOWS and scan == "-sS" and not is_admin():
        cmd.insert(0, "sudo")

    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    with open(tmp.name) as f:
        data = json.load(f)
    os.unlink(tmp.name)

    return sorted({
        p["portid"]
        for h in data.get("host", [])
        for p in h.get("ports", [])
        if p["state"]["state"] == "open"
    })


def tcp_check(host, port, timeout):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return port
    except Exception:
        return None


def scan_with_python(ports, targets, threads, timeout):
    open_ports = set()
    with ThreadPoolExecutor(max_workers=threads) as pool:
        for h in targets:
            for r in pool.map(lambda p: tcp_check(h, p, timeout), ports):
                if r:
                    open_ports.add(r)
    return sorted(open_ports)


def main():
    parser = argparse.ArgumentParser(
        description="Cross-platform adaptive port scanner"
    )
    parser.add_argument("-P", choices=["tcp", "udp"], required=True)
    parser.add_argument("-p", required=True,
                        help="Ports: 22 | 1-1024 | 22,80,445 | 22,80,1000-1010")
    parser.add_argument("-t", required=True, help="Target IP / host / CIDR")
    parser.add_argument("--threads", type=int, default=100)
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--interval", type=int)

    args = parser.parse_args()

    ports = parse_ports(args.p)
    targets = parse_targets(args.t)

    previous = None

    while True:
        print("\n[*] Running scan...")
        current = (
            scan_with_nmap(args.P, ports, args.t)
            if tool_exists("nmap")
            else scan_with_python(ports, targets, args.threads, args.timeout)
        )

        print(f"[+] Open ports: {current}")

        if previous is not None:
            print(f"[+] New: {sorted(set(current) - set(previous))}")
            print(f"[-] Closed: {sorted(set(previous) - set(current))}")

        previous = current

        if not args.interval:
            break
        time.sleep(args.interval)


if __name__ == "__main__":
    main()

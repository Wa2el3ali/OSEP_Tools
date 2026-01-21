#!/usr/bin/env python3

import argparse
import asyncio
import json
import os
import platform
import shutil
import socket
import tempfile
import ipaddress

IS_WINDOWS = platform.system() == "Windows"


# ---------------- PRIVILEGES ----------------
def is_admin():
    if IS_WINDOWS:
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            return False
    return os.geteuid() == 0


def tool_exists(tool):
    return shutil.which(tool) is not None


# ---------------- PARSING ----------------
def parse_ports(spec):
    if "-" in spec:
        a, b = map(int, spec.split("-"))
        return list(range(a, b + 1))
    return [int(spec)]


def parse_targets(value):
    try:
        net = ipaddress.ip_network(value, strict=False)
        return [str(ip) for ip in net.hosts()]
    except ValueError:
        return [value]


# ---------------- NMAP (ASYNC) ----------------
async def scan_with_nmap(protocol, ports, target):
    print("[*] Using nmap (async)")

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
    tmp.close()

    scan_type = (
        "-sS" if protocol == "tcp" and is_admin()
        else "-sT" if protocol == "tcp"
        else "-sU"
    )

    cmd = ["nmap", scan_type, "-p", ",".join(map(str, ports)), "-oJ", tmp.name, target]

    if not IS_WINDOWS and not is_admin() and scan_type == "-sS":
        cmd.insert(0, "sudo")

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL
    )
    await proc.wait()

    with open(tmp.name, "r", encoding="utf-8") as f:
        data = json.load(f)

    os.unlink(tmp.name)

    open_ports = []
    for host in data.get("host", []):
        for p in host.get("ports", []):
            if p["state"]["state"] == "open":
                open_ports.append(p["portid"])

    return sorted(set(open_ports))


# ---------------- ASYNC TCP ----------------
async def tcp_check(host, port, timeout, sem):
    async with sem:
        try:
            conn = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(conn, timeout)
            writer.close()
            await writer.wait_closed()
            return port
        except Exception:
            return None


# ---------------- ASYNC UDP ----------------
class UDPClient(asyncio.DatagramProtocol):
    def __init__(self, fut):
        self.fut = fut

    def datagram_received(self, data, addr):
        if not self.fut.done():
            self.fut.set_result(True)


async def udp_check(host, port, timeout, sem):
    async with sem:
        loop = asyncio.get_running_loop()
        fut = loop.create_future()

        try:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: UDPClient(fut),
                remote_addr=(host, port)
            )
            transport.sendto(b"\x00")

            await asyncio.wait_for(fut, timeout)
            transport.close()
            return port
        except Exception:
            return None


# ---------------- ASYNC SOCKET SCAN ----------------
async def scan_with_async_sockets(protocol, ports, targets, concurrency, timeout):
    print("[*] Using async Python sockets")

    sem = asyncio.Semaphore(concurrency)
    tasks = []

    for host in targets:
        for port in ports:
            if protocol == "tcp":
                tasks.append(tcp_check(host, port, timeout, sem))
            else:
                tasks.append(udp_check(host, port, timeout, sem))

    results = await asyncio.gather(*tasks)
    return sorted(p for p in results if p is not None)


# ---------------- DISPATCH ----------------
async def run_scan(args, ports, targets):
    if tool_exists("nmap"):
        return await scan_with_nmap(args.P, ports, args.t)

    return await scan_with_async_sockets(
        args.P, ports, targets, args.concurrency, args.timeout
    )


# ---------------- MAIN LOOP ----------------
async def main():
    parser = argparse.ArgumentParser("Async cross-platform port scanner")

    parser.add_argument("-P", choices=["tcp", "udp"], required=True)
    parser.add_argument("-p", required=True)
    parser.add_argument("-t", required=True)
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--concurrency", type=int, default=500)
    parser.add_argument("--interval", type=int)

    args = parser.parse_args()

    ports = parse_ports(args.p)
    targets = parse_targets(args.t)

    previous = None

    while True:
        print("\n[*] Running scan...")
        current = await run_scan(args, ports, targets)

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

        print(f"[*] Waiting {args.interval} seconds...")
        await asyncio.sleep(args.interval)


if __name__ == "__main__":
    asyncio.run(main())

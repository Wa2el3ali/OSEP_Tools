#!/usr/bin/env python3

import argparse, asyncio, ipaddress


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


async def tcp_check(host, port, timeout, sem):
    async with sem:
        try:
            r, w = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout
            )
            w.close()
            await w.wait_closed()
            return port
        except Exception:
            return None


async def scan_async(ports, targets, concurrency, timeout):
    sem = asyncio.Semaphore(concurrency)
    tasks = [tcp_check(h, p, timeout, sem) for h in targets for p in ports]
    results = await asyncio.gather(*tasks)
    return sorted(p for p in results if p)


async def main():
    parser = argparse.ArgumentParser(
        description="Fully async cross-platform port scanner"
    )
    parser.add_argument("-P", choices=["tcp"], required=True)
    parser.add_argument("-p", required=True,
                        help="Ports: 22 | 1-1024 | 22,80,445 | 22,80,1000-1010")
    parser.add_argument("-t", required=True)
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--concurrency", type=int, default=500)
    parser.add_argument("--interval", type=int)

    args = parser.parse_args()

    ports = parse_ports(args.p)
    targets = parse_targets(args.t)
    previous = None

    while True:
        print("\n[*] Running async scan...")
        current = await scan_async(
            ports, targets, args.concurrency, args.timeout
        )

        print(f"[+] Open ports: {current}")

        if previous:
            print(f"[+] New: {sorted(set(current) - set(previous))}")
            print(f"[-] Closed: {sorted(set(previous) - set(current))}")

        previous = current

        if not args.interval:
            break
        await asyncio.sleep(args.interval)


if __name__ == "__main__":
    asyncio.run(main())

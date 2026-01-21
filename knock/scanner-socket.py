
## Usage:
## python scanner.py -P tcp -p 1-1024 -t 192.168.1.1
## python scanner.py -P udp -p 53 -t 8.8.8.8 --timeout 3
## python scanner.py -P both -p 22 -t 192.168.1.0/24 -o results.csv








import argparse
import socket
import time
import ipaddress
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed


# ---------- PARSERS ----------
def parse_ports(value):
    if "-" in value:
        start, end = map(int, value.split("-"))
        return range(start, end + 1)
    return [int(value)]


def parse_targets(value):
    try:
        net = ipaddress.ip_network(value, strict=False)
        return [str(ip) for ip in net.hosts()]
    except ValueError:
        return [value]


# ---------- TCP CONNECT SCAN ----------
def tcp_connect_scan(target, port, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((target, port))
            if result == 0:
                return target, port, "open"
            return target, port, "closed"
    except Exception:
        return target, port, "filtered"


# ---------- UDP SCAN ----------
def udp_scan(target, port, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(b"\x00", (target, port))

            try:
                data, _ = s.recvfrom(1024)
                return target, port, "open"
            except socket.timeout:
                return target, port, "open|filtered"
    except Exception:
        return target, port, "closed"


# ---------- MAIN ----------
def main():
    parser = argparse.ArgumentParser(
        description="TCP connect / UDP socket port scanner"
    )

    parser.add_argument("-P", choices=["tcp", "udp", "both"], required=True)
    parser.add_argument("-p", required=True, help="Port or range (e.g. 80 or 1-1024)")
    parser.add_argument("-t", required=True, help="Target IP / hostname / CIDR")

    parser.add_argument(
        "--threads",
        type=int,
        default=100,
        help="Number of threads (default: 100)"
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=2.0,
        help="Socket timeout in seconds (default: 2.0)"
    )

    parser.add_argument(
        "--rate",
        type=float,
        default=0,
        help="Delay between probes in seconds"
    )

    parser.add_argument(
        "-o",
        help="Output CSV file"
    )

    args = parser.parse_args()

    ports = parse_ports(args.p)
    targets = parse_targets(args.t)

    results = []
    tasks = []

    print(
        f"\nStarting {args.P.upper()} scan\n"
        f"Targets: {len(targets)} | Ports: {len(ports)}\n"
        f"Threads: {args.threads} | Timeout: {args.timeout}s\n"
    )

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        for target in targets:
            for port in ports:
                if args.P in ("tcp", "both"):
                    tasks.append(
                        executor.submit(
                            tcp_connect_scan, target, port, args.timeout
                        )
                    )
                if args.P in ("udp", "both"):
                    tasks.append(
                        executor.submit(
                            udp_scan, target, port, args.timeout
                        )
                    )
                if args.rate:
                    time.sleep(args.rate)

        for future in as_completed(tasks):
            target, port, status = future.result()
            results.append((target, port, status))
            if status in ("open", "open|filtered"):
                print(f"[+] {target}:{port} {status}")

    print("\nScan complete.")

    if args.o:
        with open(args.o, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Target", "Port", "Status"])
            writer.writerows(results)
        print(f"Results saved to {args.o}")


if __name__ == "__main__":
    main()

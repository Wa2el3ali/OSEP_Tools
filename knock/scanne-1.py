import argparse
import random
import time
import ipaddress
import csv
from concurrent.futures import ThreadPoolExecutor
from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, sr1, send


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


# ---------- TCP SYN ----------
def tcp_syn_scan(target, port, timeout):
    sport = random.randint(1024, 65535)
    pkt = IP(dst=target) / TCP(sport=sport, dport=port, flags="S")

    resp = sr1(pkt, timeout=timeout, verbose=False)

    if resp is None:
        return target, port, "filtered"

    if resp.haslayer(TCP):
        flags = resp[TCP].flags
        if flags == 0x12:  # SYN-ACK
            send(IP(dst=target) / TCP(sport=sport, dport=port, flags="R"), verbose=False)
            return target, port, "open"
        elif flags == 0x14:  # RST-ACK
            return target, port, "closed"

    return target, port, "unknown"


# ---------- UDP RAW ----------
def udp_raw_scan(target, port, timeout, dns_probe=False):
    if dns_probe and port == 53:
        pkt = IP(dst=target) / UDP(dport=53) / DNS(
            rd=1, qd=DNSQR(qname="example.com")
        )
    else:
        pkt = IP(dst=target) / UDP(
            sport=random.randint(1024, 65535),
            dport=port
        )

    resp = sr1(pkt, timeout=timeout, verbose=False)

    if resp is None:
        return target, port, "open|filtered"

    if resp.haslayer(UDP):
        return target, port, "open"

    if resp.haslayer(ICMP):
        if resp[ICMP].type == 3 and resp[ICMP].code == 3:
            return target, port, "closed"

    return target, port, "unknown"


# ---------- MAIN ----------
def main():
    parser = argparse.ArgumentParser(
        description="TCP SYN / UDP Raw Port Scanner (Authorized use only)"
    )

    parser.add_argument("-P", choices=["tcp", "udp", "both"], required=True)
    parser.add_argument("-p", required=True, help="Port or range (e.g. 80 or 1-1024)")
    parser.add_argument("-t", required=True, help="Target IP / hostname / CIDR")

    parser.add_argument(
        "--threads",
        type=int,
        default=100,
        help="Number of concurrent threads (default: 100)"
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=2.0,
        help="Packet timeout in seconds (default: 2.0)"
    )

    parser.add_argument(
        "--rate",
        type=float,
        default=0,
        help="Delay between probes in seconds (default: 0)"
    )

    parser.add_argument(
        "--udp-dns",
        action="store_true",
        h

#!/usr/bin/env bash

usage() {
cat <<EOF
Usage: $0 -P tcp|udp -p PORTS -t TARGET [--interval N]

Options:
  -P            Protocol
  -p            Port or range
  -t            Target host/IP
  --interval    Repeat scan
  -h, --help    Show this help
EOF
exit 0
}

[[ "$1" == "-h" || "$1" == "--help" ]] && usage

while [[ $# -gt 0 ]]; do
    case "$1" in
        -P) PROTOCOL="$2"; shift 2 ;;
        -p) PORTS="$2"; shift 2 ;;
        -t) TARGET="$2"; shift 2 ;;
        --interval) INTERVAL="$2"; shift 2 ;;
        -h|--help) usage ;;
        *) usage ;;
    esac
done

parse_ports() {
    [[ "$1" == *"-"* ]] && seq ${1%-*} ${1#*-} || echo "$1"
}

run_scan() {
    if command -v nmap >/dev/null; then
        nmap -sT -p "$PORTS" "$TARGET" -oG - \
        | awk '/open/{print $2}' | cut -d/ -f1
    else
        for p in $(parse_ports "$PORTS"); do
            nc -z -w1 "$TARGET" "$p" && echo "$p"
        done
    fi
}

PREV=""
while true; do
    echo "[*] Running scan..."
    CUR=$(run_scan | sort -n | tr '\n' ' ')
    echo "[+] Open ports: $CUR"

    [[ -n "$PREV" ]] && {
        echo "[+] New: $(comm -13 <(echo "$PREV"|tr ' ' '\n') <(echo "$CUR"|tr ' ' '\n'))"
        echo "[-] Closed: $(comm -23 <(echo "$PREV"|tr ' ' '\n') <(echo "$CUR"|tr ' ' '\n'))"
    }

    PREV="$CUR"
    [[ -z "$INTERVAL" ]] && break
    sleep "$INTERVAL"
done

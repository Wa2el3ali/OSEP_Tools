#!/usr/bin/env bash

usage() {
cat <<EOF
Usage: $0 -P tcp|udp -p PORTS -t TARGET [--interval N]

Ports:
  22
  1-1024
  22,80,445
  22,80,1000-1010

Options:
  -P            Protocol
  -p            Ports
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
        -p) PORTSPEC="$2"; shift 2 ;;
        -t) TARGET="$2"; shift 2 ;;
        --interval) INTERVAL="$2"; shift 2 ;;
        -h|--help) usage ;;
        *) usage ;;
    esac
done

parse_ports() {
    IFS=',' read -ra parts <<< "$1"
    for part in "${parts[@]}"; do
        if [[ "$part" == *"-"* ]]; then
            seq "${part%-*}" "${part#*-}"
        else
            echo "$part"
        fi
    done
}

run_scan() {
    if command -v nmap >/dev/null; then
        nmap -sT -p "$PORTSPEC" "$TARGET" -oG - \
        | awk '/open/{print $2}' | cut -d/ -f1
    else
        for p in $(parse_ports "$PORTSPEC"); do
            nc -z -w1 "$TARGET" "$p" && echo "$p"
        done
    fi
}

PREV=""
while true; do
    echo "[*] Running scan..."
    CUR=$(run_scan | sort -n | tr '\n' ' ')
    echo "[+] Open ports: $CUR"

    if [[ -n "$PREV" ]]; then
        echo "[+] New: $(comm -13 <(echo "$PREV"|tr ' ' '\n') <(echo "$CUR"|tr ' ' '\n'))"
        echo "[-] Closed: $(comm -23 <(echo "$PREV"|tr ' ' '\n') <(echo "$CUR"|tr ' ' '\n'))"
    fi

    PREV="$CUR"
    [[ -z "$INTERVAL" ]] && break
    sleep "$INTERVAL"
done

#!/usr/bin/env bash

set -euo pipefail

# ---------------- CONFIG ----------------
THREADS=100
TIMEOUT=2
INTERVAL=""
PREV_OPEN_PORTS=""

# ---------------- HELPERS ----------------
usage() {
    echo "Usage: $0 -P tcp|udp -p port|start-end -t target [--interval N]"
    exit 1
}

is_root() {
    [[ $EUID -eq 0 ]]
}

tool_exists() {
    command -v "$1" >/dev/null 2>&1
}

parse_ports() {
    if [[ "$1" == *"-"* ]]; then
        seq "${1%-*}" "${1#*-}"
    else
        echo "$1"
    fi
}

normalize_ports() {
    tr ' ' '\n' | sort -n | uniq | tr '\n' ' '
}

# ---------------- NMAP ----------------
scan_with_nmap() {
    echo "[*] Using nmap"

    local scan_type
    if [[ "$PROTOCOL" == "tcp" ]]; then
        if is_root; then
            scan_type="-sS"
        else
            echo "[!] Not root — falling back to TCP connect scan"
            scan_type="-sT"
        fi
    else
        scan_type="-sU"
    fi

    local tmpfile
    tmpfile=$(mktemp)

    nmap $scan_type -p "$PORTSPEC" -oJ "$tmpfile" "$TARGET" >/dev/null

    if tool_exists jq; then
        jq -r '.host[].ports[] | select(.state.state=="open") | .portid' "$tmpfile"
    else
        grep '"state": {"state": "open"' -B2 "$tmpfile" \
        | grep '"portid"' | sed 's/[^0-9]//g'
    fi

    rm -f "$tmpfile"
}

# ---------------- NETCAT ----------------
scan_with_nc() {
    echo "[*] Using netcat"

    for port in $(parse_ports "$PORTSPEC"); do
        if [[ "$PROTOCOL" == "tcp" ]]; then
            nc -z -w"$TIMEOUT" "$TARGET" "$port" && echo "$port"
        else
            nc -u -z -w"$TIMEOUT" "$TARGET" "$port" && echo "$port"
        fi
    done
}

# ---------------- BASH SOCKET FALLBACK ----------------
scan_with_bash() {
    echo "[*] Using bash /dev/tcp fallback (TCP only)"

    [[ "$PROTOCOL" == "udp" ]] && return

    for port in $(parse_ports "$PORTSPEC"); do
        timeout "$TIMEOUT" bash -c "echo > /dev/tcp/$TARGET/$port" \
            2>/dev/null && echo "$port"
    done
}

# ---------------- RUN SCAN ----------------
run_scan() {
    if tool_exists nmap; then
        scan_with_nmap
    elif tool_exists nc; then
        scan_with_nc
    else
        scan_with_bash
    fi | normalize_ports
}

# ---------------- ARG PARSING ----------------
[[ $# -lt 6 ]] && usage

while [[ $# -gt 0 ]]; do
    case "$1" in
        -P) PROTOCOL="$2"; shift 2 ;;
        -p) PORTSPEC="$2"; shift 2 ;;
        -t) TARGET="$2"; shift 2 ;;
        --interval) INTERVAL="$2"; shift 2 ;;
        *) usage ;;
    esac
done

[[ -z "${PROTOCOL:-}" || -z "${PORTSPEC:-}" || -z "${TARGET:-}" ]] && usage

# ---------------- MAIN LOOP ----------------
while true; do
    echo
    echo "[*] Running scan..."
    CURRENT_OPEN_PORTS=$(run_scan)

    echo "[+] Open ports: ${CURRENT_OPEN_PORTS:-none}"

    if [[ -n "$PREV_OPEN_PORTS" ]]; then
        NEW=$(comm -13 <(tr ' ' '\n' <<<"$PREV_OPEN_PORTS") \
                     <(tr ' ' '\n' <<<"$CURRENT_OPEN_PORTS"))
        CLOSED=$(comm -23 <(tr ' ' '\n' <<<"$PREV_OPEN_PORTS") \
                        <(tr ' ' '\n' <<<"$CURRENT_OPEN_PORTS"))

        [[ -n "$NEW" ]] && echo "[+] New open ports: $(echo "$NEW" | tr '\n' ' ')"
        [[ -n "$CLOSED" ]] && echo "[-] Closed ports: $(echo "$CLOSED" | tr '\n' ' ')"

        [[ -z "$NEW" && -z "$CLOSED" ]] && echo "[*] No change in open ports"
    fi

    PREV_OPEN_PORTS="$CURRENT_OPEN_PORTS"

    [[ -z "$INTERVAL" ]] && break

    echo "[*] Waiting $INTERVAL seconds..."
    sleep "$INTERVAL"
done

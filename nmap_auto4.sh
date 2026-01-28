#!/bin/bash
timestamp=$(date +%Y%m%d-%H%M%S)
nmap -Pn -sS -p- --max-retries 0 -oN $1-all-ports_$timestamp.nmap $1 | grep ^[0-9] | cut -f1 -d '/' | sed ':a;N;$!ba;s/\n/,/g' | tee $1-open-ports_$timestamp.txt && nmap -sCV -p $(cat $1-open-ports_$timestamp.txt) -oN $1-open-ports-scan_$timestamp.nmap $1





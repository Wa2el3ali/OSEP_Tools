#!/bin/bash
timestamp=$(date +%Y%m%d_%H%M%S)
nmap -Pn -sS -p- -oA $1-all-ports_$timestamp $1 | grep ^[0-9] | cut -f1 -d '/' | sed ':a;N;$!ba;s/\n/,/g' | tee $1-open-ports && nmap -sCV -p $(cat $1-open-ports) -oA $1-open-ports-scan_$timestamp $1





#!/bin/sh

cat $1 | grep ^[0-9] | cut -f1 -d '/' | sed ':a;N;$!ba;s/\n/,/g' | tee open_ports

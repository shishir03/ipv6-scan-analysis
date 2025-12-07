#!/bin/bash

rm zgrab2/*

PROTOCOLS=("http" "https" "ssh" "smtp" "ftp" "imap" "pop3" "telnet")
PORT_NUMS=(80 443 22 25 21 143 110 23)

for file in xmap_addr/*; do
    basename=$(basename "$file" .txt)

    for i in {0..7}; do
        PROTO=${PROTOCOLS[i]}
        PORT=${PORT_NUMS[i]}
        echo "[*] Running $PROTO scan on port $PORT on $file"

        zgrab2 http \
            --input-file $file \
            --port $PORT \
            --output-file "zgrab2/${PROTO}_${basename}.json"
    done
done
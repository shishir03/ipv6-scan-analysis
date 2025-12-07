#!/bin/bash

# Run xmap scans on both ICMP and TCP

current_date=$(date +%Y-%m-%d)

xmap \
  -M icmp_echo_gw \
  --max-len=64 \
  --list-of-ips-file=all_ipsx2 \
  --rate=75000 \
  --output-module=json \
  --output-fields="saddr,success,data,timestamp_str,hlim" \
  -o xmap/xmap_icmp_${current_date}.json

xmap \
  -M tcp_syn \
  -p 443 \
  --max-len=64 \
  --list-of-ips-file=all_ipsx2 \
  --rate=75000 \
  --output-module=json \
  --output-fields="saddr,success,timestamp_str,hlim" \
  -o xmap/xmap_tcp_${current_date}.json

( jq -r 'select(.success == 1) | .saddr' xmap/xmap_icmp_${current_date}.json ) | sort -u > xmap_addr/icmp_${current_date}.txt
( jq -r 'select(.success == true) | .saddr' xmap/xmap_tcp_${current_date}.json ) | sort -u > xmap_addr/tcp_${current_date}.txt

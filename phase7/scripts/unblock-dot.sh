#!/bin/sh
set -eu

docker compose exec -T edge-router \
  iptables -D FORWARD -p tcp -d 172.16.2.11 --dport 853 -j DROP 2>/dev/null || true
echo "TCP/853 block removed."

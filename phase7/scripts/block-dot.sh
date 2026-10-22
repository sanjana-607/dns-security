#!/bin/sh
set -eu

docker compose exec -T edge-router \
  iptables -I FORWARD -p tcp -d 172.16.2.11 --dport 853 -j DROP
echo "TCP/853 blocked on edge-router."

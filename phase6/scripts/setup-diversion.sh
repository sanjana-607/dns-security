#!/bin/sh
set -eu

# Edge-router sends resolver-to-client packets through the attacker.
docker compose exec -T edge-router \
  ip route replace 172.16.1.10/32 via 172.16.1.100

echo "Diversion route installed:"
docker compose exec -T edge-router ip route get 172.16.1.10

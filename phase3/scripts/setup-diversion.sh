#!/bin/sh
set -eu

# Core-router sends resolver-bound packets through the attacker.
docker compose exec -T core-router \
  ip route replace 172.16.2.10/32 via 172.16.2.100

echo "Diversion route installed:"
docker compose exec -T core-router ip route get 172.16.2.10

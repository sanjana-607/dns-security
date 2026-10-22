#!/bin/sh
set -eu

# Remove the diversion route on core-router.
docker compose exec -T core-router \
  ip route del 172.16.2.10/32 2>/dev/null || true

echo "Diversion route removed. Current route to resolver:"
docker compose exec -T core-router ip route get 172.16.2.10

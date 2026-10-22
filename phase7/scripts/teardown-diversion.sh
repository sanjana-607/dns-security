#!/bin/sh
set -eu

# Remove the diversion route on edge-router.
docker compose exec -T edge-router \
  ip route del 172.16.1.10/32 2>/dev/null || true

echo "Diversion route removed. Current route to client:"
docker compose exec -T edge-router ip route get 172.16.1.10

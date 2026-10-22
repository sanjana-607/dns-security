#!/bin/sh
set -eu

PHASE5_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PHASE5_DIR"

echo "Starting the Phase 5 zone walker..."
docker compose exec -T attacker /app/zonewalker 172.16.2.10 example.com.

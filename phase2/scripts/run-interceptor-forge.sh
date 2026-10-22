#!/bin/sh
set -eu

echo "Stopping any running interceptor"
docker compose exec -T attacker pkill -f /app/interceptor 2>/dev/null || true

echo "Starting interceptor in FORGING mode (FORGE=1)"
docker compose exec -d -e FORGE=1 attacker sh -c "/app/interceptor > /tmp/interceptor.log 2>&1"
sleep 1

docker compose exec -T attacker head -n 10 /tmp/interceptor.log

#!/bin/sh
set -eu

echo "Stopping interceptor on attacker"
docker compose exec -T attacker pkill -f /app/interceptor 2>/dev/null || true
echo "Interceptor stopped."

#!/bin/sh
set -eu

docker compose exec -T client update-ca-certificates
echo "CS6008 CA installed in the client trust store."

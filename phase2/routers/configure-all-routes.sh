#!/bin/sh
set -eu

# Client -> resolver network
docker compose exec -T client \
  ip route replace 172.16.2.0/24 via 172.16.1.2

# Resolver -> authoritative and client networks
docker compose exec -T resolver \
  ip route replace 172.16.3.0/24 via 172.16.2.3
docker compose exec -T resolver \
  ip route replace 172.16.1.0/24 via 172.16.2.2

# Root, TLD, and domain nameservers -> resolver network
for ns in root-ns tld-ns domain-ns; do
  docker compose exec -T "$ns" \
    ip route replace 172.16.2.0/24 via 172.16.3.3
done

# Edge router -> authoritative network
docker compose exec -T edge-router \
  ip route replace 172.16.3.0/24 via 172.16.2.3

# Core router -> client network
docker compose exec -T core-router \
  ip route replace 172.16.1.0/24 via 172.16.2.2

echo "Static routes configured."

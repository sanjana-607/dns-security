#!/bin/sh
set -eu

docker compose exec -T client \
  kdig +tls-ca=/etc/ssl/certs/ca-certificates.crt \
  +tls-hostname=resolver.cs6008.local \
  @resolver.cs6008.local example.com A

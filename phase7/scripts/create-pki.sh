#!/bin/sh
set -eu

PHASE7_DIR="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
cd "$PHASE7_DIR"

mkdir -p pki
rm -f pki/ca.key pki/ca.crt pki/resolver.key pki/resolver.csr pki/resolver.crt

openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -subj "/CN=CS6008 Phase 7 CA" \
  -keyout pki/ca.key -out pki/ca.crt

openssl req -newkey rsa:2048 -nodes \
  -subj "/CN=resolver.cs6008.local" \
  -keyout pki/resolver.key -out pki/resolver.csr

cat > pki/resolver.ext <<'EOF'
subjectAltName=DNS:resolver.cs6008.local
extendedKeyUsage=serverAuth
EOF

openssl x509 -req -days 365 \
  -in pki/resolver.csr \
  -CA pki/ca.crt -CAkey pki/ca.key -CAcreateserial \
  -extfile pki/resolver.ext \
  -out pki/resolver.crt

rm -f pki/resolver.csr pki/resolver.ext pki/ca.srl
chmod 0600 pki/ca.key pki/resolver.key
echo "Private CA and resolver certificate created."

#!/bin/sh
set -eu

PHASE7_DIR="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
cd "$PHASE7_DIR"

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/phase7-rogue-cert.XXXXXX")"

restore() {
    if [ -f "$tmp_dir/resolver.crt" ] && [ -f "$tmp_dir/resolver.key" ]; then
        cp "$tmp_dir/resolver.crt" pki/resolver.crt
        cp "$tmp_dir/resolver.key" pki/resolver.key
        docker compose restart dot-proxy >/dev/null 2>&1 || true
    fi
    rm -rf "$tmp_dir"
}
trap restore EXIT INT TERM

cp pki/resolver.crt "$tmp_dir/resolver.crt"
cp pki/resolver.key "$tmp_dir/resolver.key"

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj "/CN=resolver.cs6008.local" \
    -addext "subjectAltName=DNS:resolver.cs6008.local" \
    -keyout pki/resolver.key \
    -out pki/resolver.crt \
    2>/dev/null

docker compose restart dot-proxy >/dev/null
echo "Testing an untrusted certificate with the correct hostname SAN..."

if "$PHASE7_DIR/scripts/query-dot.sh"; then
    echo "ERROR: the client accepted the rogue certificate."
    exit 1
else
    echo "PASS: strict DoT validation rejected the rogue certificate."
fi

echo "Testing the fallback-permitting client with the same rogue certificate..."
"$PHASE7_DIR/scripts/query-fallback.sh"
echo "PASS: fallback client used cleartext only after DoT certificate validation failed."

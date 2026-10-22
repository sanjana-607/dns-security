#!/bin/sh
set -eu

PHASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PHASE_DIR"

echo "=== Generating DNSSEC Keys and Signing Zones for Phase 7 ==="

# Run the signing operations inside the BIND 9 container so all tools are available
docker run --rm \
  --entrypoint /bin/sh \
  -v "$PHASE_DIR:/work" \
  -w /work \
  internetsystemsconsortium/bind9:9.20 -c '
set -eu

# Clean up any existing keys, dsset files, and signed zones
rm -f domain-ns/zones/K* domain-ns/zones/dsset-* domain-ns/zones/*.signed
rm -f tld-ns/zones/K* tld-ns/zones/dsset-* tld-ns/zones/*.signed
rm -f root-ns/zones/K* root-ns/zones/dsset-* root-ns/zones/*.signed

echo "[1/4] Signing example.com on domain-ns..."
cd /work/domain-ns/zones
# Clean any previous DS records
grep -v -E "DNSKEY| IN DS " db.example.com > db.example.com.clean && mv db.example.com.clean db.example.com

ZSK_EXAMPLE=$(dnssec-keygen -a ECDSAP256SHA256 -n ZONE example.com)
KSK_EXAMPLE=$(dnssec-keygen -a ECDSAP256SHA256 -f KSK -n ZONE example.com)
cat ${ZSK_EXAMPLE}.key >> db.example.com
cat ${KSK_EXAMPLE}.key >> db.example.com

dnssec-signzone -o example.com -k ${KSK_EXAMPLE} db.example.com ${ZSK_EXAMPLE}
echo "  Signed example.com -> db.example.com.signed"

echo "[2/4] Signing com on tld-ns..."
cd /work/tld-ns/zones
# Clean any previous DS records
grep -v -E "DNSKEY| IN DS " db.com > db.com.clean && mv db.com.clean db.com
cat /work/domain-ns/zones/dsset-example.com. >> db.com

ZSK_COM=$(dnssec-keygen -a ECDSAP256SHA256 -n ZONE com)
KSK_COM=$(dnssec-keygen -a ECDSAP256SHA256 -f KSK -n ZONE com)
cat ${ZSK_COM}.key >> db.com
cat ${KSK_COM}.key >> db.com

dnssec-signzone -o com -k ${KSK_COM} db.com ${ZSK_COM}
echo "  Signed com -> db.com.signed"

echo "[3/4] Signing root (.) on root-ns..."
cd /work/root-ns/zones
# Clean any previous DS records
grep -v -E "DNSKEY| IN DS " db.root > db.root.clean && mv db.root.clean db.root
cat /work/tld-ns/zones/dsset-com. >> db.root

ZSK_ROOT=$(dnssec-keygen -a ECDSAP256SHA256 -n ZONE .)
KSK_ROOT=$(dnssec-keygen -a ECDSAP256SHA256 -f KSK -n ZONE .)
cat ${ZSK_ROOT}.key >> db.root
cat ${KSK_ROOT}.key >> db.root

dnssec-signzone -o . -k ${KSK_ROOT} db.root ${ZSK_ROOT}
echo "  Signed root -> db.root.signed"

echo "[4/4] Generating Trust Anchor for Resolver..."
# Extract public key from Root KSK
# Format: . IN DNSKEY 257 3 13 <pubkey>
ROOT_PUBKEY=$(awk '\''$3 == "DNSKEY" && $4 == "257" {for(i=7;i<=NF;++i) printf "%s%s", $i, (i==NF?"":" ")}'\'' /work/root-ns/zones/${KSK_ROOT}.key)

cat << EOF > /work/resolver/trust-anchors.conf
trust-anchors {
    "." static-key 257 3 13 "${ROOT_PUBKEY}";
};
EOF

# Also create root.key for delv verification on client
cat << EOF > /work/client/root.key
trust-anchors {
    "." static-key 257 3 13 "${ROOT_PUBKEY}";
};
EOF

echo "  Trust anchor installed in resolver/trust-anchors.conf and client/root.key"
echo "DNSSEC signing completed successfully."
'

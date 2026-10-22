#!/bin/sh
set -eu

PHASE5_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PHASE5_DIR"

echo "=== [Phase 5] Signing Zones with NSEC3 (Fixed Zone - Walking Prevented) ==="

docker run --rm \
  --entrypoint /bin/sh \
  -v "$PHASE5_DIR:/work" \
  -w /work \
  internetsystemsconsortium/bind9:9.20 -c '
set -eu

# Clean up existing keys and signed files
rm -f domain-ns/zones/K* domain-ns/zones/dsset-* domain-ns/zones/*.signed
rm -f tld-ns/zones/K* tld-ns/zones/dsset-* tld-ns/zones/*.signed
rm -f root-ns/zones/K* root-ns/zones/dsset-* root-ns/zones/*.signed

# Restore templates: use db.example.com.fixed for example.com
cp domain-ns/zones/db.example.com.fixed domain-ns/zones/db.example.com
cp tld-ns/zones/db.com.template tld-ns/zones/db.com
cp root-ns/zones/db.root.template root-ns/zones/db.root

echo "[1/4] Signing example.com on domain-ns with NSEC3..."
cd /work/domain-ns/zones
ZSK_EXAMPLE=$(dnssec-keygen -a ECDSAP256SHA256 -n ZONE example.com)
KSK_EXAMPLE=$(dnssec-keygen -a ECDSAP256SHA256 -f KSK -n ZONE example.com)
cat ${ZSK_EXAMPLE}.key >> db.example.com
cat ${KSK_EXAMPLE}.key >> db.example.com

# NSEC3 authenticated denial of existence with 10 iterations and a 16-hex-digit salt
SALT="DEADBEEFCAFE1234"
dnssec-signzone -3 "${SALT}" -H 10 -o example.com -k ${KSK_EXAMPLE} db.example.com ${ZSK_EXAMPLE}

echo "[2/4] Signing com on tld-ns WITH example.com DS..."
cd /work/tld-ns/zones
cat /work/domain-ns/zones/dsset-example.com. >> db.com
ZSK_COM=$(dnssec-keygen -a ECDSAP256SHA256 -n ZONE com)
KSK_COM=$(dnssec-keygen -a ECDSAP256SHA256 -f KSK -n ZONE com)
cat ${ZSK_COM}.key >> db.com
cat ${KSK_COM}.key >> db.com
dnssec-signzone -o com -k ${KSK_COM} db.com ${ZSK_COM}

echo "[3/4] Signing root (.) on root-ns WITH com DS..."
cd /work/root-ns/zones
cat /work/tld-ns/zones/dsset-com. >> db.root
ZSK_ROOT=$(dnssec-keygen -a ECDSAP256SHA256 -n ZONE .)
KSK_ROOT=$(dnssec-keygen -a ECDSAP256SHA256 -f KSK -n ZONE .)
cat ${ZSK_ROOT}.key >> db.root
cat ${KSK_ROOT}.key >> db.root
dnssec-signzone -o . -k ${KSK_ROOT} db.root ${ZSK_ROOT}

echo "[4/4] Updating Resolver Trust Anchor..."
ROOT_PUBKEY=$(awk '\''$3 == "DNSKEY" && $4 == "257" {for(i=7;i<=NF;++i) printf "%s%s", $i, (i==NF?"":" ")}'\'' /work/root-ns/zones/${KSK_ROOT}.key)

cat << EOF > /work/resolver/trust-anchors.conf
trust-anchors {
    "." static-key 257 3 13 "${ROOT_PUBKEY}";
};
EOF

cat << EOF > /work/client/root.key
trust-anchors {
    "." static-key 257 3 13 "${ROOT_PUBKEY}";
};
EOF

echo "Signing complete: example.com signed with NSEC3 (walking prevented)."
'

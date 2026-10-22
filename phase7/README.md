# Phase 7 - Encrypting the Last Mile with DoT

This phase reuses the signed DNS hierarchy from Phase 3 and encrypts the
client-to-resolver connection with DNS-over-TLS (DoT).

The resolver is reached by the required hostname:

```text
resolver.cs6008.local -> 172.16.2.11 (the DoT endpoint)
```

The certificate has this name as its DNS SAN and is signed by the local CA.
The client trusts the CA; no insecure certificate bypass is used.

## Run

```bash
cd dns_security/phase7
./scripts/sign-zones.sh
./scripts/create-pki.sh
docker compose build
docker compose up -d
./routers/configure-all-routes.sh
./scripts/install-ca.sh
```

Verify encrypted DNS:

```bash
./scripts/query-dot.sh
```

The output should contain `status: NOERROR`, `172.16.1.20`, and a successful
TLS handshake. A packet capture on `edge-router` should show TCP/853 rather
than cleartext DNS payloads.

## Required attack cases

### Alter the answer in transit

```bash
./scripts/setup-diversion.sh
./scripts/run-interceptor-forge.sh
./scripts/query-dot.sh
./scripts/query-fallback.sh
```

The Phase 6 UDP interceptor cannot alter a DoT stream. The TLS endpoint
detects any modified ciphertext and both clients either receive the
authentic answer or fail; neither accepts a forged DoT answer.

### Impersonate the resolver

The client connects by hostname and validates the private-CA certificate.
The following test temporarily replaces the proxy certificate with a
self-signed certificate that has the correct hostname SAN:

```bash
./scripts/test-rogue-certificate.sh
```

The strict client must reject the TLS handshake. The script restores the
legitimate certificate automatically.

### Deny DoT and test fallback

```bash
./scripts/block-dot.sh
./scripts/query-dot.sh
./scripts/query-fallback.sh
./scripts/unblock-dot.sh
```

The strict DoT client fails closed. It does not silently use cleartext DNS.
The fallback client first tries DoT and then explicitly runs
`query-cleartext.sh` through the shell; it resolves only after losing the
encrypted transport.

## Cleanup

```bash
./scripts/unblock-dot.sh
./scripts/stop-interceptor.sh
./scripts/teardown-diversion.sh
docker compose down
```

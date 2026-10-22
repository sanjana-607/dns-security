# Phase 3 — DNSSEC Chain of Trust

This directory contains the complete implementation for Phase 3: deploying a three-tier DNSSEC cryptographic chain of trust across all authoritative servers (`root-ns`, `tld-ns`, `domain-ns`), enabling DNSSEC validation on the recursive resolver anchored at the Root KSK, and repeating the Phase 2 on-path forgery attack to demonstrate that DNSSEC stops the attack.

---

## Topology & Roles

- **Client Subnet (`172.16.1.0/24`)**:
  - `client` (`172.16.1.10`): End host with `dig`, `delv`, and `curl`
  - `webserver` (`172.16.1.20`): Legitimate webserver serving `example.com`
  - `rogue-web` (`172.16.1.30`): Defaced webserver
  - `edge-router` (`172.16.1.2`)
- **Resolver Subnet (`172.16.2.0/24`)**:
  - `edge-router` (`172.16.2.2`)
  - `resolver` (`172.16.2.10`): Recursive resolver with `dnssec-validation yes;`
  - `attacker` (`172.16.2.100`): On-path adversary running C interceptor (Phase 2 binary unchanged)
  - `core-router` (`172.16.2.3`)
- **Authoritative Subnet (`172.16.3.0/24`)**:
  - `core-router` (`172.16.3.3`)
  - `root-ns` (`172.16.3.10`): Authoritative for `.`, signs root, publishes `com.` DS
  - `tld-ns` (`172.16.3.20`): Authoritative for `com.`, signs `com`, publishes `example.com.` DS
  - `domain-ns` (`172.16.3.30`): Authoritative for `example.com.`, signs `example.com`

---

## Step-by-Step Commands to Deploy, Verify, and Attack

All commands are executed from `dns_security/phase3`.

### Step 1: Sign Zones & Generate Trust Anchor

Sign the DNS hierarchy bottom-up using `ECDSAP256SHA256` (Algorithm 13), building the delegation chain (`example.com` DS $\rightarrow$ `com` $\rightarrow$ `com` DS $\rightarrow$ root), and exporting the Root KSK trust anchor:

```bash
cd dns_security/phase3

# Generate keys, chain DS records, sign zones, and export resolver trust anchor
./scripts/sign-zones.sh
```

---

### Step 2: Deploy Containers & Static Routes

```bash
# Build and start all 10 containers
docker compose up --build -d

# Configure static routing across subnets
./routers/configure-all-routes.sh
```

---

### Step 3: Section 3.2 — Verify DNSSEC Chain of Trust

Before enabling the interceptor, verify that the resolver authenticates responses and establishes the cryptographic chain:

```bash
# 1. Query with +dnssec: check for 'ad' flag and RRSIG in answer
docker compose exec -T client dig +dnssec @172.16.2.10 example.com

# 2. Validate complete chain of trust with delv anchored at root.key
docker compose exec -T client delv -a /etc/bind/root.key @172.16.2.10 example.com

# 3. Verify legitimate site fetch succeeds
docker compose exec -T client curl -s http://example.com
```

**Expected results:**
- `dig` returns `flags: qr rd ra ad;` with `172.16.1.20` and an `RRSIG` record.
- `delv` prints `; fully validated`.
- `curl` displays `Legitimate example.com`.

---

### Step 4: Section 3.3 — Re-run the On-Path Attack

Enable the on-path interceptor in forging mode (`FORGE=1`), flush the resolver cache, and observe the defense:

```bash
# 1. Install diversion route on core-router
./scripts/setup-diversion.sh

# 2. Start interceptor in forging mode
./scripts/run-interceptor-forge.sh

# 3. Flush the resolver cache
docker compose exec -T resolver rndc flush

# 4. Attempt lookup from client
docker compose exec -T client dig @172.16.2.10 example.com

# 5. Attempt HTTP fetch from client
docker compose exec -T client curl -v http://example.com
```

**Expected results:**
- `dig` returns **`status: SERVFAIL`** (`ANSWER: 0`).
- `curl` fails with:
  ```
  curl: (6) Could not resolve host: example.com
  ```
- Resolver logs show signature verification failure:
  ```bash
  docker compose logs resolver | tail -n 10
  # Output: "validating example.com/A: no valid signature found"
  # Output: "RRSIG failed to verify resolving 'example.com/A/IN': 172.16.3.30#53"
  ```
- Interceptor logs show the forged injection attempt:
  ```bash
  docker compose exec -T attacker cat /tmp/interceptor.log
  # Output: "[FORGED] example.com A: 172.16.1.20 -> 172.16.1.30"
  ```

---

### Step 5: Verify Unaffected Non-Target Lookup

Verify that `www.example.com` (which is not altered by the interceptor) continues to validate cleanly and resolve to the legitimate webserver:

```bash
docker compose exec -T client dig +dnssec @172.16.2.10 www.example.com
docker compose exec -T client curl -s http://www.example.com
```

**Expected results:**
- Returns `status: NOERROR`, `flags: qr rd ra ad;`, and `A 172.16.1.20`.
- `curl` displays `Legitimate example.com`.

---

### Step 6: Teardown

```bash
# Stop the interceptor process
./scripts/stop-interceptor.sh

# Remove diversion route on core-router
./scripts/teardown-diversion.sh

# Stop containers
docker compose down
```

---

## Deliverables in `phase3/`

- `scripts/sign-zones.sh`: Automated DNSSEC key generation (Algorithm 13), DS chaining, zone signing, and trust anchor extraction.
- `domain-ns/zones/db.example.com.signed`: Cryptographically signed zone for `example.com`.
- `tld-ns/zones/db.com.signed`: Cryptographically signed `.com` zone containing `example.com` DS record.
- `root-ns/zones/db.root.signed`: Cryptographically signed root zone containing `com.` DS record.
- `resolver/trust-anchors.conf`: Root KSK trust anchor for BIND 9 resolver.
- `client/root.key`: Root KSK trust anchor for `delv`.
- `captures/attack_log.txt`: Complete terminal logs demonstrating validation, attack mitigation (`SERVFAIL`), and non-target lookups.

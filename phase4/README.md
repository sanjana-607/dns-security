# Phase 4 — Signature Stripping & Downgrade

This directory contains the complete implementation for Phase 4: evaluating DNSSEC downgrade resistance under on-the-wire signature stripping and operator misconfiguration.

---

## Topology & Roles

- **Client Subnet (`172.16.1.0/24`)**:
  - `client` (`172.16.1.10`): End host issuing DNS queries (`dig`, `delv`) and HTTP fetches (`curl`).
  - `webserver` (`172.16.1.20`): Real webserver serving legitimate `example.com`.
  - `rogue-web` (`172.16.1.30`): Defaced webserver.
  - `edge-router` (`172.16.1.2`).
- **Resolver Subnet (`172.16.2.0/24`)**:
  - `edge-router` (`172.16.2.2`).
  - `resolver` (`172.16.2.10`): Recursive caching resolver with `dnssec-validation yes;` anchored at Root KSK.
  - `attacker` (`172.16.2.100`): On-path adversary running C interceptor with strip mode (`STRIP=1`).
  - `core-router` (`172.16.2.3`).
- **Authoritative Subnet (`172.16.3.0/24`)**:
  - `core-router` (`172.16.3.3`).
  - `root-ns` (`172.16.3.10`): Authoritative for `.`, signs root, publishes `com.` DS.
  - `tld-ns` (`172.16.3.20`): Authoritative for `com.`, signs `com`.
  - `domain-ns` (`172.16.3.30`): Authoritative for `example.com.`, signs `example.com`.

---

## Step-by-Step Instructions to Reproduce

All commands must be executed from `dns_security/phase4`.

### Step 1: Generate the signed hierarchy

```bash
cd dns_security/phase4

# 1. Generate the DNSSEC zones and trust anchor
./scripts/sign-zones-run-a.sh

# 2. Build and start containers
docker compose up --build -d

# 3. Configure static routes across subnets
./routers/configure-all-routes.sh
```

---

### Step 2: Run A — Secure Delegation (Strip Rejected with SERVFAIL)

In Run A, `example.com` is fully signed, and parent `com` publishes `example.com`'s DS record.

```bash
# 1. Reload nameservers and flush resolver
docker kill -s HUP root-ns tld-ns domain-ns
docker compose exec -T resolver rndc reconfig
docker compose exec -T resolver rndc flush

# 3. Verify baseline (Section 4.2): authenticated answer with 'ad' flag
docker compose exec -T client dig +dnssec @172.16.2.10 example.com
docker compose exec -T client delv -a /etc/bind/root.key @172.16.2.10 example.com

# 4. Start interceptor in strip mode (STRIP=1) and install diversion route
./scripts/run-interceptor-strip.sh
./scripts/setup-diversion.sh
docker compose exec -T resolver rndc flush

# 5. Attack verification: resolver detects stripped signatures and returns SERVFAIL
docker compose exec -T client dig @172.16.2.10 example.com
docker compose exec -T client curl -v http://example.com
```

**Expected Run A Outcome**:
- `dig` returns `status: SERVFAIL`.
- `curl` fails with `curl: (6) Could not resolve host: example.com`.
- Resolver logs `validating example.com/A: no valid signature found`.

---

### Step 3: Run B — Operator Misconfiguration (Attack Succeeds)

In Run B, `example.com` remains fully signed by the child operator, but the parent `com` publishes NO DS record.

```bash
# 1. Sign zones WITHOUT example.com DS in com
./scripts/sign-zones-run-b.sh

# 2. Teardown diversion, stop interceptor, and reload nameservers
./scripts/teardown-diversion.sh
./scripts/stop-interceptor.sh
docker kill -s HUP root-ns tld-ns domain-ns
docker compose exec -T resolver rndc reconfig
docker compose exec -T resolver rndc flush

# 3. Check baseline without interceptor: resolves cleanly but WITHOUT 'ad' flag
docker compose exec -T client dig @172.16.2.10 example.com

# 4. Start interceptor in strip mode (STRIP=1) and install diversion route
./scripts/run-interceptor-strip.sh
./scripts/setup-diversion.sh
docker compose exec -T resolver rndc flush

# 5. Attack verification: validating resolver accepts forged A record!
docker compose exec -T client dig @172.16.2.10 example.com
docker compose exec -T client curl -s http://example.com

# 6. Verify non-target lookup remains unaffected
docker compose exec -T client dig @172.16.2.10 www.example.com
docker compose exec -T client curl -s http://www.example.com
```

**Expected Run B Outcome**:
- `dig` returns `status: NOERROR` and `172.16.1.30` (without `ad` flag).
- `curl http://example.com` returns the **Rogue Website** defacement page.
- `curl http://www.example.com` returns the **Legitimate example.com** page.

---

### Step 4: Teardown

```bash
./scripts/teardown-diversion.sh
./scripts/stop-interceptor.sh
docker compose down
```

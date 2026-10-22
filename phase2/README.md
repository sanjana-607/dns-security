# Phase 2 — On-Path Response Forgery

This directory contains the complete implementation for Phase 2: deploying an on-path DNS interceptor on the resolver's subnet, diverting authoritative replies through the attacker, and selectively forging DNS responses for `example.com` while transparently relaying non-target traffic.

---

## Architecture & Subnets

- **Client Subnet (`172.16.1.0/24`)**:
  - `client` (`172.16.1.10`): End host issuing DNS lookups and HTTP requests
  - `webserver` (`172.16.1.20`): Legitimate webserver serving `example.com`
  - `rogue-web` (`172.16.1.30`): Rogue webserver serving defacement page
  - `edge-router` (`172.16.1.2`)
- **Resolver Subnet (`172.16.2.0/24`)**:
  - `edge-router` (`172.16.2.2`)
  - `resolver` (`172.16.2.10`): Recursive caching resolver (BIND 9.20)
  - `attacker` (`172.16.2.100`): On-path adversary running C libpcap interceptor
  - `core-router` (`172.16.2.3`)
- **Authoritative Subnet (`172.16.3.0/24`)**:
  - `core-router` (`172.16.3.3`)
  - `root-ns` (`172.16.3.10`): Authoritative nameserver for root (`.`)
  - `tld-ns` (`172.16.3.20`): Authoritative nameserver for `.com`
  - `domain-ns` (`172.16.3.30`): Authoritative nameserver for `example.com`

---

## Step-by-Step Commands to Deploy, Verify, and Attack

All commands are executed from within the `dns_security/phase2` directory.

### Step 1: Deploy Containers and Static Routes

```bash
cd dns_security/phase2

# Build and start all 10 containers
docker compose up --build -d

# Configure static routing across subnets
./routers/configure-all-routes.sh
```

---

### Step 2: Verify Transparent Relay (Section 2.2)

In this mode, response traffic is diverted through the attacker, but the interceptor relays all DNS packets unmodified.

```bash
# 1. Install response diversion route on core-router
./scripts/setup-phase2-diversion.sh

# 2. Start interceptor in transparent relay mode
./scripts/run-interceptor-relay.sh

# 3. Flush resolver cache
docker compose exec -T resolver rndc flush

# 4. Verify from client (resolves to genuine IP 172.16.1.20 and legitimate site)
docker compose exec -T client dig @172.16.2.10 example.com
docker compose exec -T client curl -s http://example.com
```

**Expected output:**
- `example.com` resolves to `172.16.1.20`
- `curl` prints `Legitimate example.com`
- Interceptor logs in `/tmp/interceptor.log` show `[RELAY] ...`

---

### Step 3: Execute the Forgery Attack (Section 2.3)

Enable response forging for `example.com`.

```bash
# 1. Switch interceptor to forging mode (FORGE=1)
./scripts/run-interceptor-forge.sh

# 2. Flush the resolver cache
docker compose exec -T resolver rndc flush

# 3. Resolve example.com from client -> poisoned to rogue-web!
docker compose exec -T client dig @172.16.2.10 example.com
docker compose exec -T client curl -s http://example.com
```

**Expected output:**
- `example.com` resolves to `172.16.1.30`
- `curl` returns:
  ```html
  <h1>Rogue Website</h1>
  <p>Phase 2 DNS response forgery succeeded.</p>
  ```
- Interceptor logs show:
  ```
  [FORGED] (TXID 0x...) example.com A: 172.16.1.20 -> 172.16.1.30
  ```

---

### Step 4: Verify Non-Target Lookup Undisturbed (Section 2.3)

Verify that non-target lookups (`www.example.com`) continue to resolve to the legitimate webserver:

```bash
docker compose exec -T client dig @172.16.2.10 www.example.com
docker compose exec -T client curl -s http://www.example.com
```

**Expected output:**
- `www.example.com` resolves to `172.16.1.20`
- `curl` prints `Legitimate example.com`
- Interceptor logs show `[RELAY] ... DNS response forwarded unchanged`

---

### Step 5: Teardown / Cleanup

To stop the attack interceptor and remove the diversion route:

```bash
# Stop interceptor process on attacker
./scripts/stop-interceptor.sh

# Remove diversion route on core-router
./scripts/teardown-phase2-diversion.sh

# Stop and remove containers
docker compose down
```

---

## Deliverables & Files

- `compose.yml`: Complete 10-container topology with custom bridge networks, volume mounts, and capability definitions (`NET_ADMIN`, `NET_RAW`).
- `attacker/interceptor.c` & `attacker/Makefile`: C interceptor using `libpcap` for capture and injection.
- `scripts/setup-phase2-diversion.sh`: Installs `/32` reply diversion route on `core-router`.
- `scripts/teardown-phase2-diversion.sh`: Restores baseline routing on `core-router`.
- `scripts/run-interceptor-relay.sh`: Starts interceptor in transparent relay mode.
- `scripts/run-interceptor-forge.sh`: Starts interceptor in forging mode.
- `scripts/stop-interceptor.sh`: Stops running interceptor.
- `resolver/named.conf` & `resolver/rndc.conf`: Configured with control keys for `rndc flush`.

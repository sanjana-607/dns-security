# Phase 6 - Last-Mile Response Forgery

Phase 6 reuses the Phase 3 DNSSEC hierarchy. The resolver still validates the
authoritative response, but the attacker is moved to the client subnet:

```text
attacker: 172.16.1.100
client:   172.16.1.10
resolver: 172.16.2.10
rogue:    172.16.1.30
```

The edge router sends packets destined for the client through the attacker.
The attacker relays DNS responses unchanged in normal mode and changes the
`example.com` A record to `172.16.1.30` in forge mode.

## Run

Run from this directory:

```bash
cd dns_security/phase6
./scripts/sign-zones.sh
docker compose build
docker compose up -d
./routers/configure-all-routes.sh
./scripts/setup-diversion.sh
```

### 1. Transparent relay

```bash
./scripts/run-interceptor-relay.sh
docker compose exec -T client dig @172.16.2.10 example.com
docker compose exec -T client curl -s http://example.com
docker compose exec -T client delv -a /etc/bind/root.key @172.16.2.10 example.com
```

The ordinary lookup and `curl` request reach the legitimate site, and `delv`
reports `fully validated`.

### 2. Forge the last-mile response

```bash
./scripts/run-interceptor-forge.sh
docker compose exec -T resolver rndc flush
docker compose exec -T client dig @172.16.2.10 example.com
docker compose exec -T client curl -s http://example.com
docker compose exec -T client delv -a /etc/bind/root.key @172.16.2.10 example.com
```

Expected result:

- The ordinary stub accepts `172.16.1.30` and displays the rogue page.
- `delv` rejects the modified answer because its local trust anchor verifies
  the original RRSIG and the A record no longer matches it.

The interceptor can set the `AD` flag because that flag is only a claim in the
unprotected client-side DNS packet. A normal stub does not independently
verify it.

### Cleanup

```bash
./scripts/stop-interceptor.sh
./scripts/teardown-diversion.sh
docker compose down
```

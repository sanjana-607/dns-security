# Phase 5 - DNSSEC Zone Walking

Phase 5 demonstrates the privacy difference between standard NSEC and NSEC3.
DNSSEC protects authenticity and integrity, but standard NSEC records also
publish the next name in the zone. An attacker can use those records to walk
through a zone and discover names that are not linked from the public website.
NSEC3 hashes names before publishing them, which prevents this simple walk.

## What is included

- `sign-walkable-zone.sh` signs `example.com` with standard NSEC.
- `sign-fixed-zone.sh` signs `example.com` with NSEC3.
- `sign-zones.sh` is a short alias for the safer NSEC3 configuration.
- `attacker/zonewalker.c` queries denial responses and follows NSEC records
  within the assignment's query budget.
- `scripts/run-zonewalker.sh` runs the walker against the recursive resolver.
- `domain-ns/zones/db.example.com.walkable` contains hidden test names.
- `domain-ns/zones/db.example.com.fixed` contains the same names for the NSEC3
  test.

The hidden names are `billing`, `dev`, `mail`, `payroll`, `secret`, and `vpn`.
They are deliberately included only to make the experiment observable.

The assignment requires the Phase 5 zone-walker to be written in C or C++
using libpcap for packet capture and injection. `dig` may be used to inspect
individual denial responses and verify results, but it does not replace the
required automated walker.

## Run the experiment

Run all commands from this directory:

```bash
cd dns_security/phase5

# 1. Generate the walkable signed hierarchy.
./scripts/sign-walkable-zone.sh

# 2. Build the containers.
docker compose build

# 3. Start the DNS hierarchy.
docker compose up -d

# 4. Configure routing between the three Docker networks.
./routers/configure-all-routes.sh
```

### A. Show that NSEC can be walked

```bash
docker compose restart root-ns tld-ns domain-ns resolver
./routers/configure-all-routes.sh
./scripts/run-zonewalker.sh
```

Expected result: the walker reports `SUCCESS (Zone Walk Complete via NSEC)`
and prints the names and addresses it discovered.

### B. Show that NSEC3 prevents the walk

```bash
./scripts/sign-fixed-zone.sh
docker compose restart root-ns tld-ns domain-ns resolver
./routers/configure-all-routes.sh
./scripts/run-zonewalker.sh
```

Expected result: the walker reports `FAILURE (Zone Protected by NSEC3)` and
`Names Leaked: 0`. The failure is the expected security result: the attacker
receives an NSEC3 hash, not the next plaintext domain name.

### Cleanup

```bash
docker compose down
```

## Notes

- Run only one signing script at a time because each script replaces the
  generated keys and signed zones.
- The scripts generate DNSSEC private keys locally in the zone directories.
  Do not publish those generated `.private` files in a real project.
- DNSSEC does not encrypt DNS traffic. An on-path observer can still see query
  names and responses; NSEC3 only prevents this particular zone-walking
  technique.

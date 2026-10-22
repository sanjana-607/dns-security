$TTL 86400
@   IN  SOA ns.com. hostmaster.com. (
        2026102101
        3600
        1800
        604800
        86400
)
    IN  NS  ns.com.
ns.com. IN  A   172.16.3.20

example.com.       IN  NS  ns.example.com.
ns.example.com.    IN  A   172.16.3.30
example.com.		IN DS 15445 13 2 15AEBA05E725A7544E2A43BC87D0315E2E6EDA046EAA9192009BD1A2 E477AA6B
; This is a zone-signing key, keyid 61773, for com.
; Created: 20261022214349 (Thu Oct 22 21:43:49 2026)
; Publish: 20261022214349 (Thu Oct 22 21:43:49 2026)
; Activate: 20261022214349 (Thu Oct 22 21:43:49 2026)
com. IN DNSKEY 256 3 13 M/mJYsrFRrJL3T8VhlpNG42q/bdcHwWowTZ3bD2Wrkb4LNp0IUDXgrgf KlwPaN39k1WyI4/80PaDee6COwC/qg==
; This is a key-signing key, keyid 48614, for com.
; Created: 20261022214349 (Thu Oct 22 21:43:49 2026)
; Publish: 20261022214349 (Thu Oct 22 21:43:49 2026)
; Activate: 20261022214349 (Thu Oct 22 21:43:49 2026)
com. IN DNSKEY 257 3 13 0F/JL9M8NkTo0o2SeEnlXAB/mJlvMMiU0muZjGs1VeDYRNC4zMI3lRjR Cyy1nYwM3Qx9rXD9z4YqktpPoqbvCw==

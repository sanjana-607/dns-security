$TTL 86400
@   IN  SOA ns.example.com. hostmaster.example.com. (
        2026102101
        3600
        1800
        604800
        86400
)
    IN  NS  ns.example.com.
ns  IN  A   172.16.3.30

@       IN  A   172.16.1.20
www     IN  A   172.16.1.20

; This is a zone-signing key, keyid 55726, for example.com.
; Created: 20261022163812 (Thu Oct 22 16:38:12 2026)
; Publish: 20261022163812 (Thu Oct 22 16:38:12 2026)
; Activate: 20261022163812 (Thu Oct 22 16:38:12 2026)
; This is a key-signing key, keyid 39567, for example.com.
; Created: 20261022163812 (Thu Oct 22 16:38:12 2026)
; Publish: 20261022163812 (Thu Oct 22 16:38:12 2026)
; Activate: 20261022163812 (Thu Oct 22 16:38:12 2026)
; This is a zone-signing key, keyid 34384, for example.com.
; Created: 20261022163848 (Thu Oct 22 16:38:48 2026)
; Publish: 20261022163848 (Thu Oct 22 16:38:48 2026)
; Activate: 20261022163848 (Thu Oct 22 16:38:48 2026)
; This is a key-signing key, keyid 42561, for example.com.
; Created: 20261022163848 (Thu Oct 22 16:38:48 2026)
; Publish: 20261022163848 (Thu Oct 22 16:38:48 2026)
; Activate: 20261022163848 (Thu Oct 22 16:38:48 2026)
; This is a zone-signing key, keyid 16335, for example.com.
; Created: 20261022215008 (Thu Oct 22 21:50:08 2026)
; Publish: 20261022215008 (Thu Oct 22 21:50:08 2026)
; Activate: 20261022215008 (Thu Oct 22 21:50:08 2026)
example.com. IN DNSKEY 256 3 13 GfivzXelDF5yGAz0sBbQJkdX8vmoiY7cPdm4hvJ60DZO+fqBFhTfeEPT 4AkbGQ2T9EIddp+zQBAqfZTxs17UCQ==
; This is a key-signing key, keyid 26424, for example.com.
; Created: 20261022215008 (Thu Oct 22 21:50:08 2026)
; Publish: 20261022215008 (Thu Oct 22 21:50:08 2026)
; Activate: 20261022215008 (Thu Oct 22 21:50:08 2026)
example.com. IN DNSKEY 257 3 13 setFIeOXVTSHmxImWRo4kd6dhLaO2WaR+3Kwf0tk/S9gDqpN24Csh5Tq SefPV/UuLx8BW3KUH9iF9LoN4NmhHQ==

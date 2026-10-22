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
; This is a zone-signing key, keyid 48783, for com.
; Created: 20261022205610 (Thu Oct 22 20:56:10 2026)
; Publish: 20261022205610 (Thu Oct 22 20:56:10 2026)
; Activate: 20261022205610 (Thu Oct 22 20:56:10 2026)
com. IN DNSKEY 256 3 13 8HRJ5NBI9zK6DSiXkIkwwY/yRgG1On+UDmx3Dd9bO3sTrMdBGJ88/1Dh oIdK7QvolB34jkJYhWzoodbMmgtC9A==
; This is a key-signing key, keyid 27244, for com.
; Created: 20261022205610 (Thu Oct 22 20:56:10 2026)
; Publish: 20261022205610 (Thu Oct 22 20:56:10 2026)
; Activate: 20261022205610 (Thu Oct 22 20:56:10 2026)
com. IN DNSKEY 257 3 13 lY1x2ZXp/sZXKk6d03C+KI0QrONTpD0m27VXctz+nIr/W4pgq5uDEzFi 7j3c/ryGqtAd64SwrdLO9xd7kGU3zA==

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
; This is a zone-signing key, keyid 4587, for example.com.
; Created: 20261022205610 (Thu Oct 22 20:56:10 2026)
; Publish: 20261022205610 (Thu Oct 22 20:56:10 2026)
; Activate: 20261022205610 (Thu Oct 22 20:56:10 2026)
example.com. IN DNSKEY 256 3 13 2qM7KM+zIl+jaTvw64/fkAw5MegN+cQ+DUv9bu2kpqWW86CQ0ECh2wE7 zPvLpErAL9+XD/RniHa8SXyP5H68xA==
; This is a key-signing key, keyid 276, for example.com.
; Created: 20261022205610 (Thu Oct 22 20:56:10 2026)
; Publish: 20261022205610 (Thu Oct 22 20:56:10 2026)
; Activate: 20261022205610 (Thu Oct 22 20:56:10 2026)
example.com. IN DNSKEY 257 3 13 vXXDIm3KFoFdJT22Bi20ItuhVUINCGNbOkEskdmDZF6CeU7Ughgiwf98 atCrAVIHBBQeqb7JXjHezY8XOuOW+w==

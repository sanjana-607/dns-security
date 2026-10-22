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

; This is a zone-signing key, keyid 19738, for example.com.
; Created: 20261022163814 (Thu Oct 22 16:38:14 2026)
; Publish: 20261022163814 (Thu Oct 22 16:38:14 2026)
; Activate: 20261022163814 (Thu Oct 22 16:38:14 2026)
; This is a key-signing key, keyid 7924, for example.com.
; Created: 20261022163814 (Thu Oct 22 16:38:14 2026)
; Publish: 20261022163814 (Thu Oct 22 16:38:14 2026)
; Activate: 20261022163814 (Thu Oct 22 16:38:14 2026)
; This is a zone-signing key, keyid 1616, for example.com.
; Created: 20261022163849 (Thu Oct 22 16:38:49 2026)
; Publish: 20261022163849 (Thu Oct 22 16:38:49 2026)
; Activate: 20261022163849 (Thu Oct 22 16:38:49 2026)
; This is a key-signing key, keyid 15784, for example.com.
; Created: 20261022163849 (Thu Oct 22 16:38:49 2026)
; Publish: 20261022163849 (Thu Oct 22 16:38:49 2026)
; Activate: 20261022163849 (Thu Oct 22 16:38:49 2026)
; This is a zone-signing key, keyid 43199, for example.com.
; Created: 20261022220749 (Thu Oct 22 22:07:49 2026)
; Publish: 20261022220749 (Thu Oct 22 22:07:49 2026)
; Activate: 20261022220749 (Thu Oct 22 22:07:49 2026)
; This is a key-signing key, keyid 1283, for example.com.
; Created: 20261022220749 (Thu Oct 22 22:07:49 2026)
; Publish: 20261022220749 (Thu Oct 22 22:07:49 2026)
; Activate: 20261022220749 (Thu Oct 22 22:07:49 2026)
; This is a zone-signing key, keyid 34164, for example.com.
; Created: 20261022223016 (Thu Oct 22 22:30:16 2026)
; Publish: 20261022223016 (Thu Oct 22 22:30:16 2026)
; Activate: 20261022223016 (Thu Oct 22 22:30:16 2026)
example.com. IN DNSKEY 256 3 13 YCUV/Y4X7VjG/X5XS79GVTAvz/z1f2Zt6XXVTSiad5z5CLZVbfyP/lm1 qjU2mJEQWI82MGPMb+vtbwUGHq4Qzg==
; This is a key-signing key, keyid 51635, for example.com.
; Created: 20261022223016 (Thu Oct 22 22:30:16 2026)
; Publish: 20261022223016 (Thu Oct 22 22:30:16 2026)
; Activate: 20261022223016 (Thu Oct 22 22:30:16 2026)
example.com. IN DNSKEY 257 3 13 hA7Px90yXIYntjz2LMR1xoL96R7cqkcILC0H1Ovu3mWymXCLaMJ+jpum MsnaxEsS2dEYa3yYdZuvsQM0e9uQyg==

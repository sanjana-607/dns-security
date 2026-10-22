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
; This is a zone-signing key, keyid 15586, for example.com.
; Created: 20261022163844 (Thu Oct 22 16:38:44 2026)
; Publish: 20261022163844 (Thu Oct 22 16:38:44 2026)
; Activate: 20261022163844 (Thu Oct 22 16:38:44 2026)
; This is a key-signing key, keyid 33640, for example.com.
; Created: 20261022163845 (Thu Oct 22 16:38:45 2026)
; Publish: 20261022163845 (Thu Oct 22 16:38:45 2026)
; Activate: 20261022163845 (Thu Oct 22 16:38:45 2026)
; This is a zone-signing key, keyid 54796, for example.com.
; Created: 20261022195407 (Thu Oct 22 19:54:07 2026)
; Publish: 20261022195407 (Thu Oct 22 19:54:07 2026)
; Activate: 20261022195407 (Thu Oct 22 19:54:07 2026)
; This is a key-signing key, keyid 58639, for example.com.
; Created: 20261022195407 (Thu Oct 22 19:54:07 2026)
; Publish: 20261022195407 (Thu Oct 22 19:54:07 2026)
; Activate: 20261022195407 (Thu Oct 22 19:54:07 2026)
; This is a zone-signing key, keyid 9400, for example.com.
; Created: 20261022195802 (Thu Oct 22 19:58:02 2026)
; Publish: 20261022195802 (Thu Oct 22 19:58:02 2026)
; Activate: 20261022195802 (Thu Oct 22 19:58:02 2026)
; This is a key-signing key, keyid 5618, for example.com.
; Created: 20261022195802 (Thu Oct 22 19:58:02 2026)
; Publish: 20261022195802 (Thu Oct 22 19:58:02 2026)
; Activate: 20261022195802 (Thu Oct 22 19:58:02 2026)
; This is a zone-signing key, keyid 49823, for example.com.
; Created: 20261022195918 (Thu Oct 22 19:59:18 2026)
; Publish: 20261022195918 (Thu Oct 22 19:59:18 2026)
; Activate: 20261022195918 (Thu Oct 22 19:59:18 2026)
; This is a key-signing key, keyid 47080, for example.com.
; Created: 20261022195918 (Thu Oct 22 19:59:18 2026)
; Publish: 20261022195918 (Thu Oct 22 19:59:18 2026)
; Activate: 20261022195918 (Thu Oct 22 19:59:18 2026)
; This is a zone-signing key, keyid 56838, for example.com.
; Created: 20261022200844 (Thu Oct 22 20:08:44 2026)
; Publish: 20261022200844 (Thu Oct 22 20:08:44 2026)
; Activate: 20261022200844 (Thu Oct 22 20:08:44 2026)
example.com. IN DNSKEY 256 3 13 LoL+Vl2IwjO3W8YTIkA1geukc2edwMGBTf0NSLOww5dKOSfAz/t422tB pLoxp15oLUwG83Wwmq4oa3o7NgmvLA==
; This is a key-signing key, keyid 61103, for example.com.
; Created: 20261022200844 (Thu Oct 22 20:08:44 2026)
; Publish: 20261022200844 (Thu Oct 22 20:08:44 2026)
; Activate: 20261022200844 (Thu Oct 22 20:08:44 2026)
example.com. IN DNSKEY 257 3 13 abe6hcopz9KjSceF73vulUu0oWLrMAPrvCfWIeG8HmBWJTymhHhSR39K w5rT6tThsoZLCT3kFwEMhHaY7a1ccA==

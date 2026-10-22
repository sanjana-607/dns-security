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

; Unadvertised internal service hostnames for Phase 5 zone walking
billing IN  A   172.16.1.51
dev     IN  A   172.16.1.52
mail    IN  A   172.16.1.53
payroll IN  A   172.16.1.54
secret  IN  A   172.16.1.55
vpn     IN  A   172.16.1.56
; This is a zone-signing key, keyid 52095, for example.com.
; Created: 20261022214348 (Thu Oct 22 21:43:48 2026)
; Publish: 20261022214348 (Thu Oct 22 21:43:48 2026)
; Activate: 20261022214348 (Thu Oct 22 21:43:48 2026)
example.com. IN DNSKEY 256 3 13 2aOo3R6t+xMJjV/JwXJWT4FNN2lvEavFya3/TKzo7ynezUlSwdlgp0kN ZRN9lnbFVouosVwOn1RpDcdGax/uSg==
; This is a key-signing key, keyid 15445, for example.com.
; Created: 20261022214348 (Thu Oct 22 21:43:48 2026)
; Publish: 20261022214348 (Thu Oct 22 21:43:48 2026)
; Activate: 20261022214348 (Thu Oct 22 21:43:48 2026)
example.com. IN DNSKEY 257 3 13 vyXxuHKAc/IEDratx+M4AmpZzH9/yb5zjldTHt0Oyr8Mjdzx1/TNRq3A ly1x+3zEdvzB+rNZZgru85nC7mpcEw==

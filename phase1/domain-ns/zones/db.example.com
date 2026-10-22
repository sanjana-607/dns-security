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

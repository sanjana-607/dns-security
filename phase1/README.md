# Phase 1 - Building the DNS Hierarchy

Run from this directory:

```bash
docker compose build
docker compose up -d
./routers/configure-all-routes.sh
docker compose exec -T client dig @172.16.2.10 example.com
docker compose exec -T client curl -s http://example.com
docker compose exec -T client dig +time=1 +tries=1 @172.16.3.10 example.com
docker compose down
```
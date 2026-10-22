FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends stunnel4 \
    && rm -rf /var/lib/apt/lists/*

CMD ["stunnel", "/etc/stunnel/stunnel.conf"]

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc make libpcap-dev iproute2 iputils-ping tcpdump procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY zonewalker.c Makefile ./
RUN make

CMD ["sleep", "infinity"]
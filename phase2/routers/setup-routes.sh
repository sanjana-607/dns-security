#!/bin/sh
set -eu

# Edge router: client subnet <-> resolver subnet
ip route replace 172.16.3.0/24 via 172.16.2.3

# Core router: resolver subnet <-> authoritative subnet
ip route replace 172.16.1.0/24 via 172.16.2.2

echo "Router routes configured."
ip route

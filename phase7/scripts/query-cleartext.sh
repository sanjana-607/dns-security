#!/bin/sh
set -eu

docker compose exec -T client dig @172.16.2.10 example.com A

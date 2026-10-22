#!/bin/sh
set -eu

echo "Trying strict DoT first..."
if ./scripts/query-dot.sh; then
    echo "DoT succeeded; no cleartext fallback was needed."
    exit 0
fi

echo "DoT failed; falling back to cleartext DNS."
sh ./scripts/query-cleartext.sh

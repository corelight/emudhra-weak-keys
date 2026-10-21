#!/usr/bin/env bash
set -euo pipefail

HOST="${1:-172.16.195.128}"
BASE_PORT="${2:-4433}"

declare -a INTERMEDIATES=(
    "EM-OV-TLS-CA-G3C"
    "EM-OV-TLS-CA-G3B"
    "EM-EV-TLS-CA-G3C"
    "EM-EV-TLS-CA-G3B"
    "EM-DV-TLS-CA-G3C"
    "EM-DV-TLS-CA-G3B"
)

declare -a CHAINS=("emsign" "sectigo")

port=$BASE_PORT
for name in "${INTERMEDIATES[@]}"; do
    for chain in "${CHAINS[@]}"; do
        printf "port %5d  %-20s  chain=%-7s  " "$port" "$name" "$chain"
        status=$(curl -sk -o /dev/null -w "%{http_code}" "https://${HOST}:${port}/" 2>&1) && \
            echo "HTTP ${status}" || \
            echo "FAILED"
        port=$((port + 1))
    done
done

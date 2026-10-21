#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PIDS=()
BASE_PORT="${1:-4433}"

declare -a INTERMEDIATES=(
    "EM-OV-TLS-CA-G3C"
    "EM-OV-TLS-CA-G3B"
    "EM-EV-TLS-CA-G3C"
    "EM-EV-TLS-CA-G3B"
    "EM-DV-TLS-CA-G3C"
    "EM-DV-TLS-CA-G3B"
)

declare -a CHAINS=("emsign" "sectigo")

cleanup() {
    echo ""
    echo "Stopping all servers..."
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null
    echo "Done."
}
trap cleanup EXIT INT TERM

port=$BASE_PORT
for name in "${INTERMEDIATES[@]}"; do
    dir="${SCRIPT_DIR}/${name}"
    for chain in "${CHAINS[@]}"; do
        openssl s_server \
            -cert "${dir}/server.crt.pem" \
            -key "${dir}/server.key.pem" \
            -chainCAfile "${dir}/intermediate-${chain}.crt.pem" \
            -accept "$port" \
            -tls1_2 \
            -www \
            -quiet &
        PIDS+=($!)
        printf "port %5d  %-20s  chain=%-7s  (pid %d)\n" "$port" "$name" "$chain" $!
        port=$((port + 1))
    done
done

echo ""
echo "All ${#PIDS[@]} servers running. Ctrl-C to stop."
wait

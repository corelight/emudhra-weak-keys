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

# emSign Root TLS CA - G3, cross-signed by emSign ECC Root CA - G3 (which is in
# the Mozilla root store). Sent after the emSign intermediates, so that the
# chain can be validated against the Mozilla root store.
CROSS_CERT="${SCRIPT_DIR}/emsign-root-tls-ca-g3-cross-signed.crt.pem"
CHAIN_DIR="$(mktemp -d)"

cleanup() {
    echo ""
    echo "Stopping all servers..."
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null
    rm -rf "$CHAIN_DIR"
    echo "Done."
}
trap cleanup EXIT INT TERM

port=$BASE_PORT
for name in "${INTERMEDIATES[@]}"; do
    dir="${SCRIPT_DIR}/${name}"
    for chain in "${CHAINS[@]}"; do
        chain_file="${CHAIN_DIR}/${name}-${chain}.pem"
        cat "${dir}/intermediate-${chain}.crt.pem" > "$chain_file"
        if [ "$chain" = "emsign" ]; then
            cat "$CROSS_CERT" >> "$chain_file"
        fi

        openssl s_server \
            -cert "${dir}/server.crt.pem" \
            -key "${dir}/server.key.pem" \
            -chainCAfile "$chain_file" \
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

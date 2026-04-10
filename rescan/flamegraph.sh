#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "Usage: $0 <path_to_bitcoin_bin> <output_file>"
    exit 1
}

[[ $# -ne 2 ]] && usage

BTC_BIN="$1"
OUTPUT_FILE="$2"

stop_bitcoind() {
    echo "Stopping bitcoind..."
    "${BTC_BIN}/bitcoin-cli" stop || true
}
trap stop_bitcoind EXIT

echo "Starting bitcoind..."
"${BTC_BIN}/bitcoind" -daemon -walletpar=2 -maxconnections=0

echo "Waiting for bitcoind to start..."
until "${BTC_BIN}/bitcoin-cli" ping 2>/dev/null; do
    sleep 1
done
echo "bitcoind is ready."

echo "Running perf record + rescanblockchain..."
perf record -g --call-graph dwarf --per-thread -F 140 \
    -p "$(pgrep bitcoind)" \
    -- "${BTC_BIN}/bitcoin-cli" -rpcwallet=scanner rescanblockchain

echo "Generating flamegraph: ${OUTPUT_FILE}"
perf script | stackcollapse-perf.pl | flamegraph.pl > "${OUTPUT_FILE}"

echo "Done: ${OUTPUT_FILE}"

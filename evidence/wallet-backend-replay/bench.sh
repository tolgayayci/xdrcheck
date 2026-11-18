#!/usr/bin/env bash
# Throwaway: per-entry cost loop (binary prebuilt, template DB ready, store/mock up).
# Usage: bench.sh <sha8> <datastore|rpc> <N>
set -u
source "$(dirname "$0")/lib.sh"
SHA=$1; BACKEND=$2; N=$3
if [ "$BACKEND" = datastore ]; then
  EXTRA=(--rpc-url http://127.0.0.1:1 --datastore-bucket-path ledgers/testnet/2025-12-18 --datastore-region us-east-1
    --datastore-endpoint-url "http://127.0.0.1:$S3PORT" --datastore-buffer-size 1 --datastore-num-workers 1
    --datastore-retry-limit 1 --datastore-retry-wait 1s)
else
  EXTRA=(--rpc-url "http://127.0.0.1:$RPCPORT" --get-ledgers-limit 1)
fi
tot=0
for i in $(seq 1 "$N"); do
  DB=bench_$i; a=$(ms)
  fresh_db "$DB" "tmpl_$SHA" "$LEDGER" 2>/dev/null; b=$(ms)
  env -i PATH="$PATH" HOME="$HOME" AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_REGION=us-east-1 \
    "$R/bin/wallet-backend-$SHA" ingest --database-url "$(dburl "$DB")" --network-passphrase "$PASSPHRASE" \
    --stellar-environment spike --ledger-backend-type "$BACKEND" --archive-url http://127.0.0.1:1/ \
    --ingest-server-port $((59100 + i)) --log-level WARN "${EXTRA[@]}" >/dev/null 2>&1 &
  P=$!
  until [ "$(cursor "$DB")" = "$LEDGER" ] || ! kill -0 $P 2>/dev/null; do sleep 0.05; done; c=$(ms)
  kill -TERM $P; wait $P; rc=$?; d=$(ms)
  q "$DB" "SELECT encode(sc.signer_account_id,'hex') FROM state_changes sc JOIN transactions t ON sc.to_id=t.to_id WHERE t.hash=decode('$TXHASH','hex') AND sc.state_change_category='SIGNER'" >/dev/null; e=$(ms)
  q postgres "DROP DATABASE $DB WITH (FORCE)" >/dev/null; f=$(ms)
  echo "run $i: fresh_db=$((b-a)) ingest_to_cursor=$((c-b)) stop=$((d-c)) rc=$rc observe=$((e-d)) drop=$((f-e)) total=$((f-a)) ms"
  tot=$((tot + f - a))
done
echo "mean total: $((tot / N)) ms over $N runs ($SHA $BACKEND)"

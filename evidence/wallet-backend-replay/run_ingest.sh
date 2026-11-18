#!/usr/bin/env bash
# Throwaway: ingest exactly one ledger with wallet-backend and observe.
# Usage: run_ingest.sh <sha8> <datastore|rpc> <label> [timeout_s]
# Needs: xcc-g4-pg (and xcc-g4-s3 or mock_rpc.py) running; template DB tmpl_<sha8>.
set -u
source "$(dirname "$0")/lib.sh"
SHA=$1; BACKEND=$2; LABEL=$3; TIMEOUT=${4:-400}
DB="run_${LABEL//-/_}"
LOG="$R/logs/ingest-$LABEL.log"
PORT=$((58002 + RANDOM % 900))

t0=$(ms)
fresh_db "$DB" "tmpl_$SHA" "$LEDGER" 2>/dev/null
t_db=$(( $(ms) - t0 ))

COMMON=(--database-url "$(dburl "$DB")" --network testnet --network-passphrase "$PASSPHRASE"
  --stellar-environment spike --ingestion-mode live --ledger-backend-type "$BACKEND"
  --archive-url "http://127.0.0.1:1/" --ingest-server-port "$PORT" --log-level "${LOGLEVEL:-INFO}")
if [ "$BACKEND" = datastore ]; then
  EXTRA=(--rpc-url "http://127.0.0.1:1"
    --datastore-bucket-path ledgers/testnet/2025-12-18 --datastore-region us-east-1
    --datastore-endpoint-url "http://127.0.0.1:$S3PORT"
    --datastore-buffer-size 1 --datastore-num-workers 1 --datastore-retry-limit 1 --datastore-retry-wait 1s)
  ENVX=(AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_REGION=us-east-1)
else
  EXTRA=(--rpc-url "http://127.0.0.1:$RPCPORT" --get-ledgers-limit 1)
  ENVX=()
fi

echo "\$ wallet-backend-$SHA ingest ${COMMON[*]} ${EXTRA[*]}"
t1=$(ms)
env -i PATH="$PATH" HOME="$HOME" "${ENVX[@]}" "$R/bin/wallet-backend-$SHA" ingest "${COMMON[@]}" "${EXTRA[@]}" >"$LOG" 2>&1 &
PID=$!
state=timeout; seen_cursor=""
while true; do
  now=$(( $(ms) - t1 ))
  c=$(cursor "$DB" 2>/dev/null)
  if [ "$c" != "$seen_cursor" ]; then echo "  t+${now}ms cursor=$c"; seen_cursor=$c; fi
  if [ "$c" = "$LEDGER" ]; then state=advanced; break; fi
  if ! kill -0 $PID 2>/dev/null; then state=exited; break; fi
  if [ $now -gt $((TIMEOUT*1000)) ]; then state=timeout; break; fi
  sleep 0.25
done
t_done=$(( $(ms) - t1 ))
if [ $state != exited ]; then
  # observe what happens after the last ledger for 5 s, then stop cleanly
  sleep 5; alive=$(kill -0 $PID 2>/dev/null && echo yes || echo no)
  ts=$(ms); kill -TERM $PID 2>/dev/null; wait $PID; RC=$?; t_stop=$(( $(ms) - ts ))
  echo "  state=$state at t+${t_done}ms; still running 5s later: $alive; SIGTERM -> rc=$RC in ${t_stop}ms"
else
  wait $PID; RC=$?
  echo "  state=exited at t+${t_done}ms rc=$RC"
fi
echo "  fresh_db=${t_db}ms final cursor=$(cursor "$DB") log=$LOG"
echo "$LABEL sha=$SHA backend=$BACKEND state=$state rc=$RC t_db_ms=$t_db t_obs_ms=$t_done" >> "$R/logs/runs.tsv"

#!/usr/bin/env bash
# ingest ledgers S..E of a local chain with wallet-backend, stop at cursor=E, record timing.
# Usage: run_ingest.sh <sha8> <datastore|rpc> <label> <S> <E> [timeout_s]
# Needs xcc-g5-pg, and xcc-g5-s3 (datastore, BUCKETPATH) or mock_rpc.py on RPCPORT (rpc). Template tmpl_<sha8>.
set -u
source "$(dirname "$0")/lib.sh"
SHA=$1; BACKEND=$2; LABEL=$3; S=$4; E=$5; TIMEOUT=${6:-60}
DB="run_${LABEL//-/_}"
LOG="$R/logs/ingest-$LABEL.log"
PORT=$((58402 + RANDOM % 900))
t0=$(ms); fresh_db "$DB" "tmpl_$SHA" "$S" 2>/dev/null; t_db=$(( $(ms) - t0 ))
COMMON=(--database-url "$(dburl "$DB")" --network-passphrase "$PASSPHRASE" --ingestion-mode live --ledger-backend-type "$BACKEND"
  --archive-url "http://127.0.0.1:1/" --ingest-server-port "$PORT" --log-level "${LOGLEVEL:-INFO}")
# pins before db43b388-era refactors take --network/--stellar-environment; HEAD e967ce8b has neither
if [ "$SHA" != e967ce8b ]; then COMMON+=(--network "$NETWORK" --stellar-environment spike); fi
if [ "$BACKEND" = datastore ]; then
  EXTRA=(--rpc-url "http://127.0.0.1:1" --datastore-bucket-path "$BUCKETPATH" --datastore-region us-east-1
    --datastore-endpoint-url "http://127.0.0.1:$S3PORT" --datastore-buffer-size 1 --datastore-num-workers 1
    --datastore-retry-limit 1 --datastore-retry-wait 1s)
  ENVX=(AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_REGION=us-east-1)
else
  EXTRA=(--rpc-url "http://127.0.0.1:$RPCPORT" --get-ledgers-limit 1); ENVX=()
fi
echo "\$ wallet-backend-$SHA ingest ${COMMON[*]} ${EXTRA[*]}"
echo "  fresh DB from tmpl_$SHA, cursor latest=$((S-1)) oldest=$S; wait for latest=$E"
t1=$(ms)
env -i PATH="$PATH" HOME="$HOME" "${ENVX[@]}" "$R/bin/wallet-backend-$SHA" ingest "${COMMON[@]}" "${EXTRA[@]}" >"$LOG" 2>&1 &
PID=$!
state=timeout; seen=""
while true; do
  now=$(( $(ms) - t1 )); c=$(cursor "$DB" 2>/dev/null)
  if [ "$c" != "$seen" ]; then echo "  t+${now}ms cursor=$c"; seen=$c; fi
  if [ -n "$c" ] && [ "$c" -ge "$E" ] 2>/dev/null; then state=advanced; break; fi
  if ! kill -0 $PID 2>/dev/null; then state=exited; break; fi
  if [ $now -gt $((TIMEOUT*1000)) ]; then state=timeout; break; fi
  sleep 0.1
done
t_done=$(( $(ms) - t1 ))
if [ $state != exited ]; then
  sleep 3; alive=$(kill -0 $PID 2>/dev/null && echo yes || echo no)
  ts=$(ms); kill -TERM $PID 2>/dev/null; wait $PID; RC=$?; t_stop=$(( $(ms) - ts ))
  echo "  state=$state at t+${t_done}ms; still running 3s later: $alive; SIGTERM -> rc=$RC in ${t_stop}ms"
else
  wait $PID; RC=$?; echo "  state=exited at t+${t_done}ms rc=$RC"
fi
echo "  fresh_db=${t_db}ms final cursor=$(cursor "$DB") log=$LOG"
echo "  log: $(grep -cE 'level=(error|warning|fatal)' "$LOG") error/warning lines; $(grep -c '^panic' "$LOG") panic lines"
grep -E 'level=(error|warning|fatal)|^panic' "$LOG" | cut -c1-400 | head -5 | sed 's/^/    /'
echo "$LABEL sha=$SHA backend=$BACKEND S=$S E=$E state=$state rc=$RC t_db_ms=$t_db t_obs_ms=$t_done" >> "$R/logs/runs.tsv"

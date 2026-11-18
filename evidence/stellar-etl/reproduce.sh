#!/usr/bin/env bash
# Regenerates the transcripts in this folder into a scratch folder and compares them with the committed ones; it never
# writes into the repository (bash).
#
#   emulator-check.txt     an unmodified stellar-etl v2.8.34 reads one captured pubnet lake object from the
#                          off-the-shelf fake-gcs-server through STORAGE_EMULATOR_HOST and writes JSON Lines
#   replay-assert-known.txt  `xdrcheck replay --assert-known` with the stellar-etl adapter over the corpus entries that
#                          declare a stellar-etl replay divergence
#
# Network, once: the first run needs it to build the stellar-etl binary at the pinned commit (the adapter fetches the
# source, its Go toolchain and modules into its cache; or set STELLAR_ETL to a binary) and to install fake-gcs-server
# (`go install github.com/fsouza/fake-gcs-server@v1.49.2`, the version go-stellar-sdk's datastore tests use; or set
# FAKE_GCS). Every later run is offline. Also needs Go (the toolchain in mise.toml) and python3.
#
# WORK is the scratch folder (default: a new temporary one); the transcripts are written to $WORK/transcripts and
# compared with the committed ones (dates, timings and hashes of rebuilt binaries may differ). To refresh the committed
# transcripts after a deliberate change, copy them from there by hand.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
COMMIT=2b24ec89ddce7fc0beb7795de982c93e6895eaf3
LEDGER=64558277
PART=FC279FFF--64512000-64575999
OBJ=FC26EB3A--64558277.xdr.zst
# The adapter's cache: <cache>/xdrcheck, or the directory of the kit's earlier name when only that one exists.
cbase=${XDG_CACHE_HOME:-$HOME/.cache}
if [ -d "$cbase/xdrcheck" ] || [ ! -d "$cbase/xcc" ]; then cbase=$cbase/xdrcheck; else cbase=$cbase/xcc; fi
CACHE=${XCC_CACHE_ROOT:-$cbase/adapters}
ETL=${STELLAR_ETL:-$CACHE/stellar-etl/bin/stellar-etl-$COMMIT}
FAKE_GCS=${FAKE_GCS:-$(go env GOPATH)/bin/fake-gcs-server}
WORK=${WORK:-$(mktemp -d)}
PORT=${PORT:-47443}
scrub() { sed -e "s|$WORK|\$WORK|g" -e "s|$root|.|g" -e "s|$CACHE|\$CACHE|g" -e "s|$HOME|~|g"; }

emulator_check() {
  echo "# emulator check, $(date -u +%Y-%m-%d)"
  echo "stellar-etl: $("$ETL" version | head -1) at $COMMIT, binary sha256 $(sha256sum "$ETL" | cut -d' ' -f1)"
  echo "fake-gcs-server v1.49.2; lake object corpus/objects/pubnet/$LEDGER/$OBJ sha256 $(sha256sum "$root/corpus/objects/pubnet/$LEDGER/$OBJ" | cut -d' ' -f1)"
  local data=$WORK/gcs/xcc/lake/pubnet
  mkdir -p "$data/$PART" "$WORK/out"
  cp "$root/corpus/objects/pubnet/$LEDGER/$OBJ" "$data/$PART/"
  printf '{"networkPassphrase":"Public Global Stellar Network ; September 2015","version":"1.0","compression":"zstd","ledgersPerBatch":1,"batchesPerPartition":64000}' >"$data/.config.json"
  echo
  echo "\$ fake-gcs-server -scheme http -host 127.0.0.1 -port $PORT -public-host 127.0.0.1:$PORT -data \$WORK/gcs -backend memory"
  "$FAKE_GCS" -scheme http -host 127.0.0.1 -port "$PORT" -public-host "127.0.0.1:$PORT" -data "$WORK/gcs" -backend memory >"$WORK/gcs.log" 2>&1 &
  local gcs=$!
  trap 'kill $gcs 2>/dev/null || true' RETURN
  sleep 2
  for c in export_ledgers export_transactions export_operations export_effects export_token_transfer; do
    mkdir -p "$WORK/out/$c"
    echo "\$ env -i PATH=/usr/bin:/bin HOME=\$WORK STORAGE_EMULATOR_HOST=127.0.0.1:$PORT stellar-etl $c -s $LEDGER -e $LEDGER -o \$WORK/out/$c/ --datastore-path xcc/lake"
    local rc=0
    (cd "$WORK" && env -i PATH=/usr/bin:/bin HOME="$WORK" STORAGE_EMULATOR_HOST=127.0.0.1:$PORT \
      "$ETL" "$c" -s $LEDGER -e $LEDGER -o "$WORK/out/$c/" --datastore-path xcc/lake >"$WORK/$c.log" 2>&1) || rc=$?
    echo "exit $rc; $(cat "$WORK/out/$c"/*.txt | wc -l) rows in $(cd "$WORK/out/$c" && ls)"
    grep -o 'msg="{[^}]*}' "$WORK/$c.log" | sed 's/\\"/"/g' || true
  done
  echo
  echo "# requests the emulator answered"
  grep -o '"GET [^"]*" [0-9]*' "$WORK/gcs.log" | sed 's/\\"/"/g' | sort | uniq -c
  echo
  echo "# token-transfer rows of the mint of 6591994c… (to_muxed_id is the text memo \"psp:160886906\" in the event)"
  grep -h '"6591994cebe12b87e6ca9175769bbaefeb45c7082be221ba3ed23d6042fe9474".*"event_topic":"mint"' "$WORK/out/export_token_transfer"/*.txt
}

replay() {
  echo "# xdrcheck replay --assert-known, $(date -u +%Y-%m-%d)"
  (cd "$root/go" && go build -o "$WORK/bin/" ./cmd/xdrcheck ./adapters/stellaretl/cmd/stellaretl)
  echo "\$ xdrcheck replay --corpus corpus --adapter stellaretl --target-version $COMMIT --assert-known --report \$WORK/report"
  local rc=0
  (cd "$root" && TMPDIR=$WORK "$WORK/bin/xdrcheck" replay --corpus corpus --adapter "$WORK/bin/stellaretl" \
    --target-version $COMMIT --assert-known --report "$WORK/report") >"$WORK/replay.out" 2>&1 || rc=$?
  grep -v '^unit ' "$WORK/replay.out" || true
  echo "exit $rc"
  echo
  echo "# facts per row"
  python3 "$here/report_facts.py" "$WORK/report"
}

# The replay first: its adapter builds the binary into the cache when it is not there yet.
out=$WORK/transcripts
mkdir -p "$out"
replay 2>&1 | scrub >"$out/replay-assert-known.txt"
emulator_check 2>&1 | scrub >"$out/emulator-check.txt"
echo "transcripts written to $out; differences from the committed ones:"
for f in replay-assert-known.txt emulator-check.txt; do
  diff -u "$here/$f" "$out/$f" || true
done

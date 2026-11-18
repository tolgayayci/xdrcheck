#!/bin/bash
# usage: run.sh <testnet|mainnet> <run-dir>  (env PROTOCOL=28, SETTINGS=p27-testnet.xdr) — one clean chain, run via run-offline.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
LC="$(cd "$HERE/../../local-core" && pwd)"          # reuse the local-core release binary + stellar-xdr CLI (read-only)
NET="$1"; OUT="$(realpath -m "$2")"
case "$NET" in
  testnet) PP="Test SDF Network ; September 2015" ;;
  mainnet) PP="Public Global Stellar Network ; September 2015" ;;
  *) echo "bad net"; exit 2 ;;
esac
rm -rf "$OUT"; mkdir -p "$OUT/work"; W="$OUT/work"
export LD_LIBRARY_PATH="$LC/root/usr/lib/x86_64-linux-gnu"
CORE="$LC/root/usr/bin/stellar-core"
HTTP=11626; QHTTP=11627
# fail loudly if something already answers on our ports (the local-core run's stale-node trap); in a fresh netns nothing can
if (exec 3<>/dev/tcp/127.0.0.1/$HTTP) 2>/dev/null; then echo "port $HTTP already bound"; exit 3; fi
sed -e "s|@PP@|$PP|" -e "s|@W@|$W|g" -e "s|@OUT@|$OUT|g" -e "s|@HTTP@|$HTTP|" -e "s|@QHTTP@|$QHTTP|" "$HERE/config/core.cfg.in" > "$W/core.cfg"
cp "$W/core.cfg" "$OUT/core.cfg"
"$CORE" new-db --conf "$W/core.cfg" > "$OUT/newdb.log" 2>&1 || { echo new-db failed; exit 1; }
START=$(date +%s.%N)
"$CORE" run --conf "$W/core.cfg" > "$OUT/run.log" 2>&1 &
CPID=$!
STELLAR_XDR="$LC/tools/bin/stellar-xdr" PASSPHRASE="$PP" HTTP=$HTTP QHTTP=$QHTTP CORE_BIN="$CORE" OUT="$OUT" UPGRADE_DIR="$HERE/config/upgrades" \
  PROTOCOL="${PROTOCOL:-28}" SETTINGS="${SETTINGS:-p27-testnet.xdr}" node "$HERE/driver/scenario731.mjs" 2> "$OUT/driver.log"
RC=$?
"$CORE" http-command 'info' --conf "$W/core.cfg" > "$OUT/final-info.json" 2>/dev/null
kill -INT $CPID 2>/dev/null; wait $CPID 2>/dev/null
END=$(date +%s.%N)
python3 -c "print(\"wall_seconds\", round($END - $START, 3))" > "$OUT/wall.txt"
sha256sum "$OUT/meta.xdr" > "$OUT/meta.sha256"
rm -rf "$W"
echo "rc=$RC"; exit $RC

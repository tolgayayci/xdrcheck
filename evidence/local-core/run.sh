#!/bin/bash
# usage: run.sh <testnet|mainnet> <run-dir>   — one clean scenario run, offline
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
NET="$1"; OUT="$(realpath -m "$2")"
case "$NET" in
  testnet) PP="Test SDF Network ; September 2015" ;;
  mainnet) PP="Public Global Stellar Network ; September 2015" ;;
  *) echo "bad net"; exit 2 ;;
esac
rm -rf "$OUT"; mkdir -p "$OUT/work"; W="$OUT/work"
export LD_LIBRARY_PATH="$HERE/root/usr/lib/x86_64-linux-gnu"
CORE="$HERE/root/usr/bin/stellar-core"
HTTP=${HTTP_PORT:-11626}; QHTTP=${QUERY_PORT:-11627}
sed -e "s|@PP@|$PP|" -e "s|@W@|$W|g" -e "s|@OUT@|$OUT|g" -e "s|@HTTP@|$HTTP|" -e "s|@QHTTP@|$QHTTP|" "$HERE/config/core.cfg.in" > "$W/core.cfg"
cp "$W/core.cfg" "$OUT/core.cfg"
"$CORE" new-db --conf "$W/core.cfg" > "$OUT/newdb.log" 2>&1 || { echo new-db failed; exit 1; }
START=$(date +%s.%N)
"$CORE" run --conf "$W/core.cfg" > "$OUT/run.log" 2>&1 &
CPID=$!
STELLAR_XDR="$HERE/tools/bin/stellar-xdr" PASSPHRASE="$PP" HTTP=$HTTP QHTTP=$QHTTP CORE_BIN="$CORE" OUT="$OUT" UPGRADE_DIR="$HERE/config/upgrades" \
  node "$HERE/driver/scenario.mjs" 2> "$OUT/driver.log"
RC=$?
"$CORE" http-command 'info' --conf "$W/core.cfg" > "$OUT/final-info.json" 2>/dev/null
grep -E "VmHWM|VmPeak" /proc/$CPID/status > "$OUT/core-mem.txt" 2>/dev/null
kill -INT $CPID 2>/dev/null; wait $CPID 2>/dev/null
END=$(date +%s.%N)
python3 -c "print(\"wall_seconds\", round($END - $START, 3))" > "$OUT/wall.txt"
sha256sum "$OUT/meta.xdr" > "$OUT/meta.sha256"
grep -m1 -h 'Root account' "$OUT/newdb.log" "$OUT/run.log" > "$OUT/root.txt" 2>/dev/null
du -sh "$W" > "$OUT/workdir-size.txt"
rm -rf "$W/buckets" "$W"/*.db* 2>/dev/null
echo "rc=$RC"; exit $RC

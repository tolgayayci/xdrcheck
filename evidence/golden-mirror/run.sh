#!/bin/bash
# usage: run.sh <testnet|mainnet|coretest> <profile> <scenario.mjs> <run-dir>   — one clean chain; call via run-offline.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
LC="$(cd "$HERE/../local-core" && pwd)"          # the local-core release binary + stellar-xdr CLI, read-only
NET="$1"; PROFILE="$2"; SCEN="$(realpath "$3")"; OUT="$(realpath -m "$4")"
case "$NET" in
  testnet) PP="Test SDF Network ; September 2015" ;;
  mainnet) PP="Public Global Stellar Network ; September 2015" ;;
  coretest) PP="(V) (;,,;) (V)" ;;
  *) echo "bad net"; exit 2 ;;
esac
source "$HERE/config/profiles.sh"
FLAGS="$(profile_flags "$PROFILE")" || exit 2
rm -rf "$OUT"; mkdir -p "$OUT/work"; W="$OUT/work"
export LD_LIBRARY_PATH="$LC/root/usr/lib/x86_64-linux-gnu"
CORE="$LC/root/usr/bin/stellar-core"
HTTP=11626; QHTTP=11627
if (exec 3<>/dev/tcp/127.0.0.1/$HTTP) 2>/dev/null; then echo "port $HTTP already bound (stale node)"; exit 3; fi
if (exec 3<>/dev/tcp/127.0.0.1/$QHTTP) 2>/dev/null; then echo "port $QHTTP already bound (stale node)"; exit 3; fi
python3 -I - "$HERE/config/core.cfg.in" "$W/core.cfg" "$PP" "$W" "$OUT" "$HTTP" "$QHTTP" "$FLAGS" <<'PY'
import sys
src, dst, pp, w, out, h, q, flags = sys.argv[1:9]
t = open(src).read().replace('@PP@', pp).replace('@W@', w).replace('@OUT@', out).replace('@HTTP@', h).replace('@QHTTP@', q).replace('@FLAGS@', flags.strip())
open(dst, 'w').write(t)
PY
cp "$W/core.cfg" "$OUT/core.cfg"; echo "$PROFILE" > "$OUT/profile.txt"
(cd "$W" && "$CORE" new-db --conf "$W/core.cfg") > "$OUT/newdb.log" 2>&1 || { echo new-db failed; exit 1; }
START=$(date +%s.%N)
(cd "$W" && exec "$CORE" run --conf "$W/core.cfg") > "$OUT/run.log" 2>&1 &
CPID=$!
STELLAR_XDR="$LC/tools/bin/stellar-xdr" PASSPHRASE="$PP" HTTP=$HTTP QHTTP=$QHTTP CORE_BIN="$CORE" OUT="$OUT" UPGRADE_DIR="$HERE/config" \
  PROTOCOL="${PROTOCOL:-30}" SETTINGS="${SETTINGS:-p30-testnet.xdr}" node "$SCEN" 2> "$OUT/driver.log"
RC=$?
kill -INT $CPID 2>/dev/null; wait $CPID 2>/dev/null
END=$(date +%s.%N)
python3 -c "print(\"wall_seconds\", round($END - $START, 3))" > "$OUT/wall.txt"
sha256sum "$OUT/meta.xdr" > "$OUT/meta.sha256"
rm -rf "$W"
echo "rc=$RC"; exit $RC

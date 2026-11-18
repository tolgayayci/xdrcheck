#!/bin/bash
# compare mirror runs with a golden, per focus tx, ordered and multiset skeletons.
# usage: scripts/compare.sh <pattern-dir under out/> <golden.xdr> "<golden-frame-label>:<run-ledger>" ...
#   e.g. scripts/compare.sh trust golden/4c437318f87437c5.xdr 42-L44:L18 43-L45:L19
#        scripts/compare.sh muxed golden/f9e9d669f79493b3.xdr 11-L13:L17
# writes out/<pattern>/compare.txt and prints a summary table
set -u
X=../local-core/tools/bin/stellar-xdr; S=out/schema-LedgerCloseMeta.json; mkdir -p out/skel
[ -f $S ] || $X types schema --type LedgerCloseMeta > $S
P=$1; G=$2; shift 2; GN=$(basename $G .xdr); GD=out/golden-${GN:0:4}
[ -f $GD/frames.json ] || python3 -I scripts/split_decode.py $X $G $GD >/dev/null
{
for pair in "$@"; do g=${pair%%:*}; for m in "" "--multiset"; do
  python3 -I scripts/skeleton.py $X $S $GD/frame$g.json $m --out out/skel/golden-${GN:0:4}-$g${m:+-ms}.json >/dev/null; done; done
for d in out/$P/*/; do r=$(basename $d)
  python3 -I scripts/split_decode.py $X $d/meta.xdr $d/decoded > $d/frames.txt
  for pair in "$@"; do g=${pair%%:*}; L=${pair##*:}; f=$(ls $d/decoded/frame*-$L.json)
    for m in "" "--multiset"; do
      python3 -I scripts/skeleton.py $X $S $f $m --out out/skel/$P-$r-$L${m:+-ms}.json >/dev/null
      echo "=== $r $L vs golden ${GN:0:4} frame$g ${m:-ordered}"
      python3 -I scripts/skeleton.py diff out/skel/golden-${GN:0:4}-$g${m:+-ms}.json out/skel/$P-$r-$L${m:+-ms}.json | sed 1,2d
    done; done; done
} > out/$P/compare.txt
grep -E "^===|^differences" out/$P/compare.txt | paste - - | awk '{print $2,$3,$7,$8,$10}' | column -t

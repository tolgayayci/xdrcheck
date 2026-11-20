#!/usr/bin/env bash
# Nightly arm drift: list union arms and optional states that real networks or the next XDR show and the corpus
# lacks (the per-arm metric of `xdrcheck-corpus coverage --arms`, docs/cli.md).
#
#   lake-<network>  the newest XDRCHECK_ARM_DRIFT_LEDGERS (default 200) ledgers of the pubnet and testnet lakes, mined
#                   with `xdrcheck-corpus mine --want uncovered`: every arm or state no committed corpus input
#                   covers that a kept ledger shows is printed, with the smallest ledger to capture
#   xdr-<ref>       stellar/stellar-xdr at each ref of XDRCHECK_ARM_DRIFT_BRANCHES (default "main"), every #ifdef on,
#                   through `xdrcheck xdr diff pinned <ref>`: the arms and optional states the pinned definitions do
#                   not have, i.e. what the next protocol adds that neither the oracle nor the corpus can hold
#                   yet, each with its CAP (xdr-<ref>.txt; the full diff in xdr-<ref>.json)
#
# Usage: scripts/nightly/arm-drift.sh <out dir>
# Network: anonymous reads of the public lake and of the stellar-xdr repository only. The lists are written to
# <out>/arm-drift/; the job fails only when a part could not run (a list that is not empty is the result, not a
# failure).
source "$(dirname "$0")/lib.sh"
nightly_init arm-drift "${1:?usage: arm-drift.sh <out dir>}"
need_tool "$CORPUS_BIN"
work="$OUT/arm-drift"
mkdir -p "$work"
ledgers="${XDRCHECK_ARM_DRIFT_LEDGERS:-200}"
endpoint="https://aws-public-blockchain.s3.us-east-2.amazonaws.com"
bucket=$(pin public_lake.bucket)
bucket_path="${bucket#s3://aws-public-blockchain/}"

# key <seq>: the SEP-54 object key of a ledger (one ledger per object, 64,000 objects per partition).
key() {
  local s=$1 p=$(($1 / 64000 * 64000))
  printf '%08X--%d-%d/%08X--%d.xdr.zst' $((0xFFFFFFFF - p)) "$p" $((p + 63999)) $((0xFFFFFFFF - s)) "$s"
}

# exists <store> <seq>: whether the lake has the ledger (one anonymous HEAD).
exists() {
  local code
  code=$(curl -s -o /dev/null -w '%{http_code}' -I "$endpoint/$bucket_path/$1/$(key "$2")")
  [ "$code" = 200 ]
}

# tip <store> <start>: the newest ledger in the store, by galloping up from a ledger it has, then bisecting.
tip() {
  local store=$1 lo=$2 step=1024 hi
  exists "$store" "$lo" || return 1
  while exists "$store" $((lo + step)); do lo=$((lo + step)); step=$((step * 2)); done
  hi=$((lo + step))
  while [ $((hi - lo)) -gt 1 ]; do
    local mid=$(((lo + hi) / 2))
    if exists "$store" "$mid"; then lo=$mid; else hi=$mid; fi
  done
  echo "$lo"
}

for net in pubnet testnet; do
  t0=$(date +%s)
  if skipped "lake-$net"; then result "lake-$net" SKIPPED 0 "XDRCHECK_NIGHTLY_SKIP"; continue; fi
  store=$(pin "public_lake.$net")
  start=$(ls corpus/objects/"$net" | grep -E '^[0-9]+$' | sort -n | tail -1)
  if ! top=$(tip "$store" "$start"); then
    result "lake-$net" BLOCKED $(($(date +%s) - t0)) "the lake does not have vendored ledger $start"
    continue
  fi
  from=$((top - ledgers + 1))
  if "$CORPUS_BIN" mine --network "$net" --range "$from..$top" --want uncovered --first 1 \
    --out "$work/$net" >>"$NIGHTLY_LOG" 2>&1; then
    python3 -I -c 'import json, sys
j = json.load(open(sys.argv[1]))
for k in j["kept"]:
    for p in k["kept_for"]:
        print(p + "\t" + k["network"] + " " + str(k["ledger_seq"]))' "$work/$net/mined.json" | sort >"$work/lake-$net.txt"
    n=$(wc -l <"$work/lake-$net.txt")
    result "lake-$net" PASS $(($(date +%s) - t0)) "ledgers $from..$top: $n arms or states the corpus lacks (lake-$net.txt)"
  else
    result "lake-$net" FAIL $(($(date +%s) - t0)) "mine failed (see the log)"
  fi
done

# The XDR part is `xdrcheck xdr diff` (the nightly XDR watch, scripts/nightly/xdr-watch.sh, covers every source):
# the arms reachable from LedgerCloseMetaBatch that each stellar-xdr ref has with every feature on and the
# pinned definitions lack, numeric cases (`LedgerCloseMeta::v3`) and optional states included, with their CAP.
for branch in ${XDRCHECK_ARM_DRIFT_BRANCHES:-main}; do
  t0=$(date +%s)
  if skipped "xdr-$branch"; then result "xdr-$branch" SKIPPED 0 "XDRCHECK_NIGHTLY_SKIP"; continue; fi
  if [ ! -x "$XDRCHECK_BIN" ]; then result "xdr-$branch" BLOCKED 0 "$XDRCHECK_BIN is not built (make build)"; continue; fi
  if ! "$XDRCHECK_BIN" xdr diff pinned "$branch" --format json >"$work/xdr-$branch.json" 2>>"$NIGHTLY_LOG"; then
    result "xdr-$branch" BLOCKED $(($(date +%s) - t0)) "could not diff stellar-xdr $branch (see the log)"
    continue
  fi
  python3 -I -c 'import json, sys
for a in json.load(open(sys.argv[1]))["new_arms"]["LedgerCloseMetaBatch"]:
    print(a["id"] + "\t" + ",".join(a.get("caps") or a.get("gates") or ["-"]))' "$work/xdr-$branch.json" >"$work/xdr-$branch.txt"
  n=$(wc -l <"$work/xdr-$branch.txt")
  result "xdr-$branch" PASS $(($(date +%s) - t0)) "$n arms or optional states not in the pinned definitions (xdr-$branch.txt)"
done
nightly_finish

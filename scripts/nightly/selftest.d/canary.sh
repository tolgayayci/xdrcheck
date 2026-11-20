# shellcheck shell=bash
# maint-selftest case group `canary`: sourced by scripts/nightly/maint-selftest.sh, which provides ROOT,
# XDRCHECK, tmp (a scratch directory, with the shared fixture tmp/tracked.json) and ok/bad (record one case).
# Not run on its own.
# A release no column pins: the next major version of the pinned JavaScript SDK.
unpinned=$(python3 -I -c 'import tomllib; v = tomllib.load(open("pins.toml", "rb"))["js"]["stellar_sdk"]; print(f"{int(v.split(chr(46))[0]) + 1}.0.0")')
python3 -I - "$tmp/tracked.json" "$tmp/latest.json" "$unpinned" <<'PY'
import json, sys
rows = json.load(open(sys.argv[1]))
for r in rows:
    r["latest"], r["behind"] = r["current"], False
    if r["key"] == "js.stellar_sdk":   # a newer release than any pinned column
        r["latest"], r["behind"] = sys.argv[3], True
json.dump(rows, open(sys.argv[2], "w"))
PY
if XDRCHECK_CACHE="$tmp/cache" XDRCHECK_CANARY_PLAN=1 XDRCHECK_CANARY_LATEST="$tmp/latest.json" \
  scripts/nightly/canary.sh "$tmp/out" >"$tmp/canary.log" 2>&1 &&
  grep -q "^DRIFT    latest .*js.stellar_sdk .* -> $unpinned" "$tmp/canary.log" &&
  python3 -I - "$tmp/out/canary/plan.json" "$ROOT" "$unpinned" <<'PY'
import json, sys, tomllib
p = {f["family"]: f for f in json.load(open(sys.argv[1]))["families"]}
pins = tomllib.load(open(sys.argv[2] + "/pins.toml", "rb"))
assert p["js"]["status"] == "canary", p["js"]
assert [c["id"] for c in p["js"]["columns"]] == ["js@" + sys.argv[3]], p["js"]["columns"]
assert p["js"]["columns"][0]["template"] == "js@" + p["js"]["template_version"]
assert p["js"]["template_version"] in pins["conformance"]["columns"]["js"]
assert p["js"]["columns"][0]["column"]["dir"] == "drivers/js/" + sys.argv[3]
for fam in ("go", "python", "rust"):
    assert p[fam]["status"] == "pinned", p[fam]
PY
then
  printf '{"columns": [{"id": "js@%s"}], "cells": [{"column": "js@%s", "entry": "e"}]}' "$unpinned" "$unpinned" >"$tmp/matrix.json"
  python3 -I scripts/nightly/canary.py rename --plan "$tmp/out/canary/plan.json" --matrix "$tmp/matrix.json" --out "$tmp/renamed.json" >/dev/null
  if python3 -I -c 'import json, sys; m = json.load(open(sys.argv[1])); assert m["cells"][0]["column"] == m["columns"][0]["id"] and m["columns"][0]["id"] == json.load(open(sys.argv[2]))["families"][0]["columns"][0]["template"]' "$tmp/renamed.json" "$tmp/out/canary/plan.json"; then
    ok "canary: plan names a canary column for an unpinned release only, and rename maps it to its pinned template"
  else
    bad "canary: rename"
  fi
else
  bad "canary: plan (log: $(tail -n 5 "$tmp/canary.log"))"
fi

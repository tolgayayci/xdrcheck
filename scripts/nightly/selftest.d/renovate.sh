# shellcheck shell=bash
# maint-selftest case group `renovate`: sourced by scripts/nightly/maint-selftest.sh, which provides ROOT,
# XDRCHECK, tmp (a scratch directory, with the shared fixture tmp/tracked.json) and ok/bad (record one case).
# Not run on its own.
if node -e '
const fs = require("fs");
const cfg = JSON.parse(fs.readFileSync("renovate.json", "utf8"));
const text = fs.readFileSync("pins.toml", "utf8");
const found = [];
for (const m of cfg.customManagers) {
  for (const s of m.matchStrings) {
    for (const x of text.matchAll(new RegExp(s, "g"))) found.push(x.groups.depName + " " + x.groups.currentValue);
  }
}
const want = JSON.parse(fs.readFileSync(process.argv[1], "utf8")).map(t => t.dep_name + " " + t.current);
found.sort(); want.sort();
if (JSON.stringify(found) !== JSON.stringify(want)) {
  console.error("renovate finds", found, "\nxdrcheck pins latest tracks", want);
  process.exit(1);
}
' "$tmp/tracked.json"; then
  ok "renovate: the regex manager and xdrcheck pins latest see the same $(python3 -I -c 'import json, sys; print(len(json.load(open(sys.argv[1]))))' "$tmp/tracked.json") pins"
else
  bad "renovate: the regex manager and xdrcheck pins latest disagree"
fi

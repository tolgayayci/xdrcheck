#!/usr/bin/env python3
"""Entry-ID registry check. corpus/plan.json is the only place an entry ID is born.
- every plan row validates against corpus/schema/plan.schema.json and IDs are unique;
- every manifest file's `id` is canonical and equals its path (corpus/manifest/<id>.json);
- every entry ID cited inside manifest files (slice_of, base_entry, related entries) is canonical.
With --list, print the canonical IDs. Exit 1 on any failure."""
import glob, json, os, re, sys
import jsonschema
here = os.path.join(os.path.dirname(__file__), "..", "..")
corpus = os.path.join(here, "corpus")
plan = json.load(open(os.path.join(corpus, "plan.json")))
schema = json.load(open(os.path.join(corpus, "schema", "plan.schema.json")))
bad = [f"plan.json: {e.message[:160]} at /{'/'.join(map(str, e.absolute_path))}"
       for e in jsonschema.Draft202012Validator(schema).iter_errors(plan)]
rows = [r["id"] for r in plan]
if len(rows) != len(set(rows)):
    bad.append("plan.json: duplicate row IDs")
canonical = set(rows) | {f"{r['id']}.{m}" for r in plan for m in r.get("members", [])}
if "--list" in sys.argv:
    print("\n".join(sorted(canonical)))
    sys.exit(0)
id_re = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*(/[a-z0-9]+([.-][a-z0-9]+)*)+$")
def cited(o):
    if isinstance(o, dict):
        for k, v in o.items():
            if k in ("entry", "base_entry", "parent") and isinstance(v, str):
                yield v
            yield from cited(v)
    elif isinstance(o, list):
        for v in o:
            yield from cited(v)
n = 0
for f in sorted(glob.glob(os.path.join(corpus, "manifest", "**", "*.json"), recursive=True)):
    rel = os.path.relpath(f, os.path.join(corpus, "manifest"))[: -len(".json")]
    e = json.load(open(f))
    n += 1
    if e.get("id") != rel:
        bad.append(f"manifest/{rel}.json: id {e.get('id')!r} does not match its path")
    if e.get("id") not in canonical:
        bad.append(f"manifest/{rel}.json: id {e.get('id')!r} is not in plan.json")
    for c in cited(e):
        if id_re.match(c) and c not in canonical:
            bad.append(f"manifest/{rel}.json: cites unknown entry {c!r}")
print(f"plan rows: {len(rows)}; canonical IDs: {len(canonical)}; manifest entries checked: {n}")
for b in bad:
    print("FAIL", b)
sys.exit(1 if bad else 0)

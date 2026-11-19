#!/usr/bin/env python3
"""Validate every schema in corpus/schema against JSON Schema 2020-12 and every example against its schema.
Examples live in corpus/schema/examples/<schema>/(valid|invalid)-NN.json. Exit 1 on any failure."""
import glob, json, os, sys
import jsonschema
from referencing import Registry, Resource

root = os.path.join(os.path.dirname(__file__), "..", "..", "corpus", "schema")
schemas, reg, bad = {}, Registry(), []
for f in sorted(glob.glob(os.path.join(root, "*.schema.json"))):
    name = os.path.basename(f)[: -len(".schema.json")]
    s = json.load(open(f))
    try:
        jsonschema.Draft202012Validator.check_schema(s)
    except jsonschema.SchemaError as e:
        bad.append(f"{name}: not a valid 2020-12 schema: {e.message}")
        continue
    schemas[name] = s
    reg = reg.with_resource(s["$id"], Resource.from_contents(s))
n_valid = n_invalid = 0
for name, s in schemas.items():
    v = jsonschema.Draft202012Validator(s, registry=reg, format_checker=jsonschema.FormatChecker())
    files = sorted(glob.glob(os.path.join(root, "examples", name, "*.json")))
    if not any("/valid-" in f for f in files) or not any("/invalid-" in f for f in files):
        bad.append(f"{name}: needs at least one valid and one invalid example")
    for f in files:
        errs = list(v.iter_errors(json.load(open(f))))
        if "/valid-" in f:
            n_valid += 1
            if errs: bad.append(f"{os.path.relpath(f, root)} should be valid: {errs[0].message[:160]}")
        else:
            n_invalid += 1
            if not errs: bad.append(f"{os.path.relpath(f, root)} should be invalid but validates")
print(f"schemas: {len(schemas)}; valid examples: {n_valid}; invalid examples: {n_invalid}")
for b in bad: print("FAIL", b)
sys.exit(1 if bad else 0)

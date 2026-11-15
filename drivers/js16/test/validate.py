"""Validate driver response lines (NDJSON on stdin) against the driver protocol schema.

Usage: validate.py <repository root> < responses.ndjson

The driver schema references the manifest schema's api operation list, so both are loaded. Exit 1 on the
first line that does not validate.
"""
import json
import sys
from pathlib import Path

import jsonschema
from referencing import Registry, Resource

root = Path(sys.argv[1])
reg = Registry()
for name in ("driver-protocol", "manifest-entry"):
    s = json.loads((root / "corpus" / "schema" / f"{name}.schema.json").read_text())
    reg = reg.with_resource(s["$id"], Resource.from_contents(s))
driver = json.loads((root / "corpus" / "schema" / "driver-protocol.schema.json").read_text())
validator = jsonschema.Draft202012Validator(driver, registry=reg)

n = 0
for i, line in enumerate(sys.stdin, 1):
    if not line.strip():
        continue
    msg = json.loads(line)
    errors = sorted(validator.iter_errors(msg), key=lambda e: e.path)
    if errors:
        print(f"line {i}: does not validate: {line[:300].rstrip()}", file=sys.stderr)
        for e in errors[:5]:
            print(f"  {list(e.absolute_path)}: {e.message[:300]}", file=sys.stderr)
        sys.exit(1)
    n += 1
print(f"   {n} lines valid")

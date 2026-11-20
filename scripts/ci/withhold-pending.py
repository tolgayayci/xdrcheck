#!/usr/bin/env python3
"""Make reports directories safe to upload as a CI artifact while some failures await finding review.

    scripts/ci/withhold-pending.py DIR [DIR...]

A row whose expectation is `pending` is a defect our own run found that is not yet reported upstream
(findings/README.md, "Pending finding review"). The committed pending lists name such a row by its keys only:
a linter site by rule and site hash, a replay or conformance cell by entry, variant, column and level. CI
artifacts become downloadable once the repository is public, so an uploaded directory must not say more than
those lists do. This script, run on each directory just before it is uploaded, changes it in place (a
directory that does not exist is skipped):

- Linter reports (`xcc.report/v1` rows of tool `lint`): a report that holds a pending row names its file, line,
  function and message, which the findings check needs in clear to match the row to its site hash, so the
  report cannot be redacted and stay checkable. The report is withheld whole (deleted from DIR), with every
  file beside it that shares its name (the SARIF log, the text output, the error log), and so is any other text
  file under DIR that names a pending site (`file:line`) or its message. The findings check downstream then
  lists that linter run as not checked, as it does for any run whose report is absent; the linter job itself
  has already checked every row against the expected and pending lists before this runs.
- Replay and conformance reports: a pending row keeps its keys, class and verdict (what the pending list and the
  report's summary already state) and loses its `evidence`; a rendered `REPORT.md` beside it loses the section of
  each pending row (the sections that say "awaiting review").

A directory with no pending row is left untouched. The script prints what it withheld or changed (file names
only, never the content) and exits 1 on any error, so a workflow that uploads only after it succeeded never
uploads an unredacted directory. The local developer view is unaffected: nothing runs this outside CI.
"""

from __future__ import annotations

import json
import os
import re
import sys

REPORT_SCHEMA = "xcc.report/v1"
AWAITING = "awaiting review"


def walk(root):
    for d, dirs, files in os.walk(root):
        dirs.sort()
        for f in sorted(files):
            yield os.path.join(d, f)


def load_report(path):
    """The parsed report when PATH is an xcc.report/v1 JSON file, else None."""
    if not path.endswith(".json"):
        return None
    with open(path, "rb") as fh:
        head = fh.read(4096)
    if REPORT_SCHEMA.encode() not in head:
        return None
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict) or data.get("schema") != REPORT_SCHEMA or not isinstance(data.get("rows"), list):
        return None
    return data


def lint_needles(row):
    """Strings that name a pending linter site in any rendering: file:line, and the message."""
    lint = row.get("lint") or {}
    loc = lint.get("location") or {}
    out = set()
    if loc.get("file"):
        out.add(f"{loc['file']}:{loc.get('line', 0)}")
    msg = (lint.get("message") or "").strip()
    if len(msg) >= 20:
        out.add(msg[:80])
    return out


def drop_awaiting_sections(text):
    """REPORT.md without the `### ` sections whose body says the row awaits review."""
    parts = re.split(r"(?m)^(?=### )", text)
    kept = [p for p in parts if not (p.startswith("### ") and AWAITING in p)]
    return "".join(kept), len(parts) - len(kept)


def main(argv):
    if len(argv) < 2:
        print("usage: withhold-pending.py DIR [DIR...]", file=sys.stderr)
        return 2
    status = 0
    for root in argv[1:]:
        if not os.path.isdir(root):
            print(f"withhold-pending: {root}: no such directory, nothing to do")
            continue
        status = max(status, withhold_dir(root))
    return status


def withhold_dir(root):
    withhold, needles, edited = set(), set(), []
    for path in walk(root):
        data = load_report(path)
        if data is None:
            continue
        pending = [r for r in data["rows"] if r.get("expectation") == "pending"]
        if not pending:
            continue
        lint = [r for r in pending if r.get("tool") == "lint" or "lint" in r]
        if lint:
            for r in lint:
                needles |= lint_needles(r)
            stem = os.path.splitext(os.path.basename(path))[0]
            d = os.path.dirname(path)
            for f in os.listdir(d):
                if f == stem or f.startswith(stem + "."):
                    withhold.add(os.path.join(d, f))
            continue
        changed = 0
        for r in pending:
            if "evidence" in r:
                del r["evidence"]
                changed += 1
        if changed:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False)
                fh.write("\n")
            edited.append(f"{os.path.relpath(path, root)}: evidence dropped from {changed} pending row(s)")
        md = os.path.join(os.path.dirname(path), "REPORT.md")
        if os.path.isfile(md):
            with open(md, encoding="utf-8") as fh:
                text, n = drop_awaiting_sections(fh.read())
            if n:
                with open(md, "w", encoding="utf-8") as fh:
                    fh.write(text)
                edited.append(f"{os.path.relpath(md, root)}: {n} pending section(s) dropped")
    if needles:
        for path, text in texts(root):
            if path not in withhold and any(n in text for n in needles):
                withhold.add(path)
    for path in sorted(withhold):
        os.remove(path)
    for path in sorted(withhold):
        print(f"withhold-pending: withheld {os.path.relpath(path, root)} (names a site awaiting finding review)")
    for line in edited:
        print(f"withhold-pending: {line}")
    if not withhold and not edited:
        print(f"withhold-pending: {root}: nothing to withhold")
    # The check this script exists for: no text file left names a pending linter site.
    for path, text in texts(root):
        if any(n in text for n in needles):
            print(f"withhold-pending: {os.path.relpath(path, root)} still names a pending site", file=sys.stderr)
            return 1
    return 0


def texts(root):
    """(path, decoded text) of every text file under ROOT; binaries (a NUL byte early on) are skipped."""
    for path in walk(root):
        with open(path, "rb") as fh:
            raw = fh.read()
        if b"\0" in raw[:8192]:
            continue
        yield path, raw.decode("utf-8", "replace")


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except Exception as exc:  # fail closed: the upload is gated on this step
        print(f"withhold-pending: {exc}", file=sys.stderr)
        sys.exit(1)

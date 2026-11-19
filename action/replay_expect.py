#!/usr/bin/env python3
"""An expected-failure list and the all-read check for `xdrcheck replay` runs (docs/github-action.md section 4).

The same rules as `xdrcheck conform run --expected-failures/--require-all-read` (docs/use-in-sdk-ci.md section 5),
applied to a replay report (`report.json`, schema xcc.report/v1): an indexer keeps, in its own repository, the
entry variants it is known to get wrong, and the run passes only when its failures are exactly that list.

List file: one item per line, `<entry> <variant or -> [unread]`; `-` stands for every variant of the entry;
`#` starts a comment. A line without a third word is an expected failure; `unread` is an entry variant the
indexer is known never to read (its rows are all not_applicable, not_reached, flaky or a harness fault).

Usage:
    replay_expect.py check REPORT [--expected FILE] [--require-all-read] [--corpus DIR] [--entries GLOBS]
    replay_expect.py write REPORT [--unread]          print a list from a run (review it, then commit it)

check exits 0 when the run matches the list (and, with --require-all-read, every planned entry variant was
read or is listed unread), 1 when it differs, 2 when the input cannot be read. Without --expected every failure
is new. With --corpus and --require-all-read, every `ledger` entry the harness plans (replay.indexer_scope not
sdk-only) that matches --entries must have rows: one with none is reported MISSING.
"""
import argparse
import fnmatch
import json
import os
import sys

READ = {"pass", "mishandled", "dropped"}


def load_report(path):
    with open(path, "rb") as f:
        r = json.load(f)
    if r.get("schema") != "xcc.report/v1":
        raise ValueError(f"{path}: not an xcc.report/v1 file")
    keys = {}
    for row in r.get("rows") or []:
        if row.get("tool") != "replay":
            continue
        k = (row["entry"], row.get("variant") or "-")
        st = keys.setdefault(k, {"failure": False, "read": False, "classes": set()})
        st["failure"] |= bool(row.get("failure"))
        cls = (row.get("replay") or {}).get("class") or ""
        st["classes"].add(cls)
        st["read"] |= cls in READ
    return keys


def load_list(path):
    items = {}
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            words = line.split("#", 1)[0].split()
            if not words:
                continue
            if len(words) not in (2, 3) or (len(words) == 3 and words[2] != "unread"):
                raise ValueError(f"{path}:{n}: want `<entry> <variant or -> [unread]`, got {line.strip()!r}")
            items[(words[0], words[1])] = ("unread" if len(words) == 3 else "fail", n)
    return items


def selected(entry, globs):
    return not globs or any(fnmatch.fnmatchcase(entry, g) for g in globs)


def planned_entries(corpus):
    """Ledger entries the replay harness plans: kind ledger, replay.indexer_scope not sdk-only."""
    out = set()
    for d, dirs, names in os.walk(os.path.join(corpus, "manifest")):
        dirs.sort()
        for n in sorted(names):
            if n.endswith(".json"):
                with open(os.path.join(d, n), "rb") as f:
                    e = json.load(f)
                if e.get("kind") == "ledger" and (e.get("replay") or {}).get("indexer_scope") != "sdk-only":
                    out.add(e["id"])
    return out


def match(items, key, kind):
    """The list line covering this key for this kind (exact variant first, then `-`)."""
    for k in (key, (key[0], "-")):
        if k in items and items[k][0] == kind:
            return k
    return None


def check(a):
    keys = load_report(a.report)
    items = load_list(a.expected) if a.expected else {}
    globs = [g for g in (a.entries or "").split(",") if g]
    problems, used = [], set()
    still = 0
    for key in sorted(keys):
        st = keys[key]
        if st["failure"]:
            k = match(items, key, "fail")
            if k:
                used.add(k); still += 1
            else:
                problems.append(f"NEW-FAILURE      {key[0]} {key[1]}")
        if a.require_all_read and not st["read"]:
            k = match(items, key, "unread")
            if k:
                used.add(k)
            else:
                cls = ",".join(sorted(c for c in st["classes"] if c)) or "no class"
                problems.append(f"NEW-UNREAD       {key[0]} {key[1]}  ({cls})")
    for k, (kind, n) in sorted(items.items(), key=lambda x: x[1][1]):
        if k in used or not selected(k[0], globs):
            continue
        rows = [s for key, s in keys.items() if key[0] == k[0] and (k[1] == "-" or key[1] == k[1])]
        if not rows:
            problems.append(f"NOT-RUN          {k[0]} {k[1]}  (line {n}: no row for it in this run)")
        elif kind == "fail":
            problems.append(f"UNEXPECTED-PASS  {k[0]} {k[1]}  (line {n}: listed as failing; remove the line)")
        elif kind == "unread" and a.require_all_read:
            problems.append(f"UNEXPECTED-READ  {k[0]} {k[1]}  (line {n}: listed unread, now read; remove the line)")
    missing = 0
    if a.require_all_read and a.corpus:
        seen = {key[0] for key in keys}
        for e in sorted(planned_entries(a.corpus)):
            if selected(e, globs) and e not in seen and not match(items, (e, "-"), "unread"):
                problems.append(f"MISSING          {e} -  (a planned ledger entry with no row)")
                missing += 1
    for p in problems:
        print(p)
    count = lambda w: sum(1 for p in problems if p.startswith(w))
    print("expected failures (replay): %d still as listed, %d new failures, %d new unread, %d unexpected passes, "
          "%d listed but not run%s" % (still, count("NEW-FAILURE"), count("NEW-UNREAD") + missing,
                                       count("UNEXPECTED"), count("NOT-RUN"),
                                       "" if a.require_all_read else "; all-read check off"))
    return 1 if problems else 0


def write(a):
    keys = load_report(a.report)
    print("# Expected replay failures. Checked by replay_expect.py check REPORT --expected FILE: a new failure")
    print("# fails the run, and so does a listed entry variant that passes (remove its line when a bug is fixed).")
    print("# <entry> <variant or -> [unread]")
    for key in sorted(keys):
        st = keys[key]
        if st["failure"]:
            print(f"{key[0]} {key[1]}  # " + ",".join(sorted(st["classes"])))
        elif a.unread and not st["read"]:
            print(f"{key[0]} {key[1]} unread  # " + ",".join(sorted(st["classes"])))
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check")
    c.add_argument("report")
    c.add_argument("--expected")
    c.add_argument("--require-all-read", action="store_true")
    c.add_argument("--corpus")
    c.add_argument("--entries")
    w = sub.add_parser("write")
    w.add_argument("report")
    w.add_argument("--unread", action="store_true")
    a = p.parse_args()
    try:
        return check(a) if a.cmd == "check" else write(a)
    except (OSError, ValueError, KeyError) as e:
        print(f"replay_expect: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

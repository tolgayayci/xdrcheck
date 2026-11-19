#!/usr/bin/env python3
"""The sibling matrix: every SDK defect class the kit knows, against every SDK family it drives.

One SDK's fix is every other SDK's regression test only if someone looks for the same defect in the others. This
script does that look for every known defect at once, from executed runs: the level-resolved conformance matrices
(`matrix.json`) of the `pr` and `public` column sets, and the public finding records under `findings/` whose
component is `sdk` or `xdr-library`.

Defect classes are derived, not written by hand:

1. A unit is one finding record together with the cells (entry, variant, level) on which the runs show its
   declared divergence (`check: known`, `finding: <record>`). A record whose cells fail on different sets of
   columns is split into one unit per column set (one record can hold two defects with different version
   ranges); a record the runs never cite is one unit made of its own entries.
2. Units are joined into one class when they share a defect group (`defect_group`), when one record names the
   other as a sibling (`siblings`), or when they fail on the same (entry, variant, level) cell.
3. A class made only of `not-a-defect` records is not a row.

Each class's cells are then judged per SDK family on the class's own (entry, variant, level) cells, never on a
folded entry: `reproduces` when some version fails one of them (with the versions, the first later version run
that passes, the records the failing cells cite, and `pending` when a failing cell waits on finding review),
`not-a-defect` when every failing cell is explained by a `not-a-defect` record, `not-affected` when the family's
columns judged the cells and none failed, `outside-runs` when the runs pass or do not reach the cells but a
public record of the class shows the defect in that family by other means, and `not-run` when no column of the
family judged a cell (no driver in the public sets, or no column run gives a verdict on the cells).

A `not-run` cell becomes `not-applicable` when findings/siblings-not-applicable.json rules that the family has no
counterpart API for the class; the ruling's reason is the cell's `why`. Any other state (an executed result or a
public record) wins over a ruling. A ruling that names a class or family the matrix does not have is an error.

Usage:
    sibling_matrix.py generate --pr DIR --public DIR [--check]
        DIR: the report directories of `make verify-conformance` and the public set's run (each holds
        matrix.json); writes evidence/results/sibling-matrix.json and findings/SIBLINGS.md.
    sibling_matrix.py refresh [--check]
        the record states and the not-applicable rulings applied to the committed JSON, and the page re-rendered,
        without a run.
    sibling_matrix.py check
        the cheap check `make repo-checks` runs, without a run: the committed JSON is well formed, of the corpus
        conformance-matrix.json is of, agrees with it on every reproducing and not-affected cell, names only
        public records with their current state, carries exactly the not-applicable rulings, and
        findings/SIBLINGS.md is its rendering.
    sibling_matrix.py candidates --pr DIR --public DIR
        print every reproducing cell no public record of that family accounts for (entry, variant, level,
        columns, verdict). For the maintainer's own triage; never write it into the tree.

--check compares the committed files with what the sources give and exits 1 on any difference, without writing.
"""
import argparse, collections, json, os, re, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import results as R  # noqa: E402  (shared helpers: records, refs, dumping)

ROOT = R.ROOT
JSON_PATH = os.path.join(R.OUT, "sibling-matrix.json")
MD_PATH = os.path.join(ROOT, "findings", "SIBLINGS.md")
NA_PATH = os.path.join(ROOT, "findings", "siblings-not-applicable.json")
SCHEMA = "xdrcheck.results.sibling-matrix/v1"
GENERATED_BY = "make results-siblings"
STATES = ["reproduces", "not-a-defect", "outside-runs", "not-affected", "not-applicable", "not-run"]
FAILING = {"diverge", "accepts_invalid", "reject_valid", "crash", "wrong_value"}

# The SDK families, in column order. `columns` picks a run column ID; a family no public column belongs to has no
# driver in the public sets. `projects` are the upstream projects whose records count as the family's own.
FAMILIES = [
    {"id": "js", "label": "JavaScript 17.x", "projects": ["stellar/js-stellar-sdk", "stellar/js-stellar-base", "stellar/js-xdr"],
     "match": lambda c: c["sdk"] == "js" and c["version"].startswith("17.")},
    {"id": "js16", "label": "JavaScript 16.x", "projects": ["stellar/js-stellar-sdk", "stellar/js-stellar-base", "stellar/js-xdr"],
     "match": lambda c: c["sdk"] == "js" and c["version"].startswith("16.")},
    {"id": "go", "label": "Go", "projects": ["stellar/go-stellar-sdk", "stellar/go-xdr"],
     "match": lambda c: c["sdk"] == "go" and not c.get("profile")},
    {"id": "rust", "label": "Rust (default limits)", "projects": ["stellar/rs-stellar-xdr", "stellar/rs-stellar-strkey"],
     "match": lambda c: c["sdk"] == "rust" and c.get("profile") == "limits-default"},
    {"id": "rust-nolimits", "label": "Rust (no limits)", "projects": ["stellar/rs-stellar-xdr", "stellar/rs-stellar-strkey"],
     "match": lambda c: c["sdk"] == "rust" and c.get("profile") == "limits-none"},
    {"id": "python", "label": "Python", "projects": ["StellarCN/py-stellar-base"],
     "match": lambda c: c["sdk"] == "python"},
    {"id": "java", "label": "Java", "projects": ["lightsail-network/java-stellar-sdk"], "match": lambda c: c["sdk"] == "java"},
    {"id": "dotnet", "label": ".NET", "projects": ["Beans-BV/dotnet-stellar-sdk"], "match": lambda c: c["sdk"] == "dotnet"},
    {"id": "core", "label": "stellar-core", "projects": ["stellar/stellar-core"], "match": lambda c: c["sdk"] == "core"},
]
FAMILY_IDS = [f["id"] for f in FAMILIES]
LEVEL = re.compile(r"^(L[0-4]|spec|json)$")


class Fail(Exception):
    pass


def read(path):
    if not os.path.exists(path):
        return ""
    with open(path) as f:
        return f.read()


def vkey(v):
    return tuple(int(x) if x.isdigit() else x for x in re.split(r"[.\-+]", v.lstrip("v")))


def family_of_column(col):
    for f in FAMILIES:
        if f["match"](col):
            return f["id"]
    raise Fail(f"column {col['id']}: no SDK family")


def record_families(rec):
    """The families a record is about, from its project (and, for the JavaScript SDK, the major lines its
    affected-versions text names)."""
    proj = rec["target"]["project"]
    fams = [f["id"] for f in FAMILIES if proj in f["projects"]]
    # The affected range is the text's first clause; later clauses and remarks in parentheses may name versions
    # that are not affected.
    va = re.sub(r"\([^()]*\)", "", rec["target"].get("versions_affected") or "").split(";")[0]
    if "js" in fams:
        lines = {"js16"} if re.search(r"(^|\D)16\.", va) else set()
        if re.search(r"(^|\D)17\.|main|master", va) or not lines:
            lines.add("js")
        fams = [f for f in fams if f not in ("js", "js16")] + sorted(lines)
    if "rust" in fams and "Limits::none" in (rec.get("title", "") + va):
        fams = [f for f in fams if f != "rust"]
    return fams


def sdk_records():
    recs = R.public_findings()
    return {k: v for k, v in recs.items() if v["component"] in ("sdk", "xdr-library")}


# ---------------------------------------------------------------- runs

def load_runs(pr_dir, public_dir):
    """Columns by ID and cells by (entry, variant, level, column), merged over the two runs."""
    columns, cells, corpus = {}, {}, None
    for name, d in (("pr", pr_dir), ("public", public_dir)):
        m = R.load(os.path.join(d, "matrix.json"))
        if m.get("schema") != "xcc.conformance.matrix/v1":
            raise Fail(f"{name}: not a conformance matrix")
        c = {"version": m["corpus"]["version"], "manifest_sha256": m["corpus"]["manifest_sha256"]}
        if corpus not in (None, c):
            raise Fail("the pr and public runs are of different corpora")
        corpus = c
        for col in m["columns"]:
            columns[col["id"]] = {"id": col["id"], "sdk": col["sdk"], "version": col["version"].lstrip("v"),
                                  "profile": col.get("profile")}
        for x in m["cells"]:
            k = (x["entry"], x.get("variant", "") or "", x["level"], x["column"])
            v = {"verdict": x["verdict"], "check": x["check"], "finding": x.get("finding"),
                 "pending": bool(x.get("pending_review"))}
            if k in cells and cells[k] != v:
                raise Fail(f"{k}: the pr run gives {cells[k]}, the public run {v}")
            cells[k] = v
    return corpus, columns, cells


# ---------------------------------------------------------------- classes

def split_record(keyed, cells):
    """Split one record's failing cells into defects: cells that fail on the same columns are one group, and two
    groups are one defect unless a column fails one group while it judges every cell of the other conform (a
    column that does not reach a cell, n_a, says nothing)."""
    groups = collections.defaultdict(set)
    for k, cols in keyed.items():
        groups[frozenset(cols)].add(k)
    groups = [{"keys": set(ks), "fail": set(f)} for f, ks in sorted(groups.items(), key=lambda kv: sorted(kv[1])[0])]
    for g in groups:
        judged = {col for (e, v, l, col), c in cells.items() if (e, v, l) in g["keys"] and c["verdict"] != "n_a"}
        g["pass"] = judged - g["fail"]
    merged = True
    while merged:
        merged = False
        for i in range(len(groups)):
            for j in range(i + 1, len(groups)):
                a, b = groups[i], groups[j]
                if not (a["fail"] & b["pass"]) and not (b["fail"] & a["pass"]):
                    a["keys"] |= b["keys"]
                    a["fail"] |= b["fail"]
                    a["pass"] = (a["pass"] | b["pass"]) - a["fail"]
                    del groups[j]
                    merged = True
                    break
            if merged:
                break
    return [g["keys"] for g in groups]


def build_classes(recs, columns, cells):
    # 1. units
    units = []  # {"records": {id}, "keys": {(e, v, l)}}
    by_record = collections.defaultdict(lambda: collections.defaultdict(set))  # rid -> key -> failing columns
    for (e, v, l, col), c in cells.items():
        if c["check"] == "known" and c["finding"] in recs:
            by_record[c["finding"]][(e, v, l)].add(col)
    record_units = collections.defaultdict(list)
    run_keys = {(e, v, l) for (e, v, l, _) in cells}
    for rid in sorted(recs):
        keyed = by_record.get(rid)
        if keyed:
            for keys in split_record(keyed, cells):
                units.append({"records": {rid}, "keys": keys})
                record_units[rid].append(len(units) - 1)
        else:
            keys = set()
            for e in recs[rid].get("entries", []):
                if not e.get("id") or e["id"] == "none" or not LEVEL.match(e.get("scope") or ""):
                    continue
                if e.get("variant"):
                    keys.add((e["id"], e["variant"], e["scope"]))
                else:  # a record entry without a variant names every variant of the entry at that level
                    keys |= {k for k in run_keys if k[0] == e["id"] and k[2] == e["scope"]}
            units.append({"records": {rid}, "keys": keys})
            record_units[rid].append(len(units) - 1)

    parent = list(range(len(units)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(a, b):
        a, b = find(a), find(b)
        if a != b:
            parent[max(a, b)] = min(a, b)

    def join_records(a, b):
        ua, ub = record_units[a], record_units[b]
        pairs = [(x, y) for x in ua for y in ub if units[x]["keys"] & units[y]["keys"]]
        if not pairs:
            pairs = [(x, y) for x in ua for y in ub if len(ua) == 1 or len(ub) == 1]
        for x, y in pairs:
            union(x, y)

    # 2. joins
    groups = collections.defaultdict(list)
    for rid, rec in recs.items():
        if rec.get("defect_group"):
            groups[rec["defect_group"]].append(rid)
        for s in rec.get("siblings") or []:
            if s in recs:
                join_records(rid, s)
    for rids in groups.values():
        for r in rids[1:]:
            join_records(rids[0], r)
    owner = {}
    for i, u in enumerate(units):
        for k in u["keys"]:
            if k in owner:
                union(owner[k], i)
            else:
                owner[k] = i

    merged = collections.defaultdict(lambda: {"records": set(), "keys": set(), "units": []})
    for i, u in enumerate(units):
        m = merged[find(i)]
        m["records"] |= u["records"]
        m["keys"] |= u["keys"]
        m["units"].append(i)
    classes = []
    for m in merged.values():
        if all(recs[r]["state"] == "not-a-defect" for r in m["records"]):
            continue
        classes.append(m)
    # 3. names: the defect group most of the class's records carry, else its lowest record; the title of the
    # lowest record that lies wholly inside the class (a record split over two classes describes both).
    out = []
    used = collections.Counter()
    for m in sorted(classes, key=lambda m: min(m["records"])):
        rids = sorted(m["records"])
        dg = collections.Counter(recs[r]["defect_group"] for r in rids if recs[r].get("defect_group"))
        cid = dg.most_common(1)[0][0] if dg else "DC-" + rids[0]
        used[cid] += 1
        if used[cid] > 1:
            cid += f"-{used[cid]}"
        whole = [r for r in rids if all(find(u) == find(m["units"][0]) for u in record_units[r])
                 and recs[r]["state"] != "not-a-defect"]
        title_rec = recs[(whole or [r for r in rids if recs[r]["state"] != "not-a-defect"])[0]]
        title = R.strip_refs(title_rec["title"])
        if R.FOREIGN_REF.search(title):
            raise Fail(f"{title_rec['id']}: title carries an upstream reference")
        out.append({"id": cid, "title": title, "title_from": title_rec["id"], "records": rids, "keys": sorted(m["keys"])})
    return out


# ---------------------------------------------------------------- cells

def judge(cls, recs, columns, cells, fam_columns):
    rec_fams = {r: record_families(recs[r]) for r in cls["records"]}
    row = {}
    for fid in FAMILY_IDS:
        cols = fam_columns.get(fid, [])
        fails, passes, cited, pending, nad_only = [], [], set(), False, True
        for col in cols:
            failed, judged = False, False
            for (e, v, l) in cls["keys"]:
                c = cells.get((e, v, l, col))
                if c is None or c["verdict"] == "n_a":
                    continue
                judged = True
                if c["verdict"] in FAILING:
                    failed = True
                    if c["pending"]:
                        pending = True
                        nad_only = False
                    elif c["finding"]:
                        cited.add(c["finding"])
                        if recs.get(c["finding"], {}).get("state") != "not-a-defect":
                            nad_only = False
                    else:
                        nad_only = False
            if failed:
                fails.append(col)
            elif judged:
                passes.append(col)
        own = {r for r in cls["records"] if fid in rec_fams[r]}
        cell = {}
        if fails:
            cell["state"] = "not-a-defect" if nad_only else "reproduces"
            cell["versions"] = [columns[c]["version"] for c in fails]
            last = max(fails, key=lambda c: vkey(columns[c]["version"]))
            later = sorted((c for c in passes if vkey(columns[c]["version"]) > vkey(columns[last]["version"])),
                           key=lambda c: vkey(columns[c]["version"]))
            cell["passes_from"] = columns[later[0]]["version"] if later else None
            cell["records"] = sorted(cited | own)
            if pending:
                cell["pending"] = True
        elif own and any(recs[r]["state"] != "not-a-defect" for r in own):
            cell["state"] = "outside-runs"
            cell["versions_run"] = [columns[c]["version"] for c in passes]
            cell["records"] = sorted(own)
        elif passes:
            cell["state"] = "not-affected"
            cell["versions"] = [columns[c]["version"] for c in passes]
        else:
            cell["state"] = "not-run"
            cell["why"] = not_run_why(cols)
        row[fid] = cell
    return row


def not_run_why(columns):
    return "no driver in the public column sets" if not columns else "no column run gives a verdict on the cells"


def load_rulings(path=None):
    """The not-applicable rulings: {(class, family): reason}, checked for shape."""
    path = path or NA_PATH
    d = R.load(path)
    where = R.rel(path)
    if set(d) != {"about", "rulings"} or not isinstance(d["rulings"], list):
        raise Fail(f"{where}: expected the keys about and rulings")
    out = {}
    for i, r in enumerate(d["rulings"]):
        at = f"{where}: ruling {i + 1}"
        if set(r) != {"class", "families", "reason"} or not r["families"]:
            raise Fail(f"{at}: expected class, families (non-empty) and reason")
        reason = r["reason"]
        if not isinstance(reason, str) or not reason.strip() or "\n" in reason or "|" in reason:
            raise Fail(f"{at}: the reason must be one line of text without |")
        if R.FOREIGN_REF.search(reason):
            raise Fail(f"{at}: the reason carries an upstream reference")
        for f in r["families"]:
            if f not in FAMILY_IDS:
                raise Fail(f"{at}: {f} is not an SDK family ({', '.join(FAMILY_IDS)})")
            if (r["class"], f) in out:
                raise Fail(f"{at}: {r['class']} × {f} is ruled twice")
            out[(r["class"], f)] = reason
    return out


def apply_rulings(rows, families, rulings):
    """Turn the ruled not-run cells of `rows` (the JSON's classes) into not-applicable cells, after first turning
    every not-applicable cell back into not-run, so applying twice, or after a ruling is removed, gives the same
    result. A cell with any other state keeps it. A not-run cell's `why` follows from the family's columns."""
    ids = {r["id"] for r in rows}
    for (cid, f) in sorted(rulings):
        if cid not in ids:
            raise Fail(f"{R.rel(NA_PATH)}: class {cid} is not in the sibling matrix")
    for r in rows:
        for f, x in r["cells"].items():
            if x["state"] in ("not-applicable", "not-run"):
                r["cells"][f] = {"state": "not-run", "why": not_run_why(families[f]["columns"])}
            if r["cells"][f]["state"] == "not-run" and (r["id"], f) in rulings:
                r["cells"][f] = {"state": "not-applicable", "why": rulings[(r["id"], f)]}
    return rows


def count_states(rows):
    totals = collections.Counter(x["state"] for c in rows for x in c["cells"].values())
    return {s: totals.get(s, 0) for s in STATES}


def record_view(recs, rids):
    out = {}
    for r in sorted(rids):
        d = recs[r]
        v = {"state": d["state"], "project": d["target"]["project"]}
        if d["state"] == "filed":
            url = (d.get("upstream") or {}).get("url")
            if not url:
                raise Fail(f"{r}: filed without an upstream URL")
            v["url"] = url
        out[r] = v
    return out


def generate(pr_dir, public_dir):
    recs = sdk_records()
    corpus, columns, cells = load_runs(pr_dir, public_dir)
    conf = R.load(os.path.join(R.OUT, "conformance-matrix.json"))
    if conf["corpus"] != corpus:
        raise Fail(f"the runs are of corpus {corpus}, evidence/results/conformance-matrix.json of {conf['corpus']}")
    public_cols = set(conf["sets"]["public"])
    fam_columns = collections.defaultdict(list)
    for cid in sorted(columns, key=lambda c: (c.split("@")[0], vkey(columns[c]["version"]))):
        if cid in public_cols:
            fam_columns[family_of_column(columns[cid])].append(cid)
    classes = build_classes(recs, columns, cells)
    rows, cited = [], set()
    for cls in classes:
        row = judge(cls, recs, columns, cells, fam_columns)
        for c in row.values():
            cited.update(c.get("records", []))
        cited.update(cls["records"])
        rows.append({
            "id": cls["id"],
            "title": cls["title"],
            "title_from": cls["title_from"],
            "records": cls["records"],
            "entries": sorted({k[0] for k in cls["keys"]}),
            "cells": row,
        })
    families = {f["id"]: {"label": f["label"], "columns": fam_columns.get(f["id"], [])} for f in FAMILIES}
    apply_rulings(rows, families, load_rulings())
    return {
        "schema": SCHEMA,
        "generated_by": GENERATED_BY,
        "corpus": corpus,
        "states": STATES,
        "families": families,
        "classes": rows,
        "records": record_view(recs, cited),
        "totals": count_states(rows),
    }


def candidates(pr_dir, public_dir):
    """Reproducing cells that no public record of the cell's family accounts for."""
    recs = sdk_records()
    corpus, columns, cells = load_runs(pr_dir, public_dir)
    out = []
    for (e, v, l, col), c in sorted(cells.items()):
        if c["verdict"] not in FAILING:
            continue
        fam = family_of_column(columns[col])
        rec = recs.get(c["finding"]) if c["finding"] else None
        if rec and fam in record_families(rec):
            continue
        out.append({"entry": e, "variant": v, "level": l, "column": col, "verdict": c["verdict"],
                    "check": c["check"], "finding": c["finding"], "pending": c["pending"]})
    return out


# ---------------------------------------------------------------- rendering

def versions_text(vs):
    return ", ".join(vs)


def cell_short(c):
    s = c["state"]
    if s == "reproduces":
        t = "reproduces " + versions_text(c["versions"])
        if c.get("passes_from"):
            t += f"; passes from {c['passes_from']}"
        return t
    return {"not-a-defect": "differs, not a defect", "outside-runs": "record only", "not-affected": "not affected",
            "not-applicable": "not applicable", "not-run": "not run"}[s]


def record_text(rid, view):
    v = view[rid]
    if v["state"] == "filed":
        return f"{rid} ([filed]({v['url']}))"
    if v["state"] == "duplicate-of":
        return f"{rid} (known upstream)"
    return f"{rid} ({v['state']})"


def render(d):
    fams = [f for f in FAMILY_IDS]
    labels = {k: v["label"] for k, v in d["families"].items()}
    t = d["totals"]
    lines = [
        "# Sibling matrix: each SDK defect class across the SDK families",
        "",
        "<!-- Generated by `make results-siblings` (scripts/py/sibling_matrix.py) from evidence/results/sibling-matrix.json;",
        "     do not edit by hand. `make repo-checks` fails when this page and the JSON disagree. -->",
        "",
        "A defect found in one SDK is looked for in every other SDK the kit drives. Each row is one defect class,",
        "derived from the public finding records and the corpus cells their divergences show on (records joined by",
        "defect group, by sibling link, or by failing on the same entry, variant and level). Each cell is read from",
        "the executed conformance runs of the `pr` and `public` column sets (`drivers/sets.toml`) on exactly those",
        "cells, not from reading the SDK's code.",
        "",
        f"Corpus {d['corpus']['version']} (manifest sha256 `{d['corpus']['manifest_sha256'][:16]}…`). "
        f"{len(d['classes'])} classes × {len(fams)} families: "
        + ", ".join(f"{t[s]} {s}" for s in STATES) + ".",
        "",
        "| State | Meaning |",
        "|---|---|",
        "| reproduces | some version run fails one of the class's cells; the versions that fail, the first later version run that passes, and the records |",
        "| pending | (with reproduces) a failing cell waits on finding review; nothing more is published about it |",
        "| differs, not a defect | the family fails the cells, and its record shows that the behaviour is the network's own or by design |",
        "| record only | the runs pass or do not reach the cells, but a public record shows the defect in this family by other means (an API the drivers do not call, a level outside the column sets, a source reading) |",
        "| not affected | the family's columns judged the cells and none failed |",
        "| not applicable | the family has no counterpart API for this class; the reason is given (`findings/siblings-not-applicable.json`) |",
        "| not run | no column of the family judged a cell: no driver in the public column sets, or no column run gives a verdict on the cells |",
        "",
        "Records: a record this kit filed links to its issue; `known upstream` means the defect was already reported",
        "upstream before the kit found it.",
        "",
        "## Overview",
        "",
        "| Class | " + " | ".join(labels[f] for f in fams) + " |",
        "|---|" + "---|" * len(fams),
    ]
    for c in d["classes"]:
        cells = []
        for f in fams:
            x = c["cells"][f]
            s = {"reproduces": "**R**", "not-a-defect": "nd", "outside-runs": "rec", "not-affected": "ok",
                 "not-applicable": "n/a", "not-run": "–"}[x["state"]]
            if x.get("pending"):
                s += " (pending)"
            cells.append(s)
        lines.append(f"| [{c['id']}](#{c['id'].lower()}) | " + " | ".join(cells) + " |")
    lines += ["", "**R** reproduces · nd differs, not a defect · rec record only · ok not affected · n/a not applicable"
              " · – not run", ""]
    for c in d["classes"]:
        lines += [f"## {c['id']}", "", c["title"] + f" (title of {c['title_from']}).", "",
                  "Records: " + ", ".join(record_text(r, d["records"]) for r in c["records"]) + ".", "",
                  "Entries: " + ", ".join(f"`{e}`" for e in c["entries"]) + ".", "",
                  "| Family | Result | Records |", "|---|---|---|"]
        for f in fams:
            x = c["cells"][f]
            res = cell_short(x)
            if x["state"] in ("not-run", "not-applicable"):
                res += f" ({x['why']})"
            if x["state"] == "not-affected":
                res += " (" + versions_text(x["versions"]) + ")"
            if x["state"] == "outside-runs" and x.get("versions_run"):
                res += " (runs pass on " + versions_text(x["versions_run"]) + ")"
            if x["state"] == "not-a-defect":
                res += " (" + versions_text(x["versions"]) + ")"
            if x.get("pending"):
                res += "; pending"
            recs = ", ".join(record_text(r, d["records"]) for r in x.get("records", [])) or "–"
            lines.append(f"| {labels[f]} | {res} | {recs} |")
        lines.append("")
    lines += ["## Regenerate", "", "```sh",
              "make verify-conformance OFFLINE=1            # the pr set, into $(REPORTS)/conformance",
              "make verify-conformance-public OFFLINE=1     # the public set, into $(REPORTS)/conformance-public",
              "make results-siblings                        # this page and evidence/results/sibling-matrix.json",
              "make results-siblings RESULTS_CHECK=1        # compare instead of writing",
              "```", ""]
    return "\n".join(lines)


# ---------------------------------------------------------------- checks

def cheap_check():
    errs = []
    if not os.path.exists(JSON_PATH):
        return [f"{R.rel(JSON_PATH)}: missing"]
    d = R.load(JSON_PATH)
    if d.get("schema") != SCHEMA or d.get("generated_by") != GENERATED_BY:
        return [f"{R.rel(JSON_PATH)}: schema or generated_by"]
    conf = R.load(os.path.join(R.OUT, "conformance-matrix.json"))
    if d["corpus"] != conf["corpus"]:
        errs.append(f"{R.rel(JSON_PATH)}: corpus differs from conformance-matrix.json (regenerate both from one run)")
    recs = sdk_records()
    allrecs = R.public_findings()
    if sorted(d["families"]) != sorted(FAMILY_IDS):
        errs.append(f"{R.rel(JSON_PATH)}: families are not {FAMILY_IDS}")
    for f, meta in d["families"].items():
        for col in meta["columns"]:
            if col not in conf["columns"]:
                errs.append(f"{R.rel(JSON_PATH)}: family {f}: column {col} is not in conformance-matrix.json")
    cited = set()
    for c in d["classes"]:
        where = f"{R.rel(JSON_PATH)}: {c['id']}"
        if set(c["cells"]) != set(FAMILY_IDS):
            errs.append(f"{where}: cells are not one per family")
            continue
        for r in c["records"]:
            if r not in recs:
                errs.append(f"{where}: {r} is not a public sdk or xdr-library record")
        for e in c["entries"]:
            if e not in conf["entries"]:
                errs.append(f"{where}: entry {e} is not in conformance-matrix.json")
        if R.FOREIGN_REF.search(c["title"]):
            errs.append(f"{where}: title carries an upstream reference")
        for f, x in c["cells"].items():
            if x["state"] not in STATES:
                errs.append(f"{where} {f}: state {x['state']!r}")
                continue
            cited.update(x.get("records", []))
            cols = {conf["columns"][col]["version"].lstrip("v"): col for col in d["families"][f]["columns"]}
            folded = [conf["entries"].get(e, {}) for e in c["entries"]]
            if x["state"] in ("reproduces", "not-a-defect"):
                for v in x["versions"]:
                    col = cols.get(v)
                    if col is None:
                        errs.append(f"{where} {f}: version {v} is not a column of the family")
                    elif not any(fe.get(col, {}).get("class") in ("diverges", "pending") for fe in folded):
                        errs.append(f"{where} {f}: {v} reproduces, but conformance-matrix.json shows no divergence on the class's entries")
            if x["state"] == "not-affected":
                for v in x["versions"]:
                    col = cols.get(v)
                    if col is None or not any(fe.get(col, {}).get("class") == "agrees" for fe in folded):
                        errs.append(f"{where} {f}: {v} not affected, but conformance-matrix.json shows no agreeing cell")
            if x.get("pending") and not any(fe.get(cols.get(v), {}).get("class") == "pending"
                                            for fe in folded for v in x.get("versions", [])):
                errs.append(f"{where} {f}: pending, but conformance-matrix.json shows no pending cell")
    cited |= {r for c in d["classes"] for r in c["records"]}
    if set(d["records"]) != cited:
        errs.append(f"{R.rel(JSON_PATH)}: records map is not exactly the records the classes cite")
    try:
        view = record_view(allrecs, cited & set(allrecs))
        if view != {k: v for k, v in d["records"].items() if k in view}:
            errs.append(f"{R.rel(JSON_PATH)}: a record's state or issue differs from findings/ (make results-siblings-refresh)")
    except Fail as e:
        errs.append(str(e))
    if d.get("states") != STATES:
        errs.append(f"{R.rel(JSON_PATH)}: states are not {STATES}")
    try:
        ruled = apply_rulings(json.loads(json.dumps(d["classes"])), d["families"], load_rulings())
        if ruled != d["classes"]:
            errs.append(f"{R.rel(JSON_PATH)}: the not-applicable cells differ from {R.rel(NA_PATH)} (make results-siblings-refresh)")
    except (Fail, R.Fail) as e:
        errs.append(str(e))
    if d["totals"] != count_states(d["classes"]):
        errs.append(f"{R.rel(JSON_PATH)}: totals do not match the cells")
    text = read(JSON_PATH)
    allowed = {v["url"] for v in d["records"].values() if v.get("url")}
    for m in R.FOREIGN_REF.finditer(text):
        line = text[text.rfind("\n", 0, m.start()) + 1: text.find("\n", m.end())]
        if not any(u in line for u in allowed):
            errs.append(f"{R.rel(JSON_PATH)}: an upstream reference that is not a filed record's own issue: {line.strip()}")
    md = read(MD_PATH)
    if md != render(d):
        errs.append(f"{R.rel(MD_PATH)}: differs from the rendering of {R.rel(JSON_PATH)} (make results-siblings-refresh)")
    return errs


def refresh():
    """Rewrite the records map from findings/, apply the not-applicable rulings and re-render the page, without a
    run (a record changed state, or a ruling changed)."""
    d = R.load(JSON_PATH)
    allrecs = R.public_findings()
    d["records"] = record_view(allrecs, set(d["records"]))
    d["states"] = STATES
    apply_rulings(d["classes"], d["families"], load_rulings())
    d["totals"] = count_states(d["classes"])
    return d


def write(obj, check):
    rc = R.write_or_check("sibling-matrix.json", obj, check, JSON_PATH)
    md = render(obj)
    if check:
        old = read(MD_PATH)
        if old != md:
            print(f"{R.rel(MD_PATH)}: differs from a fresh generation", file=sys.stderr)
            return 1
        print(f"{R.rel(MD_PATH)}: current")
        return rc
    with open(MD_PATH, "w") as f:
        f.write(md)
    print(f"{R.rel(MD_PATH)}: written")
    return rc


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("generate")
    g.add_argument("--pr", required=True)
    g.add_argument("--public", required=True)
    g.add_argument("--check", action="store_true")
    c = sub.add_parser("candidates")
    c.add_argument("--pr", required=True)
    c.add_argument("--public", required=True)
    sub.add_parser("check")
    sub.add_parser("refresh").add_argument("--check", action="store_true")
    a = ap.parse_args()
    try:
        if a.cmd == "generate":
            return write(generate(a.pr, a.public), a.check)
        if a.cmd == "candidates":
            for x in candidates(a.pr, a.public):
                print(json.dumps(x, sort_keys=True))
            return 0
        if a.cmd == "refresh":
            return write(refresh(), a.check)
        errs = cheap_check()
        for e in errs:
            print(e, file=sys.stderr)
        if not errs:
            print(f"{R.rel(JSON_PATH)}, {R.rel(MD_PATH)}: consistent with conformance-matrix.json and findings/")
        return 1 if errs else 0
    except (Fail, R.Fail) as e:
        print(f"sibling_matrix: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

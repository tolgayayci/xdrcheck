#!/usr/bin/env python3
"""Generate and check the results data under evidence/results/ (evidence/results/README.md has the formats).

Every file is made from public sources only: the tracked corpus index, the tracked finding records
(`visibility: public`), the tracked pending lists, pins.toml, the README's known-defects table, and the report
directories of runs of the public column sets and the pinned pipelines. Output fields are whitelisted: nothing of a
run's notes, evidence, values or declared-divergence references is copied.

Usage:
    results.py conformance --pr DIR --public DIR [--check]
        DIR: the report directories `make verify-conformance` and `make verify-conformance-public` wrote
        (each holds matrix.json).
    results.py replay --replay-full DIR --replay-regression DIR --replay-etl-known DIR --selftest DIR [--check]
        the report directories of `make replay-full`, `make verify-replay`, `make replay-etl-known` and
        `make harness-selftest` (its `none` run is the unmodified baseline indexer).
    results.py findings [--check]
    results.py known-defects [--check]
    results.py prevalence --entry-tokens TSV --token-table TSV [--check]
        evidence/mainnet-scan/entry-prevalence.json: per corpus entry, the rarest of its shape tokens and how often
        that token occurs on mainnet. TSV: the output of `xdrcheck-corpus scan entry-tokens`, and the scan's
        token table (`scan token-census` tokens.tsv, or .tsv.zst). Aggregates only.
    results.py acceptance --table FILE [--check]
        evidence/results/acceptance.json: one row per acceptance check of docs/acceptance.md, with the status and
        reason of the acceptance table FILE (the acceptance.json `xdrcheck report acceptance` writes beside
        acceptance.md; `make verify-acceptance` makes it), and the run that made it: the commit of the tree and
        whether it was a GitHub Actions run (its run ID) or a local one. Run it in the tree the table was made in.
    results.py check
        the cheap check `make repo-checks` runs: findings.json and known-defects.json equal a fresh generation, and
        conformance-matrix.json, replay-summary.json, acceptance.json and the mainnet entry-prevalence file (when
        present) are well formed and consistent with corpus/index.json, findings/, findings/pending/,
        docs/acceptance.md and guide/claims.yaml.

--check compares the committed file with what the sources give and exits 1 on any difference, without writing.
"""
import argparse, collections, glob, json, os, re, sys, tomllib

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
OUT = os.path.join(ROOT, "evidence", "results")
PREVALENCE = os.path.join(ROOT, "evidence", "mainnet-scan", "entry-prevalence.json")

CONF_CLASSES = ["agrees", "diverges", "pending", "not-run"]
CONF_FOLD = ["diverges", "pending", "agrees", "not-run"]  # first present wins
REPLAY_CLASSES = ["pass", "mishandled", "dropped", "halt", "refused", "pending", "not-run", "error"]
REPLAY_FOLD = ["error", "halt", "refused", "mishandled", "dropped", "pending", "pass", "not-run"]
COVERAGE = ["reproduced", "run", "checked", "agreement", "input"]
FINDING_STATES = ["filed", "duplicate-of", "not-a-defect"]
SEVERITIES = ["critical", "high", "medium", "low"]
# An upstream URL or issue number in generated text is refused (only a filed record's own issue URL is allowed).
FOREIGN_REF = re.compile(r"\b[\w.-]+#\d+|/(?:issues|pull|discussions)/\d+|(?:^|[\s(\[\"])#\d+|\b(?:PR|[Ii]ssue|[Pp]ull request)s? #?\d+")


class Fail(Exception):
    pass


def strip_refs(text):
    """Drop the parts of parenthesised remarks that cite an upstream item ("(since repo#N; range not
    established)" becomes "(range not established)"); a citation outside parentheses is left for the caller to
    refuse."""
    if not isinstance(text, str):
        return text
    def paren(m):
        parts = [p.strip() for p in m.group(1).split(";") if not FOREIGN_REF.search(p)]
        return f"({'; '.join(parts)})" if parts else ""
    return re.sub(r"\s*\(([^()]*)\)", lambda m: (" " + paren(m)) if paren(m) else "", text).strip()


def load(path):
    with open(path) as f:
        return json.load(f)


def dump(obj):
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def rel(path):
    return os.path.relpath(path, ROOT)


def public_findings():
    recs = {}
    for f in sorted(glob.glob(os.path.join(ROOT, "findings", "F-*", "finding.json"))):
        d = load(f)
        if d.get("visibility") != "public":
            continue
        recs[d["id"]] = d
    return recs


def corpus_index():
    idx = load(os.path.join(ROOT, "corpus", "index.json"))
    return {e["id"]: e for e in idx["entries"]}


def known_finding(fid, recs, where):
    if fid not in recs:
        raise Fail(f"{where}: finding {fid} has no public record under findings/")
    return fid


def pending_conformance():
    d = load(os.path.join(ROOT, "findings", "pending", "conformance.json"))
    return {(p["entry"], p["column"]) for p in d["pending"]}


def pending_replay():
    """(entry, target name) pairs of the tracked replay pending lists."""
    out = set()
    for f in sorted(glob.glob(os.path.join(ROOT, "findings", "pending", "*.json"))):
        d = load(f)
        for p in d.get("pending", []):
            if "column" in p:
                continue
            out.add(p.get("entry"))
    return out


# ---------------------------------------------------------------- conformance

def conformance(pr_dir, public_dir):
    recs = public_findings()
    index = corpus_index()
    pend = pending_conformance()
    matrices = {"pr": load(os.path.join(pr_dir, "matrix.json")), "public": load(os.path.join(public_dir, "matrix.json"))}
    columns, sets, cells = {}, {}, {}
    corpus = None
    for name, m in matrices.items():
        if m.get("schema") != "xcc.conformance.matrix/v1":
            raise Fail(f"{name}: not a conformance matrix")
        c = {"version": m["corpus"]["version"], "manifest_sha256": m["corpus"]["manifest_sha256"]}
        if corpus is not None and corpus != c:
            raise Fail("the pr and public runs are of different corpora")
        corpus = c
        sets[name] = sorted(col["id"] for col in m["columns"])
        for col in m["columns"]:
            meta = {
                "sdk": col["sdk"],
                "package": (col.get("describe_sdk") or {}).get("package") or col.get("target"),
                "version": col["version"],
                "profile": col.get("profile"),
                "role": col.get("role"),
                "release_date": None,
            }
            if columns.setdefault(col["id"], meta) != meta:
                raise Fail(f"column {col['id']} differs between the pr and public runs")
        run_cells = collections.defaultdict(set)
        run_findings = collections.defaultdict(set)
        for x in m["cells"]:
            where = f"{name} run: {x['entry']} {x.get('variant', '')} {x['level']} {x['column']}"
            if x["entry"] not in index:
                raise Fail(f"{where}: entry not in corpus/index.json")
            chk = x["check"]
            if chk == "conform":
                cls = "agrees"
            elif chk == "n_a":
                cls = "not-run"
            elif chk == "known":
                cls = "diverges"
                if x.get("finding"):
                    run_findings[(x["entry"], x["column"])].add(known_finding(x["finding"], recs, where))
            elif chk == "undeclared" and x.get("pending_review"):
                if (x["entry"], x["column"]) not in pend:
                    raise Fail(f"{where}: pending cell not in findings/pending/conformance.json")
                cls = "pending"
            else:
                raise Fail(f"{where}: check {chk!r} is neither conform, known, n_a nor a pending cell")
            run_cells[(x["entry"], x["column"])].add(cls)
        for key, classes in run_cells.items():
            cls = next(c for c in CONF_FOLD if c in classes)
            cell = {"class": cls}
            if cls == "diverges":
                cell["findings"] = sorted(run_findings.get(key, ()))
            if key in cells and cells[key] != cell:
                raise Fail(f"{key[0]} {key[1]}: the pr run gives {cells[key]}, the public run {cell}")
            cells[key] = cell
    for col in sets["public"]:
        for e in {k[0] for k in cells}:
            if (e, col) not in cells:
                raise Fail(f"{e} {col}: no cell in the public run")
    if not set(sets["pr"]) <= set(sets["public"]):
        raise Fail("the pr set is not inside the public set")
    entries = collections.defaultdict(dict)
    totals = {c: {k: 0 for k in CONF_CLASSES} for c in columns}
    for (e, col), cell in cells.items():
        entries[e][col] = cell
        totals[col][cell["class"]] += 1
    return {
        "schema": "xdrcheck.results.conformance-matrix/v1",
        "generated_by": "make results-conformance",
        "corpus": corpus,
        "sets": sets,
        "columns": columns,
        "classes": CONF_CLASSES,
        "entries": dict(entries),
        "totals": totals,
    }


def check_conformance_file(d, recs, index):
    errs = []
    if d.get("schema") != "xdrcheck.results.conformance-matrix/v1" or not d.get("generated_by"):
        return ["conformance-matrix.json: schema or generated_by missing"]
    pend = pending_conformance()
    cols = set(d["columns"])
    if set(d["sets"]["public"]) != cols or not set(d["sets"]["pr"]) <= cols:
        errs.append("conformance-matrix.json: sets and columns disagree")
    totals = {c: {k: 0 for k in CONF_CLASSES} for c in cols}
    for e, row in d["entries"].items():
        if e not in index:
            errs.append(f"conformance-matrix.json: {e} is not in corpus/index.json")
        if set(row) != cols:
            errs.append(f"conformance-matrix.json: {e} lacks a cell of some column")
        for col, cell in row.items():
            cls = cell.get("class")
            if cls not in CONF_CLASSES:
                errs.append(f"conformance-matrix.json: {e} {col}: class {cls!r}")
                continue
            totals.setdefault(col, {k: 0 for k in CONF_CLASSES})[cls] += 1
            extra = set(cell) - ({"class", "findings"} if cls == "diverges" else {"class"})
            if extra:
                errs.append(f"conformance-matrix.json: {e} {col}: unexpected keys {sorted(extra)}")
            for fid in cell.get("findings", []):
                if fid not in recs:
                    errs.append(f"conformance-matrix.json: {e} {col}: {fid} has no public record")
            if cls == "pending" and (e, col) not in pend:
                errs.append(f"conformance-matrix.json: {e} {col}: pending but not in findings/pending/conformance.json")
    if totals != d["totals"]:
        errs.append("conformance-matrix.json: totals do not match the cells")
    return errs


# ---------------------------------------------------------------- replay

def replay_class(row, pend):
    """The class of one replay row. The caller publishes a failing row of a real pipeline that names no finding,
    or whose expectation is not `expected`, as `pending` without detail; the kit's own reference indexer keeps
    its class, since its refusals are its documented behaviour."""
    rep = row["replay"]
    cls, qual = rep["class"], rep.get("qualifier")
    if row.get("expectation") == "pending":
        if row["entry"] not in pend:
            raise Fail(f"{row['row_id']}: pending row not in findings/pending/")
        return "pending"
    if cls in ("harness_fault", "flaky"):
        raise Fail(f"{row['row_id']}: {cls}; a published summary must not rest on it")
    if cls == "pass":
        return "pass"
    if cls in ("not_applicable", "not_reached"):
        return "not-run"
    if qual == "halt":
        return "halt"
    if qual == "refused":
        return "refused"
    if cls in ("mishandled", "dropped"):
        return cls
    raise Fail(f"{row['row_id']}: unknown class {cls}·{qual}")


def replay(full_dir, regression_dir, etl_dir, selftest_dir):
    recs = public_findings()
    index = corpus_index()
    pend = pending_replay()
    with open(os.path.join(ROOT, "pins.toml"), "rb") as f:
        pins = tomllib.load(f)
    wb = pins["pipelines"]["wallet_backend"]
    etl = pins["pipelines"]["stellar_etl"]
    roles = {wb["current"]: ("current", None)}
    for i, p in enumerate(wb["acceptance"], 1):
        roles[p["prefix"]] = ("prefix", i)
        roles[p["fixed"]] = ("fixed", i)

    reports = []  # (pipeline key, meta, report path)
    for p in sorted(glob.glob(os.path.join(full_dir, "wallet-backend-*", "report.json"))):
        reports.append(("corpus", p))
    for p in sorted(glob.glob(os.path.join(regression_dir, "*", "report.json"))):
        reports.append(("known-divergences", p))
    for p in sorted(glob.glob(os.path.join(etl_dir, "stellar-etl-*", "report.json"))):
        reports.append(("known-divergences", p))
    base = os.path.join(selftest_dir, "none", "report.json")
    if os.path.exists(base):
        reports.append(("corpus", base))
    if not reports:
        raise Fail("no replay reports found")

    pipelines, cells, inputs = {}, collections.defaultdict(lambda: collections.defaultdict(set)), set()
    cell_findings = collections.defaultdict(set)
    for scope, path in reports:
        r = load(path)
        hdr = r["header"]
        if (hdr.get("mode") or {}).get("overlay") is not False:
            raise Fail(f"{rel(path)}: not a run without the private overlay (header.mode.overlay)")
        inp = hdr["pins"]["values"]["input"]
        inputs.add(inp)
        rows = r["rows"]
        if not rows:
            raise Fail(f"{rel(path)}: no rows")
        tgt = rows[0]["target"]
        name, version = tgt["name"], tgt["version"]
        if name == "stellar/wallet-backend":
            if version not in roles:
                raise Fail(f"{rel(path)}: wallet-backend {version} is not a pinned commit")
            role, pair = roles[version]
            key = f"wallet-backend@{version[:12]}"
            meta = {"pipeline": "wallet-backend", "commit": version, "role": role, "pair": pair}
        elif name == "stellar/stellar-etl":
            if version not in (etl["commit"], etl["tag"]):
                raise Fail(f"{rel(path)}: stellar-etl {version} is not the pinned commit")
            key = f"stellar-etl@{etl['commit'][:12]}"
            meta = {"pipeline": "stellar-etl", "commit": etl["commit"], "tag": etl["tag"], "role": "current", "pair": None}
        elif name == "xdrcheck baseline indexer":
            key = f"baseline@{version}"
            meta = {"pipeline": "baseline", "version": version, "role": "reference", "pair": None}
        else:
            raise Fail(f"{rel(path)}: unknown target {name}")
        # The current commit runs both in replay-full (whole corpus) and in verify-replay (known divergences):
        # the whole-corpus scope wins.
        if key in pipelines and pipelines[key]["scope"] == "corpus":
            meta["scope"] = "corpus"
            if scope != "corpus":
                continue
        meta["scope"] = scope
        pipelines[key] = meta
        for row in rows:
            if row["target"]["version"] != version:
                raise Fail(f"{row['row_id']}: target version differs within one report")
            if row["entry"] not in index:
                raise Fail(f"{row['row_id']}: entry not in corpus/index.json")
            cls = replay_class(row, pend)
            if name != "xdrcheck baseline indexer" and cls in ("halt", "refused", "mishandled", "dropped") \
                    and (not row.get("finding") or row.get("expectation") != "expected"):
                cls = "pending"
            cells[(row["entry"], key)][inp].add(cls)
            if cls in ("halt", "refused", "mishandled", "dropped") and row.get("finding"):
                cell_findings[(row["entry"], key, inp)].add(known_finding(row["finding"], recs, row["row_id"]))
    entries = collections.defaultdict(dict)
    totals = collections.defaultdict(lambda: collections.defaultdict(lambda: collections.Counter()))
    for (e, key), per_input in cells.items():
        out = {}
        for inp, classes in per_input.items():
            cls = next(c for c in REPLAY_FOLD if c in classes)
            cell = {"class": cls}
            if cls in ("halt", "refused", "mishandled", "dropped"):
                cell["findings"] = sorted(cell_findings.get((e, key, inp), ()))
            out[inp] = cell
            totals[key][inp][cls] += 1
        entries[e][key] = out
    return {
        "schema": "xdrcheck.results.replay-summary/v1",
        "generated_by": "make results-replay",
        "pipelines": pipelines,
        "inputs": sorted(inputs),
        "classes": REPLAY_CLASSES,
        "entries": dict(entries),
        "totals": {k: {i: dict(c) for i, c in v.items()} for k, v in totals.items()},
    }


def check_replay_file(d, recs, index):
    errs = []
    if d.get("schema") != "xdrcheck.results.replay-summary/v1" or not d.get("generated_by"):
        return ["replay-summary.json: schema or generated_by missing"]
    totals = collections.defaultdict(lambda: collections.defaultdict(collections.Counter))
    for e, row in d["entries"].items():
        if e not in index:
            errs.append(f"replay-summary.json: {e} is not in corpus/index.json")
        for key, per_input in row.items():
            if key not in d["pipelines"]:
                errs.append(f"replay-summary.json: {e}: unknown pipeline {key}")
            for inp, cell in per_input.items():
                cls = cell.get("class")
                if inp not in d["inputs"] or cls not in REPLAY_CLASSES or cls == "error":
                    errs.append(f"replay-summary.json: {e} {key} {inp}: bad input or class {cls!r}")
                    continue
                totals[key][inp][cls] += 1
                allowed = {"class", "findings"} if cls in ("halt", "refused", "mishandled", "dropped") else {"class"}
                if set(cell) - allowed:
                    errs.append(f"replay-summary.json: {e} {key} {inp}: unexpected keys")
                for fid in cell.get("findings", []):
                    if fid not in recs:
                        errs.append(f"replay-summary.json: {e} {key} {inp}: {fid} has no public record")
    if {k: {i: dict(c) for i, c in v.items()} for k, v in totals.items()} != d["totals"]:
        errs.append("replay-summary.json: totals do not match the cells")
    return errs


# ---------------------------------------------------------------- findings

# The states an issue filed upstream can be in (corpus/schema/finding-record.schema.json, `upstream.state`).
UPSTREAM_STATES = ("open", "fixed", "fix-merged-unreleased", "wont-fix", "closed-other", "acknowledged-private")


def findings():
    recs = public_findings()
    index = corpus_index()
    rows = []
    totals = {"state": collections.Counter(), "severity": collections.Counter(), "component": collections.Counter()}
    for fid, d in sorted(recs.items()):
        state = d["state"]
        if state not in FINDING_STATES:
            raise Fail(f"{fid}: state {state!r} is not one the results data publishes")
        if d["severity"] not in SEVERITIES:
            raise Fail(f"{fid}: severity {d['severity']!r}")
        entries = sorted({e["id"] for e in d.get("entries", []) if e.get("id") and e["id"] != "none"})
        for e in entries:
            if e not in index:
                raise Fail(f"{fid}: entry {e} is not in corpus/index.json")
        caps = set(d.get("caps") or [])
        for e in entries:
            caps.update(index[e].get("caps") or [])
        if state == "filed":
            upstream = (d.get("upstream") or {}).get("url")
            if not upstream:
                raise Fail(f"{fid}: filed without an upstream URL")
            upstream_state = (d.get("upstream") or {}).get("state")
            if upstream_state not in UPSTREAM_STATES:
                raise Fail(f"{fid}: upstream state {upstream_state!r}")
        elif state == "duplicate-of":
            upstream, upstream_state = "known upstream", None
        else:
            upstream, upstream_state = None, None
        row = {
            "id": fid,
            "title": strip_refs(d["title"]),
            "state": state,
            "component": d["component"],
            "target": d["target"]["project"],
            "severity": d["severity"],
            "class": d["class"],
            "caps": sorted(caps),
            "entries": entries,
            "versions_affected": strip_refs(d["target"].get("versions_affected")),
            "fixed_in": strip_refs(d["target"].get("fixed_in")),
            "upstream": upstream,
            "upstream_state": upstream_state,
        }
        for k in ("title", "versions_affected", "fixed_in"):
            if isinstance(row[k], str) and FOREIGN_REF.search(row[k]):
                raise Fail(f"{fid}: {k} carries an upstream reference: {row[k]!r}")
        rows.append(row)
        totals["state"][state] += 1
        totals["severity"][d["severity"]] += 1
        totals["component"][d["component"]] += 1
    return {
        "schema": "xdrcheck.results.findings/v1",
        "generated_by": "make results-findings",
        "findings": rows,
        "totals": {k: dict(sorted(v.items())) for k, v in totals.items()},
    }


# ---------------------------------------------------------------- known upstream defects

def known_defects():
    with open(os.path.join(ROOT, "README.md")) as f:
        text = f.read()
    m = re.search(r"^## Known upstream defects\n(.*?)(?=^## )", text, re.S | re.M)
    if not m:
        raise Fail("README.md: no 'Known upstream defects' section")
    lines = [l for l in m.group(1).splitlines() if l.startswith("| ") and not l.startswith("| Defect |") and not l.startswith("|---")]
    rows, totals = [], collections.Counter()
    for i, line in enumerate(lines, 1):
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) != 3:
            raise Fail(f"README.md known-defects row {i}: want 3 cells, got {len(cells)}")
        defect, how, where = cells
        sm = re.match(r"([\w.-]+)#\d+ \((.+)\)$", defect)
        if not sm:
            raise Fail(f"README.md known-defects row {i}: cannot read {defect!r}")
        project, topic = sm.group(1), sm.group(2)
        word = re.match(r"(\w+)", how).group(1)
        coverage = {"reproduced": "reproduced", "run": "run", "checked": "checked", "agreement": "agreement",
                    "input": "input"}.get(word)
        if not coverage:
            raise Fail(f"README.md known-defects row {i}: coverage {word!r} is none of {COVERAGE}")
        ticks = re.findall(r"`([^`]+)`", where)
        targets = sorted({t for t in ticks if t.startswith("make ")})
        entries = sorted({t for t in ticks if not t.startswith(("make ", "reports/")) and ("/" in t or "*" in t)})
        links = sorted({l for l in re.findall(r"\]\(([^)]+)\)", where) if not l.startswith("http")})
        how_text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", how)
        how_text = re.sub(r"^\w+[:,]?\s*", "", how_text) or None
        for k, v in (("topic", topic), ("how", how_text or "")):
            if FOREIGN_REF.search(v):
                raise Fail(f"README.md known-defects row {i}: {k} carries an upstream reference")
        rows.append({"id": f"kd-{i:02d}", "project": project, "topic": topic, "coverage": coverage,
                     "how": how_text, "entries": entries, "make_targets": targets, "evidence": links})
        totals[coverage] += 1
    return {
        "schema": "xdrcheck.results.known-defects/v1",
        "generated_by": "make results-known-defects",
        "readme_anchor": "known-upstream-defects",
        "defects": rows,
        "totals": {c: totals[c] for c in COVERAGE},
    }


# ---------------------------------------------------------------- mainnet prevalence per entry

RAREST_LIMIT = 5  # tokens listed per entry when several share the lowest count


def read_tsv(path):
    import subprocess
    if path.endswith(".zst"):
        text = subprocess.run(["zstd", "-dc", path], check=True, capture_output=True, text=True).stdout
    else:
        with open(path) as f:
            text = f.read()
    lines = text.splitlines()
    head = lines[0].split("\t")
    return [dict(zip(head, l.split("\t"))) for l in lines[1:] if l]


def prevalence(entry_tokens, token_table):
    """entry_tokens: the TSV of `xdrcheck-corpus scan entry-tokens`; token_table: the scan's `scan token-census`
    tokens.tsv (or .tsv.zst)."""
    index = corpus_index()
    table = read_tsv(token_table)
    scan_dir = os.path.join(ROOT, "evidence", "mainnet-scan")
    classes = {(r["kind"], r["class"]): r for r in read_tsv(os.path.join(scan_dir, "token-classes.tsv"))}
    if len(table) != int(classes[("all", "all")]["distinct_tokens"]):
        raise Fail(f"{token_table}: {len(table)} tokens, but token-classes.tsv says "
                   f"{classes[('all', 'all')]['distinct_tokens']}: not this scan's token table")
    chain = dict(l.split("\t", 1) for l in open(os.path.join(scan_dir, "chain-summary.txt")).read().splitlines() if "\t" in l)
    first, last = (int(x) for x in chain["unit_range"].split("-"))
    tok = {r["token"]: (int(r["occurrences"]), int(r["first_ledger"]), int(r["last_ledger"])) for r in table}
    variants = collections.defaultdict(lambda: collections.defaultdict(set))
    other = collections.defaultdict(set)
    for r in read_tsv(entry_tokens):
        e = r["entry"]
        if e not in index:
            raise Fail(f"{entry_tokens}: {e} is not in corpus/index.json")
        if r["kind"] == "!":
            raise Fail(f"{entry_tokens}: {e} {r['variant']} could not be walked: {r['token']}")
        if r["kind"] == "-":
            other[e].add(r["variant"])
            continue
        variants[e][r["variant"]].add(r["token"])
    # Ground truth for the walk: a pubnet ledger taken from history inside the scanned range was itself scanned, so
    # every token of its variant must be in the table with that ledger inside the token's first..last range.
    checked = 0
    for e, per_var in variants.items():
        for v in index[e].get("variants", []):
            if v.get("network") != "pubnet" or v.get("source") not in ("history", "history-archive") \
                    or not first <= v.get("ledger_seq", 0) <= last:
                continue
            for var, toks in per_var.items():
                if var.split("#")[0] != f"pubnet@{v['protocol']}" or ("#" in var and var != f"pubnet@{v['protocol']}#{v['ledger_seq']}"):
                    continue
                checked += 1
                for t in toks:
                    if t not in tok or not tok[t][1] <= v["ledger_seq"] <= tok[t][2]:
                        raise Fail(f"{e} {var}: token {t!r} of a scanned mainnet ledger ({v['ledger_seq']}) is not in "
                                   "the token table at that ledger: the walk does not match the scan")
    if not checked:
        raise Fail("no scanned mainnet variant to check the walk against")
    entries = {}
    walked_tokens = set()
    for e in sorted(index):
        if e not in variants:
            entries[e] = {"walked": False}
            continue
        per = {}
        for var, toks in variants[e].items():
            walked_tokens |= toks
            low = min(tok.get(t, (0, None, None))[0] for t in toks)
            per[var] = low
        # The variant whose rarest token is the most common: the form of the entry closest to mainnet.
        best = sorted(per, key=lambda v: (-per[v], v))[0]
        toks = variants[e][best]
        low = per[best]
        rarest = sorted(t for t in toks if tok.get(t, (0,))[0] == low)
        out = {
            "walked": True,
            "variant": best,
            "rarest_occurrences": low,
            "never_seen_on_mainnet": low == 0,
            "rarest_tokens": [
                {"token": t, "occurrences": low,
                 "first_ledger": tok[t][1] if t in tok else None, "last_ledger": tok[t][2] if t in tok else None}
                for t in rarest[:RAREST_LIMIT]
            ],
            "rarest_tokens_total": len(rarest),
            "tokens": len(toks),
            "tokens_unseen_on_mainnet": sum(1 for t in toks if t not in tok),
            "variants": dict(sorted(per.items())),
        }
        if out["never_seen_on_mainnet"] and any(
                v.get("network") == "pubnet" and v.get("source") in ("history", "history-archive")
                for v in index[e].get("variants", [])):
            raise Fail(f"{e}: never seen in the scanned range but taken from a mainnet ledger (after the scan's end?); "
                       "give it its own field before publishing")
        entries[e] = out
    walked = [v for v in entries.values() if v["walked"]]
    return {
        "schema": "xdrcheck.results.entry-prevalence/v1",
        "generated_by": "make results-prevalence TOKEN_TABLE=<the scan's token table>",
        "scan": {"first_ledger": first, "last_ledger": last, "grammar": "xcc.shape/v1",
                 "distinct_tokens": len(table)},
        "entries": entries,
        "totals": {
            "entries": len(entries),
            "walked": len(walked),
            "not_walked": len(entries) - len(walked),
            "never_seen_on_mainnet": sum(1 for v in walked if v["never_seen_on_mainnet"]),
            "distinct_entry_tokens": len(walked_tokens),
            "distinct_entry_tokens_seen_on_mainnet": sum(1 for t in walked_tokens if t in tok),
            "mainnet_variants_checked_against_the_scan": checked,
        },
    }


def check_prevalence_file(d, index):
    errs = []
    if d.get("schema") != "xdrcheck.results.entry-prevalence/v1" or not d.get("generated_by"):
        return ["entry-prevalence.json: schema or generated_by missing"]
    walked = never = 0
    for e, v in d.get("entries", {}).items():
        if e not in index:
            errs.append(f"entry-prevalence.json: {e} is not in corpus/index.json")
        if not v.get("walked"):
            continue
        walked += 1
        never += v["never_seen_on_mainnet"]
        if v["never_seen_on_mainnet"] != (v["rarest_occurrences"] == 0) or not v["rarest_tokens"] \
                or v["variants"].get(v["variant"]) != v["rarest_occurrences"] \
                or any(t["occurrences"] != v["rarest_occurrences"] for t in v["rarest_tokens"]):
            errs.append(f"entry-prevalence.json: {e}: inconsistent")
    t = d.get("totals", {})
    if t.get("walked") != walked or t.get("never_seen_on_mainnet") != never or t.get("entries") != len(d["entries"]):
        errs.append("entry-prevalence.json: totals do not match the entries")
    return errs


# ---------------------------------------------------------------- acceptance

ACCEPTANCE_DOC = os.path.join(ROOT, "docs", "acceptance.md")
ACC_STATUSES = ["met", "not met", "missing", "not recorded", "proven in full CI"]
# The acceptance check IDs docs/acceptance.md defines, in table order. A check with cases names them in parentheses
# after its ID ("`replay-regression` (cases `wallet-backend-729`, ...): ..."); the acceptance table then has one row
# per case, `<id>/<case>`, or one row for the whole check.
CHECK_IDS = ["roundtrip", "golden-agreement", "replay-regression", "lint-fixtures", "lint-current", "guide-table",
             "guide-review", "sdk-regression", "findings-linked"]
CHECK_ID = re.compile(r"^`?(" + "|".join(map(re.escape, CHECK_IDS)) + r")`?(?:\s*\(cases?\s+([^)]*)\))?\s*:\s*(.*)$")
CASE_ID = re.compile(r"[a-z][a-z0-9.-]*-\d+")
MACHINE_PATH = re.compile(r"(?:^|[\s`'\"(=])/(?:home|data|tmp|root|Users|var|mnt|opt)/")
# A count of rows or cells pending finding review: the published reason says that rows are pending, not how many.
PENDING_COUNT = re.compile(r"\b\d+ (rows?|cells?|row names|rows name|warnings?|errors?)( pending finding review| awaiting finding review)")


def acceptance_definitions():
    """The acceptance checks of docs/acceptance.md's check table (header "| <area> | Check | Command |"), in table
    order: id, its cases (if any), area, check text, and the first make target its Command column names."""
    rows, area = [], None
    in_table = False
    for line in open(ACCEPTANCE_DOC, encoding="utf-8"):
        if re.match(r"^\| [^|]+ \| Check \| Command \|", line):
            in_table = True
            continue
        if in_table and not line.startswith("|"):
            break
        if not in_table or line.startswith("|---"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split(" | ")]
        if len(cells) < 3:
            raise Fail(f"docs/acceptance.md: a table row with {len(cells)} cells: {line.strip()}")
        area = cells[0] or area
        m = CHECK_ID.match(cells[1])
        if not m:
            continue
        mk = re.search(r"`make ([a-z][a-z0-9-]*)", cells[2])
        if not mk:
            raise Fail(f"docs/acceptance.md: {m.group(1)} names no make target")
        rows.append({"id": m.group(1), "cases": CASE_ID.findall(m.group(2) or ""), "area": area,
                     "check": no_issue_refs(m.group(3)), "make": mk.group(1)})
    if not rows:
        raise Fail("docs/acceptance.md: no acceptance check (" + ", ".join(CHECK_IDS) + ") in the check table")
    return rows


def no_issue_refs(text):
    """Text without upstream issue numbers: "wallet-backend#729, #731 and #716" becomes "the known wallet-backend
    defects", a leading "#729: " is dropped. The published file repeats no upstream reference."""
    text = re.sub(r"([A-Za-z][\w.-]*)#\d+(?:,? #\d+)*(?:,? and #\d+)?", r"the known \1 defects", text)
    return re.sub(r"(?:(?<=^)|(?<=; ))#\d+:\s*", "", text)


def acceptance_ids(d):
    """The acceptance table's row IDs a docs/acceptance.md check stands for: its ID, and for a check with cases also
    `<id>/<case>` for each case."""
    return {d["id"]} | {d["id"] + "/" + c for c in d["cases"]}


def documented_make_targets():
    out = set()
    for path in [os.path.join(ROOT, "Makefile")] + sorted(glob.glob(os.path.join(ROOT, "mk", "*.mk"))):
        for line in open(path, encoding="utf-8"):
            m = re.match(r"^([a-z][a-z0-9-]*):[^=].*##\s", line)
            if m:
                out.add(m.group(1))
    return out


def public_reason(text):
    """The acceptance table's 'what was checked' text as published: no count of rows pending finding review, no
    clause about runs with the private overlay or the private acceptance run (those rows are not in a public run),
    no machine path."""
    plural = {"row": "rows", "rows": "rows", "cell": "cells", "cells": "cells", "warning": "warnings",
              "warnings": "warnings", "error": "errors", "errors": "errors"}
    text = PENDING_COUNT.sub(lambda m: plural[m.group(1).split()[0]] + m.group(2), text)
    text = re.sub(r"(cells pending finding review elsewhere in the matrix), per run: (?:`[^`]*`: \d+(?:; (?=`))?)+", r"\1", text)
    text = re.sub(r"\bexcept 1 row\b", "except rows", text)
    parts = [p for p in text.split("; ") if "private" not in p]
    return no_issue_refs("; ".join(parts))


RUN_KINDS = ["github-actions", "local"]


def acceptance_run():
    """Which run made the acceptance table: in GitHub Actions the workflow run (GITHUB_RUN_ID) and its commit
    (GITHUB_SHA); elsewhere a local run of the checked-out commit, and whether tracked files differed from it."""
    import subprocess

    def git(*args):
        return subprocess.run(["git", "-C", ROOT, *args], check=True, capture_output=True, text=True).stdout.strip()

    if os.environ.get("GITHUB_RUN_ID"):
        return {"kind": "github-actions", "commit": os.environ.get("GITHUB_SHA") or git("rev-parse", "HEAD"),
                "id": os.environ["GITHUB_RUN_ID"]}
    return {"kind": "local", "commit": git("rev-parse", "HEAD"),
            "modified": bool(git("status", "--porcelain", "--untracked-files=no"))}


def acceptance(table_path):
    table = load(table_path)
    if table.get("schema") != "xdrcheck.acceptance/v1":
        raise Fail(f"{table_path}: not an acceptance table (schema xdrcheck.acceptance/v1)")
    by_id = {r["check"]: r for r in table["rows"]}
    rows, used = [], set()
    for d in acceptance_definitions():
        ids = [i for i in [d["id"]] + [d["id"] + "/" + c for c in d["cases"]] if i in by_id]  # the page's order
        if not ids:
            raise Fail(f"{table_path}: no row for {d['id']} (docs/acceptance.md)")
        for i in ids:
            t = by_id[i]
            used.add(i)
            if t["status"] not in ACC_STATUSES:
                raise Fail(f"{table_path}: {i}: unknown status {t['status']!r}")
            rows.append({"id": i, "area": d["area"], "check": d["check"], "make": "make " + d["make"],
                         "status": t["status"], "reason": public_reason(t["checked"])})
    extra = sorted(set(by_id) - used)
    if extra:
        raise Fail(f"{table_path}: rows docs/acceptance.md does not define: {', '.join(extra)}")
    totals = collections.Counter(r["status"] for r in rows)
    return {"schema": "xdrcheck.results.acceptance/v1",
            "generated_by": "make results-acceptance (after make verify-acceptance)",
            "run": acceptance_run(),
            "statuses": ACC_STATUSES, "rows": rows,
            "totals": {s: totals.get(s, 0) for s in ACC_STATUSES}}


def check_acceptance_file(d):
    """acceptance.json against the acceptance definitions (docs/acceptance.md) and what the tree itself shows."""
    errs, name = [], "evidence/results/acceptance.json"
    if d.get("schema") != "xdrcheck.results.acceptance/v1":
        return [f"{name}: schema is not xdrcheck.results.acceptance/v1"]
    try:
        defs = acceptance_definitions()
    except Fail as e:
        return [str(e)]
    targets = documented_make_targets()
    rows = d.get("rows") or []
    got = [r.get("id") for r in rows]
    if len(got) != len(set(got)):
        errs.append(f"{name}: a check is listed twice")
    for df in defs:
        mine = [r for r in rows if r.get("id") in acceptance_ids(df)]
        if not mine:
            errs.append(f"{name}: no row for {df['id']} (docs/acceptance.md)")
        for r in mine:
            if r.get("make") != "make " + df["make"] or r.get("check") != df["check"] or r.get("area") != df["area"]:
                errs.append(f"{name}: {r['id']}: area, check or make target differs from docs/acceptance.md")
    allowed = set().union(*(acceptance_ids(df) for df in defs))
    for r in rows:
        if r.get("id") not in allowed:
            errs.append(f"{name}: {r.get('id')} is not a check of docs/acceptance.md")
        if r.get("status") not in ACC_STATUSES:
            errs.append(f"{name}: {r.get('id')}: unknown status {r.get('status')!r}")
        if r.get("make", "").removeprefix("make ") not in targets:
            errs.append(f"{name}: {r.get('id')}: {r.get('make')} is not a documented make target")
        reason = r.get("reason", "")
        if MACHINE_PATH.search(reason) or PENDING_COUNT.search(reason) or "private" in reason:
            errs.append(f"{name}: {r.get('id')}: the reason carries a machine path, a pending count or a private-run clause")
    status = {r.get("id"): r.get("status") for r in rows}
    # What the tree shows without a run: an unreviewed claim keeps guide-review open; a pending entry or a record not
    # in a terminal state keeps findings-linked open.
    claims = open(os.path.join(ROOT, "guide", "claims.yaml"), encoding="utf-8").read()
    if re.search(r"reviewer_status:\s*(unreviewed|disputed)\b", claims) and status.get("guide-review") == "met":
        errs.append(f"{name}: guide-review is met while guide/claims.yaml has claims not confirmed or corrected")
    pend = sum(len(load(p).get("pending") or []) for p in
               sorted(glob.glob(os.path.join(ROOT, "findings", "pending", "*.json")) +
                      glob.glob(os.path.join(ROOT, "lint", "expected", "*", "*.pending.json"))))
    open_records = [r for r in public_findings().values() if r.get("state") not in FINDING_STATES]
    if (pend or open_records) and status.get("findings-linked") == "met":
        errs.append(f"{name}: findings-linked is met while pending entries or records not filed, duplicate-of or not-a-defect remain")
    run = d.get("run")
    if run is not None:
        kind = run.get("kind") if isinstance(run, dict) else None
        if kind not in RUN_KINDS or not re.fullmatch(r"[0-9a-f]{40}", str(run.get("commit"))):
            errs.append(f"{name}: run needs a kind ({', '.join(RUN_KINDS)}) and a full commit ID")
        elif kind == "github-actions" and not re.fullmatch(r"[0-9]+", str(run.get("id"))):
            errs.append(f"{name}: a GitHub Actions run needs its numeric run ID")
        elif kind == "local" and not isinstance(run.get("modified"), bool):
            errs.append(f"{name}: a local run says whether tracked files differed from its commit (modified)")
    want = collections.Counter(r.get("status") for r in rows)
    if d.get("totals") != {s: want.get(s, 0) for s in ACC_STATUSES} or d.get("statuses") != ACC_STATUSES:
        errs.append(f"{name}: totals or statuses do not match the rows")
    return errs


# ---------------------------------------------------------------- main

def write_or_check(name, obj, check, path=None):
    path = path or os.path.join(OUT, name)
    new = dump(obj)
    if check:
        old = open(path).read() if os.path.exists(path) else ""
        if old != new:
            print(f"{rel(path)}: differs from a fresh generation (run the make target that writes it)", file=sys.stderr)
            return 1
        print(f"{rel(path)}: current")
        return 0
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(new)
    print(f"{rel(path)}: written")
    return 0


def cheap_check():
    rc = 0
    rc |= write_or_check("findings.json", findings(), True)
    rc |= write_or_check("known-defects.json", known_defects(), True)
    recs, index = public_findings(), corpus_index()
    for name, fn in (("conformance-matrix.json", check_conformance_file), ("replay-summary.json", check_replay_file)):
        p = os.path.join(OUT, name)
        if not os.path.exists(p):
            print(f"{rel(p)}: missing", file=sys.stderr)
            rc = 1
            continue
        errs = fn(load(p), recs, index)
        for e in errs:
            print(e, file=sys.stderr)
        if errs:
            rc = 1
        else:
            print(f"{rel(p)}: consistent with corpus/index.json, findings/ and findings/pending/")
    acc = os.path.join(OUT, "acceptance.json")
    if os.path.exists(acc):
        errs = check_acceptance_file(load(acc))
        for e in errs:
            print(e, file=sys.stderr)
        rc |= 1 if errs else 0
        if not errs:
            print(f"{rel(acc)}: consistent with docs/acceptance.md, guide/claims.yaml, findings/ and the pending lists")
    if os.path.exists(PREVALENCE):
        errs = check_prevalence_file(load(PREVALENCE), index)
        for e in errs:
            print(e, file=sys.stderr)
        rc |= 1 if errs else 0
        if not errs:
            print(f"{rel(PREVALENCE)}: consistent with corpus/index.json")
    for name in ("conformance-matrix.json", "replay-summary.json", "findings.json", "known-defects.json", "acceptance.json"):
        p = os.path.join(OUT, name)
        if os.path.exists(p):
            text = open(p).read()
            allowed = {r["upstream"] for r in findings()["findings"] if r["state"] == "filed"}
            for mm in FOREIGN_REF.finditer(text):
                line = text[text.rfind("\n", 0, mm.start()) + 1: text.find("\n", mm.end())]
                if not any(u in line for u in allowed):
                    print(f"{rel(p)}: an upstream reference that is not a filed record's own issue: {line.strip()}", file=sys.stderr)
                    rc = 1
    return rc


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("conformance")
    c.add_argument("--pr", required=True)
    c.add_argument("--public", required=True)
    c.add_argument("--check", action="store_true")
    r = sub.add_parser("replay")
    r.add_argument("--replay-full", required=True)
    r.add_argument("--replay-regression", required=True)
    r.add_argument("--replay-etl-known", required=True)
    r.add_argument("--selftest", required=True)
    r.add_argument("--check", action="store_true")
    for n in ("findings", "known-defects"):
        sub.add_parser(n).add_argument("--check", action="store_true")
    pv = sub.add_parser("prevalence")
    pv.add_argument("--entry-tokens", required=True)
    pv.add_argument("--token-table", required=True)
    pv.add_argument("--check", action="store_true")
    ac = sub.add_parser("acceptance")
    ac.add_argument("--table", required=True)
    ac.add_argument("--check", action="store_true")
    sub.add_parser("check")
    a = ap.parse_args()
    try:
        if a.cmd == "conformance":
            return write_or_check("conformance-matrix.json", conformance(a.pr, a.public), a.check)
        if a.cmd == "replay":
            return write_or_check("replay-summary.json",
                                  replay(a.replay_full, a.replay_regression, a.replay_etl_known, a.selftest), a.check)
        if a.cmd == "findings":
            return write_or_check("findings.json", findings(), a.check)
        if a.cmd == "acceptance":
            obj = acceptance(a.table)
            committed = os.path.join(OUT, "acceptance.json")
            if a.check and os.path.exists(committed):
                # The committed file names the run that made it; a later run compares its rows, not its commit.
                old = load(committed)
                if "run" in old:
                    obj["run"] = old["run"]
                else:
                    obj.pop("run")
            return write_or_check("acceptance.json", obj, a.check)
        if a.cmd == "known-defects":
            return write_or_check("known-defects.json", known_defects(), a.check)
        if a.cmd == "prevalence":
            return write_or_check("entry-prevalence.json", prevalence(a.entry_tokens, a.token_table), a.check,
                                  PREVALENCE)
        return cheap_check()
    except Fail as e:
        print(f"results: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

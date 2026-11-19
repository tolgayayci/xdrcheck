#!/usr/bin/env python3
"""Build the dashboard's data files (and the landing's summary) from tracked repository files.

Every number the dashboard and the landing show comes from here; nothing on either page is typed by hand. The
script reads only files git tracks (a file that exists but is not committed is treated as absent), writes JSON with
sorted keys and no timestamps, and refuses to write anything that names another project's issue or pull request,
a machine path, or a private record.

Usage:
    build_data.py            write apps/dashboard/site/data/*.json and apps/landing/site/data/summary.json
    build_data.py --check    exit 1 when a committed data file differs from what the sources give
    build_data.py --from REV [--check]
                             read the sources from commit REV instead of the working tree (in a working tree that
                             holds someone else's uncommitted changes to a source)

Standard library only.
"""
import collections, json, os, re, subprocess, sys, tomllib

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))
OUT_DASH = "apps/dashboard/site/data"
OUT_LANDING = "apps/landing/site/data"
REGEN = "python3 apps/dashboard/scripts/build_data.py"

# Where the pages link to. The documentation site and the dashboard are deployed by hand; set these before a deploy.
LINKS = {
    "docs": "https://docs.xdrcheck.dev/",
    "docs_results": "https://docs.xdrcheck.dev/results/overview",
    "dashboard": "https://xdrcheck.dev/dashboard/",
    "landing": "https://xdrcheck.dev/",
    # The public repository's URL. Left empty on purpose: the repository's own name may only appear in the few files
    # scripts/py/check_slug.py allows, and the public repository is created at release. Pages hide the link while
    # this is None.
    "repository": None,
}

# ---------------------------------------------------------------------------------------------------------------
# sources


SRC_REV = None  # --from REV: read every source from that commit instead of the working tree


def tracked():
    if SRC_REV:
        out = subprocess.check_output(["git", "ls-tree", "-r", "-z", "--name-only", "--full-tree", SRC_REV], cwd=ROOT)
    else:
        out = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
    return {f for f in out.decode().split("\0") if f}


TRACKED = set()


def have(path):
    return path in TRACKED and (SRC_REV is not None or os.path.isfile(os.path.join(ROOT, path)))


def read_text(path):
    if not have(path):
        raise SystemExit(f"build_data: {path} is not a tracked file")
    if SRC_REV:
        return subprocess.check_output(["git", "show", f"{SRC_REV}:{path}"], cwd=ROOT).decode("utf-8")
    with open(os.path.join(ROOT, path), encoding="utf-8") as f:
        return f.read()


def read_json(path, optional=False):
    if optional and not have(path):
        return None
    return json.loads(read_text(path))


def read_toml(path):
    return tomllib.loads(read_text(path))


def read_tsv(path):
    lines = [l for l in read_text(path).split("\n") if l.strip()]
    head = lines[0].split("\t")
    return [dict(zip(head, l.split("\t"))) for l in lines[1:]]


def num(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------------------------------------------
# text hygiene: other projects' issue and PR numbers, links and machine paths never reach the pages

REF_REPO = re.compile(r"\(?\b(?:since |see |in |from )?[\w.-]+/[\w.-]+#\d+\)?")
REF_SHORT = re.compile(r"[\w.-]+#\d+")
URL = re.compile(r"https?://\S+")


def clean(text):
    if text is None:
        return None
    t = REF_REPO.sub("", str(text))
    t = REF_SHORT.sub("", t)
    t = URL.sub("", t)
    t = re.sub(r"\(\s*[;,]\s*", "(", t)
    t = re.sub(r"\s*[;,]\s*\)", ")", t)
    t = re.sub(r"\(\s*\)", "", t)
    t = re.sub(r"\s{2,}", " ", t).strip()
    t = re.sub(r"\s+([,.;)])", r"\1", t)
    return t


FORBIDDEN = [
    (re.compile(r"[\w.-]#\d+"), "issue or PR number"),
    (re.compile(r"(?<!vector )#\d{2,}"), "issue or PR number"),
    (re.compile(r"\b(?:issue|issues|PR|PRs|pull request)s? #\d+", re.I), "issue or PR number"),
    (re.compile(r"/(?:home|Users|root|data|tmp)/[A-Za-z0-9]"), "machine path"),
    (re.compile(r"\bF-[5-9]\d{3}\b"), "private record ID"),
]
GH_ITEM = re.compile(r"https://github\.com/[\w.-]+/[\w.-]+/(?:issues|pull|pulls|security|discussions)/[^\s\"]*")


def assert_public(name, payload, allowed_urls):
    text = json.dumps(payload, ensure_ascii=False)
    bad = []
    for rx, why in FORBIDDEN:
        for m in rx.finditer(text):
            bad.append(f"{why}: {m.group(0)!r}")
    for m in GH_ITEM.finditer(text):
        if m.group(0) not in allowed_urls:
            bad.append(f"link to an upstream item that is not one of this kit's filed issues: {m.group(0)}")
    if bad:
        raise SystemExit(f"build_data: {name} would publish what it must not:\n  " + "\n  ".join(sorted(set(bad))))


# ---------------------------------------------------------------------------------------------------------------
# the mainnet scan

SCAN_DIR = "evidence/mainnet-scan"


def build_scan():
    chain = {}
    for line in read_text(f"{SCAN_DIR}/chain-summary.txt").split("\n"):
        if "\t" in line:
            k, v = line.split("\t", 1)
            chain[k] = v
    first, last = (int(x) for x in chain["unit_range"].split("-"))
    groups = read_tsv(f"{SCAN_DIR}/chain-groups.tsv")
    gsum = lambda col: sum(int(g[col]) for g in groups)
    facts = read_tsv(f"{SCAN_DIR}/census-facts.tsv")
    bands = {}
    for r in facts:
        p = int(r["protocol"])
        b = bands.setdefault(p, {"protocol": p, "ledgers": 0, "transactions": 0, "first_ledger": None,
                                 "last_ledger": None, "meta_arms": []})
        b["ledgers"] += int(r["ledgers"])
        b["transactions"] += int(r["txs"])
        fl, ll = int(r["first_ledger"]), int(r["last_ledger"])
        b["first_ledger"] = fl if b["first_ledger"] is None else min(b["first_ledger"], fl)
        b["last_ledger"] = ll if b["last_ledger"] is None else max(b["last_ledger"], ll)
        arm = "v" + r["lcm_arm"]
        if arm not in b["meta_arms"]:
            b["meta_arms"].append(arm)
    bands = [bands[p] for p in sorted(bands)]
    ledgers, txs = int(chain["ledgers"]), int(chain["transactions"])
    if sum(b["ledgers"] for b in bands) != ledgers or sum(b["transactions"] for b in bands) != txs:
        raise SystemExit("build_data: census-facts.tsv does not sum to chain-summary.txt")
    summary = {(r["level"], r["kind"]): r for r in read_tsv(f"{SCAN_DIR}/census-summary.tsv")}
    g3_tx = sum(int(summary[("G3", k)]["distinct"]) for k in "AEFMOR")
    g3_l = int(summary[("G3", "L")]["distinct"])
    tok = {r["kind"] + "|" + r["class"]: r for r in read_tsv(f"{SCAN_DIR}/token-classes.tsv")}
    tokens = int(tok["all|all"]["distinct_tokens"])
    checks = [
        {"check": "Ledgers refused by a per-ledger check (decode, byte-exact re-encode, XDR walk, header hash, "
                  "result-to-envelope join)", "checked": ledgers, "unit": "ledgers", "failures": int(chain["refusals"])},
        {"check": "Header hash chain (previous-ledger hash)", "checked": int(chain["hash_links_checked"]),
         "unit": "links", "failures": int(chain["hash_mismatches"])},
        {"check": "Missing ledgers", "checked": ledgers, "unit": "ledgers", "failures": int(chain["missing_ledgers"])},
        {"check": "Gaps", "checked": ledgers, "unit": "ledgers", "failures": int(chain["gaps"])},
        {"check": "Duplicate or out-of-order ledgers", "checked": ledgers, "unit": "ledgers",
         "failures": int(chain["duplicates_or_out_of_order"])},
        {"check": "Transaction-set hash", "checked": gsum("ledgers"), "unit": "ledgers",
         "failures": gsum("tx_set_hash_fail")},
        {"check": "Result-set hash", "checked": gsum("ledgers"), "unit": "ledgers", "failures": gsum("result_hash_fail")},
        {"check": "Lake object metadata against the header", "checked": gsum("ledgers"), "unit": "ledgers",
         "failures": gsum("meta_mismatch")},
        {"check": "Object MD5 against its ETag", "checked": gsum("ledgers"), "unit": "ledgers",
         "failures": gsum("md5_etag_fail") + gsum("no_etag")},
    ]
    # The mainnet tier's token coverage (corpus/mainnet/README.md), as `xdrcheck-corpus mainnet coverage` states it.
    mc = read_json("evidence/results/mainnet-coverage.json", optional=True)
    mainnet_tier = None if not mc else {
        "tokens": mc["tokens"], "tier_tokens": mc["mainnet_tier"]["tokens_held"],
        "tier_transactions": mc["mainnet_tier"]["transactions"], "tier_ledgers": mc["mainnet_tier"]["ledgers"],
        "curated_tokens": mc["curated"]["tokens_held"], "statement": mc["statement"],
        "source": "evidence/results/mainnet-coverage.json", "tier": "corpus/mainnet/README.md"}
    if mainnet_tier:
        ids_tx = {(r["level"], r["order"]): r for r in read_tsv(f"{SCAN_DIR}/cover-summary.tsv")}[("TOK", "rare")]
        if mainnet_tier["tokens"] != int(ids_tx["ids_tx"]):
            raise SystemExit("build_data: mainnet-coverage.json's token count is not the scan's (cover-summary.tsv TOK ids_tx)")
    return {
        "mainnet_tier": mainnet_tier,
        "first_ledger": first, "last_ledger": last, "ledgers": ledgers, "transactions": txs,
        "units": int(chain["units"]), "protocol_min": bands[0]["protocol"], "protocol_max": bands[-1]["protocol"],
        "protocol_bands": bands, "checks": checks,
        "failures_total": sum(c["failures"] for c in checks),
        "shapes": {"tx_component_shapes_g3": g3_tx, "ledger_component_shapes_g3": g3_l,
                   "whole_tx_shapes_g3": int(summary[("G3", "tx")]["distinct"]), "tokens": tokens},
        "source": SCAN_DIR,
    }


# ---------------------------------------------------------------------------------------------------------------
# the corpus

# The rare shapes behind known upstream reader defects (the README's known-defects table); the corpus entries that
# hold each one are tagged with its key.
RISK_SHAPES = [
    ("issuer-order", "Asset pairs whose issuers sort differently by strkey and by XDR bytes",
     {"shapes": {"issuers-sort-differently-by-strkey-and-bytes", "issuer-byte-order-differs-from-strkey",
                 "pool-asset-order"}}),
    ("muxed-accounts", "Muxed source and recipient accounts",
     {"shapes": {"muxed-source", "muxed-transaction-source", "muxed-operation-source", "muxed-inner-source",
                 "muxed-fee-source", "muxed-destination", "muxed-destination-over-memo",
                 "sac-transfer-to-muxed-account", "muxed-clawback-from"}}),
    ("id-roundtrip", "Muxed account and offer IDs that decode to a different ID than they encode",
     {"prefix": ("cap-0027/api-muxed-account-id-encoding", "classic/api-offer-id-encoding"),
      "shapes": {"muxed-id-builder", "offer-id-builder"}}),
    ("max-length", "Vectors and values at their maximum length",
     {"shapes": {"vector-over-declared-max", "memo-text-max-length"}, "flags": {"length-exceeds-max"},
      "ids": {"classic/set-options-home-domain-32-bytes", "strkey/synthetic-gap-vectors.signed-payload-64-byte",
              "strkey/synthetic-gap-vectors.signed-payload-65-byte", "cap-0046/scval-nested-vec-99-in-event",
              "limits/scvec-nesting-99", "limits/scvec-nesting-100", "xdr-json/vector-longer-than-declared-max"}}),
    ("nested-auth", "Nested authorization entries",
     {"shapes": {"nested-auth-tree", "nested-delegates"},
      "prefix": ("cap-0046/auth-deep-tree-golden", "cap-0046/auth-wide-tree-golden")}),
    ("map-keys", "Maps whose keys collide after conversion",
     {"shapes": {"scmap-colliding-keys", "scmap-colliding-native-keys"}}),
]

FAMILY_OF_TARGET = {
    "@stellar/stellar-sdk": "js", "github.com/stellar/go-stellar-sdk": "go", "stellar-xdr (crates.io)": "rust",
    "stellar-sdk (PyPI)": "python", "network.lightsail:stellar-sdk (Maven)": "java",
    "soroban-spec (crates.io)": "soroban-spec", "@stellar/stellar-xdr-json": "xdr-json",
    "github.com/stellar/go-stellar-xdr-json": "xdr-json", "stellar/wallet-backend": "wallet-backend",
    "stellar/stellar-etl": "stellar-etl",
}
PIPELINES = ("wallet-backend", "stellar-etl")


def risk_shapes(entry, manifest):
    shapes, flags, eid = set(manifest.get("shapes") or []), set(entry["flags"]), entry["id"]
    out = []
    for key, _, rule in RISK_SHAPES:
        if (shapes & rule.get("shapes", set()) or flags & rule.get("flags", set()) or eid in rule.get("ids", set())
                or any(eid.startswith(p) for p in rule.get("prefix", ()))):
            out.append(key)
    return out


def build_corpus(findings_by_entry):
    index = read_json("corpus/index.json")
    coverage = read_json("corpus/coverage.json")
    entries = []
    for e in index["entries"]:
        m = read_json("corpus/" + e["manifest"])
        nets = sorted({v["network"] for v in e["variants"]})
        variants = []
        for v in e["variants"]:
            variants.append({"network": v["network"], "protocol": v["protocol"], "ledger_seq": v["ledger_seq"],
                             "source": v["source"], "xdr_type": v["xdr_type"],
                             "tx": (v.get("focus") or {}).get("tx_hash")})
        divs = []
        for kd in (m.get("conformance") or {}).get("known_divergences") or []:
            fam = FAMILY_OF_TARGET.get(kd["target"], "other")
            divs.append({"family": fam, "pipeline": fam in PIPELINES, "level": kd.get("level"),
                         "outcome": kd.get("outcome"), "status": kd.get("status"), "finding": kd.get("finding"),
                         "versions": clean(kd.get("versions")), "fixed_in": clean(kd.get("fixed_in"))})
        divs.sort(key=lambda d: (d["family"], d["level"] or "", d["versions"] or "", d["finding"] or ""))
        fids = sorted({d["finding"] for d in divs if d["finding"]} | set(findings_by_entry.get(e["id"], [])))
        entries.append({
            "id": e["id"], "title": clean(e["title"]), "kind": e["kind"], "caps": e["caps"], "rows": e["rows"],
            "protocol": e["protocol"].get("introduced"), "synthetic": e["synthetic"], "validity": e["validity"],
            "flags": e["flags"], "sources": e["sources"], "tier": e["tier"], "networks": nets,
            "twin": "testnet" in nets and "pubnet" in nets, "shapes": m.get("shapes") or [],
            "why": clean(m.get("why")), "variants": variants, "divergences": divs, "findings": fids,
            "risk_shapes": risk_shapes(e, m), "manifest": "corpus/" + e["manifest"],
        })
    # totals must match the committed coverage report
    by_source = collections.Counter(s for e in index["entries"] for s in e["sources"])
    twins = sum(1 for e in entries if e["twin"])
    rows = coverage["rows"]
    if len(entries) != len(index["entries"]):
        raise SystemExit("build_data: entry count mismatch")
    core_protocols = sorted({v["protocol"] for e in entries for v in e["variants"]
                             if v["source"] in ("local-core", "core-golden", "history", "history-archive")})
    return entries, rows, {
        "version": coverage["corpus_version"], "entries": len(entries), "twins": twins,
        "synthetic": sum(1 for e in entries if e["synthetic"]),
        "by_source": dict(sorted(by_source.items())),
        "real_network": sum(1 for e in index["entries"] if "history" in e["sources"] or "history-archive" in e["sources"]),
        "core_emitted": sum(1 for e in index["entries"]
                            if {"local-core", "core-golden", "history", "history-archive"} & set(e["sources"])),
        "rows": len(rows), "rows_with_entries": sum(1 for r in rows if r["entries"]),
        "cap_rows": sum(1 for r in rows if r["group"].startswith("cap-")),
        "cap_rows_with_entries": sum(1 for r in rows if r["group"].startswith("cap-") and r["entries"]),
        "core_protocols": core_protocols,
        "risk_shapes": [{"key": k, "label": label, "entries": sum(1 for e in entries if k in e["risk_shapes"])}
                        for k, label, _ in RISK_SHAPES],
    }


def build_prevalence(rows, entries, bands):
    """Per row, the joined arms its entries hold. An arm only counts toward the row's first and last ledger when it
    first occurs at or after the ledger where the row's protocol reached pubnet: an arm seen earlier was not brought
    by that protocol, even though one of the row's entries holds it."""
    def activation_band(p):
        # pubnet skipped some protocols (no protocol 14 ledger): the next protocol it ran stands in
        later = [b for b in bands if p is not None and b["protocol"] >= p]
        return min(later, key=lambda b: b["first_ledger"]) if later else None

    def activation(p):
        b = activation_band(p)
        return b["first_ledger"] if b else None
    prev = read_json("apps/docs/data/cap-prevalence.json")
    by_id = {e["id"]: e for e in entries}
    row_arms = collections.defaultdict(list)
    for a in prev["arms"]:
        arm = {"arm": a["arm"], "class": a.get("class"), "seen": bool(a.get("seen")), "entries": a["entries"],
               "occurrences": a.get("occurrences"), "ledgers": a.get("ledgers"),
               "first_ledger": a.get("first_ledger"), "last_ledger": a.get("last_ledger")}
        groups = set()
        for eid in a["entries"]:
            e = by_id.get(eid)
            if e:
                groups.update(e["rows"])
                groups.update("cap-%04d" % c for c in e["caps"])
        for g in groups:
            row_arms[g].append(arm)
    out = {}
    for r in rows:
        arms = sorted(row_arms.get(r["group"], []), key=lambda a: a["arm"])
        act = activation(r["protocol"])
        held = [a for a in arms if a["seen"]]
        seen = [a for a in held if act is not None and a["first_ledger"] >= act]
        out[r["group"]] = {
            "activation_ledger": act,
            "activation_protocol": (activation_band(r["protocol"]) or {}).get("protocol"), "arms_joined": len(arms), "arms_seen_any": len(held), "arms_seen": len(seen),
            "arms_before_activation": len(held) - len(seen),
            "first_ledger": min((a["first_ledger"] for a in seen), default=None),
            "last_ledger": max((a["last_ledger"] for a in seen), default=None),
            "rarest_occurrences": min((a["occurrences"] for a in seen), default=None),
            "arms": [{**a, "before_activation": bool(a["seen"] and (act is None or a["first_ledger"] < act))}
                     for a in arms],
        }
    return out, {"scan_first_ledger": prev["scan_first_ledger"], "scan_last_ledger": prev["scan_last_ledger"],
                 "arms": len(prev["arms"]), "arms_seen": sum(1 for a in prev["arms"] if a.get("seen"))}


# ---------------------------------------------------------------------------------------------------------------
# findings

PROJECT_SHORT = {
    "stellar/wallet-backend": "wallet-backend", "stellar/stellar-etl": "stellar-etl",
    "stellar/stellar-horizon": "Horizon", "stellar/js-stellar-sdk": "js-stellar-sdk", "stellar/js-xdr": "js-xdr",
    "stellar/go-stellar-sdk": "go-stellar-sdk", "stellar/go-xdr": "go-xdr", "stellar/rs-stellar-xdr": "rs-stellar-xdr",
    "stellar/rs-stellar-strkey": "rs-stellar-strkey", "StellarCN/py-stellar-base": "py-stellar-base",
    "stellar/stellar-cli": "stellar-cli", "stellar/rs-stellar-rpc-client": "rs-stellar-rpc-client",
    "lightsail-network/java-stellar-sdk": "java-stellar-sdk", "Beans-BV/dotnet-stellar-sdk": "dotnet-stellar-sdk",
}
SEVERITY_ORDER = ["critical", "high", "medium", "low"]


def build_findings():
    records = []
    for path in sorted(p for p in TRACKED if re.fullmatch(r"findings/F-\d{4}/finding\.json", p)):
        x = read_json(path)
        if x.get("visibility") != "public" or int(x["id"][2:]) >= 5000:
            raise SystemExit(f"build_data: {path} is not a public record")
        records.append(x)
    caps_of = {}
    index = {e["id"]: e for e in read_json("corpus/index.json")["entries"]}
    allowed_urls, out = set(), []
    for x in records:
        t = x["target"]
        entries = sorted({en["id"] for en in x.get("entries") or [] if en.get("id") and en["id"] != "none"})
        caps = sorted(set(x.get("caps") or []) | {c for eid in entries for c in index.get(eid, {}).get("caps", [])})
        rules = sorted({en["scope"] for en in x.get("entries") or [] if re.fullmatch(r"XDR\d{3}", en.get("scope") or "")})
        upstream = None
        if x["state"] == "filed":
            url = (x.get("upstream") or {}).get("url")
            if not url or not GH_ITEM.fullmatch(url):
                raise SystemExit(f"build_data: {x['id']} is filed without an upstream URL")
            upstream = {"kind": "filed", "url": url, "state": (x.get("upstream") or {}).get("state")}
            allowed_urls.add(url)
        elif x["state"] == "duplicate-of":
            upstream = {"kind": "known-upstream"}
        out.append({
            "id": x["id"], "title": clean(x["title"]), "state": x["state"], "severity": x["severity"],
            "class": x["class"], "component": x["component"], "project": PROJECT_SHORT.get(t["project"], t["project"]),
            "versions_affected": clean(t.get("versions_affected")), "fixed_in": clean(t.get("fixed_in")),
            "caps": caps, "entries": entries, "rules": rules, "defect_group": x.get("defect_group"),
            "siblings": sorted(x.get("siblings") or []), "upstream": upstream,
        })
        caps_of[x["id"]] = caps
    # awaiting review: counts only, never the rows
    awaiting = {"conformance": 0, "replay": 0, "linter": 0}
    p = read_json("findings/pending/conformance.json", optional=True)
    awaiting["conformance"] = len((p or {}).get("pending") or [])
    p = read_json("findings/pending/replay.json", optional=True)
    awaiting["replay"] = len((p or {}).get("pending") or [])
    for path in sorted(t for t in TRACKED if re.fullmatch(r"lint/expected/[^/]+/[0-9a-f]+\.pending\.json", t)):
        awaiting["linter"] += len(read_json(path).get("pending") or [])
    by = lambda k: dict(sorted(collections.Counter(f[k] for f in out).items()))
    totals = {"records": len(out), "state": by("state"), "severity": by("severity"), "component": by("component"),
              "project": by("project"), "awaiting_review": awaiting,
              "awaiting_review_total": sum(awaiting.values())}
    return out, totals, allowed_urls


def build_lint():
    text = read_text("lint/docs/README.md")
    rules = []
    for line in text.split("\n"):
        m = re.match(r"\| \[(XDR\d{3})\]\([^)]*\) \| (.*?) \| (\w+) \| (yes|opt-in) \| (.*?) \| (.*?) \|$", line)
        if m:
            guide = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", m.group(5))
            rules.append({"id": m.group(1), "reports": m.group(2), "severity": m.group(3),
                          "default": m.group(4) == "yes", "guide_section": guide,
                          "checklist": None if m.group(6) == "—" else m.group(6),
                          "family": {"0": "suppressions", "1": "unvalidated fields", "2": "depth and size caps",
                                     "3": "participants from meta", "4": "protocol and value edges"}[m.group(1)[3]]})
    if not rules:
        raise SystemExit("build_data: no rules read from lint/docs/README.md")
    return rules


# ---------------------------------------------------------------------------------------------------------------
# SDK columns, pipelines, results


def build_columns():
    sets = read_toml("drivers/sets.toml")["sets"]
    cols = {}
    for path in sorted(t for t in TRACKED if re.fullmatch(r"drivers/sets\.d/[^/]+\.toml", t)):
        for cid, c in (read_toml(path).get("columns") or {}).items():
            cols[cid] = c

    def expand(name, seen=()):
        out = []
        for m in sets.get(name, []):
            out += expand(m[1:], seen + (name,)) if m.startswith("@") else [m]
        return out
    named = {s: expand(s) for s in ("required", "acceptance", "pr", "public")}
    columns = []
    for cid in named["public"]:
        c = cols[cid]
        columns.append({"id": cid, "sdk": c["sdk"], "kind": c["kind"], "package": c.get("package"),
                        "version": c["version"], "profile": c.get("profile"), "role": c.get("role"),
                        "sets": [s for s in ("required", "acceptance", "pr", "public") if cid in named[s]]})
    return columns, {k: len(v) for k, v in named.items()}


def build_pipelines(findings):
    pins = read_toml("pins.toml")
    wb, etl = pins["pipelines"]["wallet_backend"], pins["pipelines"]["stellar_etl"]
    by_fix = {}
    for f in findings:
        if f["project"] == "wallet-backend" and f["fixed_in"]:
            by_fix.setdefault(f["fixed_in"], []).append(f)
    pairs = []
    for i, a in enumerate(wb["acceptance"], 1):
        fs = by_fix.get(a["fixed"], [])
        pairs.append({"pair": i, "prefix": a["prefix"], "fixed": a["fixed"],
                      "findings": sorted(f["id"] for f in fs), "titles": [f["title"] for f in fs],
                      "caps": sorted({c for f in fs for c in f["caps"]}),
                      "entries": sorted({e for f in fs for e in f["entries"]})})
    return {
        "wallet-backend": {"current": wb["current"], "acceptance_pairs": pairs},
        "stellar-etl": {"tag": etl["tag"], "commit": etl["commit"]},
        "Horizon": {"note": "rig only: it runs lake ledgers, not corpus entries"},
    }


def drop_pending(cells):
    """Remove every cell that waits on finding review, at any depth; return how many were removed. Only their number
    is published: not even which entry, column or pipeline they sit in."""
    n = 0
    for k in list(cells):
        v = cells[k]
        if isinstance(v, dict) and v.get("class") == "pending":
            del cells[k]
            n += 1
        elif isinstance(v, dict):
            n += drop_pending(v)
            if not v:
                del cells[k]
    return n


def compact_matrix(m):
    if not m:
        return None
    entries = json.loads(json.dumps(m.get("entries") or {}))
    pending = drop_pending(entries)
    totals = json.loads(json.dumps(m.get("totals") or {}))

    def strip(t):
        for k in list(t):
            if k == "pending":
                del t[k]
            elif isinstance(t[k], dict):
                strip(t[k])
    strip(totals)
    classes = [c for c in (m.get("classes") or []) if c != "pending"]
    return {"columns": m.get("columns"), "sets": m.get("sets"), "classes": classes, "entries": entries,
            "totals": totals, "pending_cells": pending}


def build_results():
    res = {}
    for name, path in (("conformance", "evidence/results/conformance-matrix.json"),
                       ("replay", "evidence/results/replay-summary.json"),
                       ("known_defects", "evidence/results/known-defects.json"),
                       ("acceptance", "evidence/results/acceptance.json"),
                       ("entry_prevalence", "evidence/mainnet-scan/entry-prevalence.json")):
        d = read_json(path, optional=True)
        res[name] = d
        res[name + "_source"] = path if d is not None else None
    if res["known_defects"]:
        res["known_defects"] = {"defects": [{k: (clean(v) if isinstance(v, str) else v) for k, v in s.items()
                                             if k not in ("evidence",)}
                                            for s in res["known_defects"].get("defects", [])],
                                "totals": res["known_defects"].get("totals")}
    return res


REPLAY_FAIL = ("error", "halt", "refused", "mishandled", "dropped")
REPLAY_WORST = ["error", "halt", "refused", "mishandled", "dropped", "pass", "not-run"]
ROLE_ORDER = {"reference": 0, "current": 1, "prefix": 2, "fixed": 3}


def worst(classes):
    return next((w for w in REPLAY_WORST if w in classes), None)


def build_replay(raw, pipelines, findings_by_id):
    """The replay summary for the replay view: one column per pipeline version and input that ran, the acceptance
    pairs read from their cells, and what the current pinned commit still fails. Pending cells are only counted."""
    if not raw:
        return None
    entries = json.loads(json.dumps(raw.get("entries") or {}))
    pending = drop_pending(entries)
    totals = raw.get("totals") or {}
    meta = raw.get("pipelines") or {}
    cols = []
    for k in sorted(meta, key=lambda k: (meta[k]["pipeline"] != "wallet-backend", ROLE_ORDER.get(meta[k]["role"], 9),
                                         meta[k].get("pair") or 0, k)):
        for i in sorted((totals.get(k) or {})):
            m = meta[k]
            cols.append({"key": k, "input": i, "pipeline": m["pipeline"], "role": m["role"], "pair": m.get("pair"),
                         "scope": m.get("scope"), "commit": m.get("commit"), "tag": m.get("tag"),
                         "version": m.get("version")})
    by_commit = {m.get("commit"): k for k, m in meta.items() if m.get("commit")}
    current = next((k for k, m in meta.items() if m["pipeline"] == "wallet-backend" and m["role"] == "current"), None)

    def cell_worst(eid, key):
        c = (entries.get(eid) or {}).get(key)
        return worst({x["class"] for x in c.values()}) if c else None

    def cell_findings(eid, key):
        c = (entries.get(eid) or {}).get(key) or {}
        return sorted({f for x in c.values() for f in x.get("findings") or []})
    pairs = []
    for p in pipelines["wallet-backend"]["acceptance_pairs"]:
        pre, fix = by_commit.get(p["prefix"]), by_commit.get(p["fixed"])
        ids = sorted({e for e, c in entries.items() if pre in c or fix in c}) if pre and fix else []
        rows = [{"entry": e, "prefix": cell_worst(e, pre), "fixed": cell_worst(e, fix),
                 "current": cell_worst(e, current), "findings": cell_findings(e, pre)} for e in ids]
        fids = sorted({f for r in rows for f in r["findings"]})
        for f in fids:
            if f not in findings_by_id:
                raise SystemExit(f"build_data: the replay summary names {f}, which is not a public finding record")
        pairs.append({"pair": p["pair"], "prefix": p["prefix"], "fixed": p["fixed"], "prefix_key": pre, "fixed_key": fix,
                      "rows": rows, "findings": fids,
                      "reproduced": bool(rows) and all(r["prefix"] in REPLAY_FAIL and r["fixed"] == "pass" for r in rows),
                      "current_passes": bool(rows) and all(r["current"] == "pass" for r in rows)})
    still = []
    if current:
        for e in sorted(entries):
            w = cell_worst(e, current)
            if w in REPLAY_FAIL:
                still.append({"entry": e, "class": w, "findings": cell_findings(e, current)})

    def strip(t):
        return {k: strip(v) for k, v in t.items() if k != "pending"} if isinstance(t, dict) else t
    return {"pipelines": meta, "inputs": raw.get("inputs"), "columns": cols, "classes": [c for c in raw.get("classes") or []
            if c != "pending"], "entries": entries, "totals": strip(totals), "pending_cells": pending, "pairs": pairs,
            "current_key": current, "current_failing": still}


SIBLING_ORDER = ["js", "js16", "go", "rust", "rust-nolimits", "python", "java", "dotnet", "core"]
# The SDK each sibling family is a line of: the matrix splits JavaScript by major line and Rust by decode limits, so
# its families outnumber the SDKs they belong to. A family not listed is its own SDK, named by its label.
SIBLING_SDK = {"js": "JavaScript", "js16": "JavaScript", "go": "Go", "rust": "Rust", "rust-nolimits": "Rust",
               "python": "Python", "java": "Java", "dotnet": ".NET", "core": "stellar-core"}


def sdk_phrase(rep, reached, fams):
    """'in all 6 SDK lines that run it (4 SDKs: JavaScript, Go, Rust, Python)', computed from the families."""
    names = list(dict.fromkeys(SIBLING_SDK.get(f, fams[f]["label"]) for f in rep))
    head = f"all {len(reached)}" if len(rep) == len(reached) else f"{len(rep)} of the {len(reached)}"
    if len(names) == len(rep):
        return f"in {head} SDK{'' if len(reached) == 1 else 's'} that run it ({', '.join(names)})"
    return f"in {head} SDK lines that run it ({len(names)} SDK{'' if len(names) == 1 else 's'}: {', '.join(names)})"


def build_siblings(findings_by_id):
    raw = read_json("evidence/results/sibling-matrix.json", optional=True)
    if not raw:
        return None
    fams = raw["families"]
    order = [f for f in SIBLING_ORDER if f in fams] + sorted(f for f in fams if f not in SIBLING_ORDER)
    pending = 0
    classes = []
    for c in raw["classes"]:
        cells = {}
        for f in order:
            x = dict(c["cells"].get(f) or {"state": "not-run"})
            if x.pop("pending", False):
                pending += 1
            for r in x.get("records") or []:
                if r not in findings_by_id:
                    raise SystemExit(f"build_data: the sibling matrix names {r}, which is not a public finding record")
            if "why" in x:
                x["why"] = clean(x["why"])
            cells[f] = x
        for r in c["records"]:
            if r not in findings_by_id:
                raise SystemExit(f"build_data: the sibling matrix names {r}, which is not a public finding record")
        classes.append({"id": c["id"], "title": clean(c["title"]), "title_from": c.get("title_from"),
                        "records": c["records"], "entries": c["entries"], "cells": cells})
    with_driver = [f for f in order if fams[f]["columns"]]

    def reach(c):
        return [f for f in order if c["cells"][f]["state"] in ("reproduces", "not-affected", "not-a-defect")]
    top = max(classes, key=lambda c: (sum(1 for f in order if c["cells"][f]["state"] == "reproduces"), -classes.index(c)))
    rep = [f for f in order if top["cells"][f]["state"] == "reproduces"]
    return {"families": {f: {"label": fams[f]["label"], "columns": fams[f]["columns"]} for f in order},
            "family_order": order, "families_with_driver": with_driver, "states": raw["states"],
            "classes": classes, "totals": raw["totals"], "pending_notes": pending,
            "corpus": raw.get("corpus"),
            "top": {"id": top["id"], "title": top["title"], "reproduces": rep, "reached": reach(top),
                    "labels": [fams[f]["label"] for f in rep],
                    "sdks": list(dict.fromkeys(SIBLING_SDK.get(f, fams[f]["label"]) for f in rep)),
                    "phrase": sdk_phrase(rep, reach(top), fams)}}


def entry_prevalence(raw):
    """Per entry: how often the rarest shape token of its focus transaction (or ledger) occurs in the scanned range."""
    out = {}
    for eid, x in ((raw or {}).get("entries") or {}).items():
        if not x.get("walked"):
            out[eid] = {"walked": False}
            continue
        t = (x.get("rarest_tokens") or [{}])[0]
        tok = t.get("token") or ""
        out[eid] = {"walked": True, "occurrences": x["rarest_occurrences"], "never_seen": bool(x["never_seen_on_mainnet"]),
                    "first_ledger": t.get("first_ledger"), "last_ledger": t.get("last_ledger"),
                    "token": tok if len(tok) <= 160 else tok[:157] + "…", "rarest_tokens": x.get("rarest_tokens_total"),
                    "tokens": x.get("tokens"), "tokens_unseen": x.get("tokens_unseen_on_mainnet"),
                    "variant": x.get("variant")}
    return out


def build_golden(coverage):
    """Both golden tiers (the transaction tier, which golden-agreement counts as mapped, and the operation tier), and the reverse view per operation type."""
    t = coverage["totals"]
    mirrors = read_json("corpus/mirrors.json")
    tx = sorted(m["entry"] for m in mirrors["mapped"])
    ops = sorted(m["entry"] for m in mirrors["operations"])
    if len(tx) != t["entries_local_core_with_golden_mirror"] or len(ops) != t["entries_local_core_with_golden_operations_only"]:
        raise SystemExit("build_data: corpus/mirrors.json and corpus/coverage.json disagree on the golden tiers")
    rows, on = [], False
    for line in read_text("corpus/COVERAGE.md").split("\n"):
        if line.startswith("## "):
            on = line.strip() == "## Golden operation shapes"
            continue
        m = re.match(r"\| ([A-Z_]+) \| (\d+) \| (\d+) \| (\d+) \| (\d+) \|$", line) if on else None
        if m:
            rows.append({"op": m.group(1), "shapes": int(m.group(2)), "core_emitted": int(m.group(3)),
                         "goldens_only": int(m.group(4)), "not_held": int(m.group(5))})
    sums = {k: sum(r[k] for r in rows) for k in ("shapes", "core_emitted", "goldens_only", "not_held")}
    if (sums["shapes"], sums["core_emitted"], sums["goldens_only"], sums["not_held"]) != (
            t["golden_operation_shapes"], t["golden_operation_shapes_held_by_core_emitted_entries"],
            t["golden_operation_shapes_held_only_by_imported_goldens"], t["golden_operation_shapes_not_held"]):
        raise SystemExit("build_data: the golden operation table of corpus/COVERAGE.md does not sum to coverage.json")
    tier = {e: "transaction" for e in tx} | {e: "operations" for e in ops}
    return tier, {"core_tag": mirrors.get("core_tag"), "local_core_entries": t["entries_local_core"],
                  "transaction_tier": len(tx), "operation_tier": len(ops),
                  "no_golden": t["entries_local_core"] - len(tx) - len(ops),
                  "shapes": t["golden_operation_shapes"], "shapes_core_emitted": sums["core_emitted"],
                  "shapes_goldens_only": sums["goldens_only"], "shapes_not_held": sums["not_held"], "by_operation": rows}


# Commands that replay an entry or a row, in the form of the cookbook in docs/cli.md: from the repository root after
# `make fetch && make build`, with ./bin on PATH. test_site.py checks every subcommand and flag against docs/cli.md.
CLI_PREFACE = "From the repository root after make fetch && make build, with export PATH=\"$PWD/bin:$PATH\"."


def sh_quote(s):
    return s if re.fullmatch(r"[\w@%+=:,./-]+", s) else "'" + s + "'"


def cli_templates(replay):
    """Command templates; an entry lists the keys that apply to it and the page fills in {id} (shell-quoted)."""
    t = {"entry": {"what": "show the entry: tags, variants, expected values, declared divergences, mainnet prevalence",
                   "cmd": "xdrcheck entry {id}"},
         "baseline": {"what": "replay it through the kit's reference indexer",
                      "cmd": "xdrcheck replay --adapter bin/baseline --target-version dev --entries {id}"},
         "conform-pr": {"what": "run it through every SDK column of the pr set", "cmd": "xdrcheck conform run --entries {id}"},
         "conform-public": {"what": "run it through every SDK column of the public set",
                            "cmd": "xdrcheck conform run --set public --entries {id}"}}
    for k, m in ((replay or {}).get("pipelines") or {}).items():
        if m["pipeline"] == "wallet-backend":
            role = {"current": "at its pinned current commit", "prefix": f"before fix {m.get('pair')}",
                    "fixed": f"after fix {m.get('pair')}"}[m["role"]]
            t[k] = {"what": f"replay it through wallet-backend {role} (needs Docker)",
                    "cmd": f"xdrcheck replay --adapter bin/wallet-backend-adapter --target-version {m['commit']} --input rpc --entries {{id}}"}
        elif m["pipeline"] == "stellar-etl":
            for net in ("testnet", "pubnet"):
                t[k + ":" + net] = {"what": f"replay it through stellar-etl {m.get('tag')} at its pinned commit",
                                    "cmd": f"xdrcheck replay --adapter \"bin/stellaretl --offline\" --target-version {m['commit']} --network {net} --entries {{id}}"}
    return t


def entry_cli(e, replay, conf, sets):
    out = ["entry"]
    cells = (replay or {}).get("entries", {}).get(e["id"]) or {}
    meta = (replay or {}).get("pipelines") or {}
    for k in sorted(cells, key=lambda k: (meta[k].get("pair") or 0, ROLE_ORDER.get(meta[k]["role"], 9), k)):
        p = meta[k]["pipeline"]
        if p == "baseline":
            out.append("baseline")
        elif p == "wallet-backend":
            out.append(k)
        elif p == "stellar-etl":
            out.append(k + ":" + ("testnet" if "testnet" in e["networks"] else "pubnet"))
    judged = {c for c, x in ((conf or {}).get("entries", {}).get(e["id"]) or {}).items() if x.get("class") != "not-run"}
    if judged & set(sets.get("pr") or []):
        out.append("conform-pr")
    elif judged:
        out.append("conform-public")
    return out


def row_cli(r):
    g = r["group"]
    if g.startswith("cap-"):
        n = int(g[4:])
        sel = sh_quote(g + "/*")
        return [{"what": "list the entries tagged with this CAP", "cmd": f"xdrcheck entry --cap {n}"},
                {"what": "replay them through the kit's reference indexer", "cmd":
                 f"xdrcheck replay --adapter bin/baseline --target-version dev --caps {n}"},
                {"what": "run the entries whose ID starts with this row through the pr set's SDK columns", "cmd":
                 f"xdrcheck conform run --entries {sel}"}]
    sel = sh_quote(g + "/*")
    return [{"what": "list this row's entries", "cmd": f"xdrcheck entry --list {sel}"},
            {"what": "replay them through the kit's reference indexer", "cmd":
             f"xdrcheck replay --adapter bin/baseline --target-version dev --entries {sel}"},
            {"what": "run them through the pr set's SDK columns", "cmd": f"xdrcheck conform run --entries {sel}"}]


def conformance_summary(conf, eid):
    """Per SDK of the entry's cells: [agrees, diverges, not run, the findings its divergences name]."""
    out = {}
    for col, x in ((conf or {}).get("entries", {}).get(eid) or {}).items():
        s = out.setdefault(col.split("@")[0], [0, 0, 0, []])
        s[{"agrees": 0, "diverges": 1}.get(x["class"], 2)] += 1
        s[3] = sorted(set(s[3]) | set(x.get("findings") or []))
    return out


# ---------------------------------------------------------------------------------------------------------------


def generate():
    findings, ftotals, allowed = build_findings()
    by_entry = collections.defaultdict(list)
    for f in findings:
        for e in f["entries"]:
            by_entry[e].append(f["id"])
    entries, rows, corpus_totals = build_corpus(by_entry)
    scan = build_scan()
    prevalence, prev_meta = build_prevalence(rows, entries, scan["protocol_bands"])
    lint = build_lint()
    columns, set_sizes = build_columns()
    pipelines = build_pipelines(findings)
    results = build_results()
    fmap = {f["id"]: f for f in findings}
    replay = build_replay(results["replay"], pipelines, fmap)
    siblings = build_siblings(fmap)
    conf = compact_matrix(results["conformance"])
    prev_entries = entry_prevalence(results["entry_prevalence"])
    tier, golden = build_golden(read_json("corpus/coverage.json"))
    for e in entries:
        e["prevalence"] = prev_entries.get(e["id"])
        e["golden"] = tier.get(e["id"])
        e["sdk"] = conformance_summary(conf, e["id"])
        cells = (replay or {}).get("entries", {}).get(e["id"]) or {}
        e["replay"] = {k: worst({x["class"] for x in v.values()}) for k, v in cells.items()}
        e["cli"] = entry_cli(e, replay, conf, (conf or {}).get("sets") or {})

    f_by_cap = collections.defaultdict(set)
    r_by_cap = collections.defaultdict(set)
    for f in findings:
        for c in f["caps"]:
            f_by_cap["cap-%04d" % c].add(f["id"])
            r_by_cap["cap-%04d" % c].update(f["rules"])
    for e in entries:
        for g in e["rows"]:
            f_by_cap[g].update(e["findings"])
    for g, ids in f_by_cap.items():
        for i in ids:
            r_by_cap[g].update(fmap[i]["rules"] if i in fmap else [])
    cap_rows = []
    for r in rows:
        g = r["group"]
        cap_rows.append({
            "group": g, "title": clean(r["title"]), "protocol": r["protocol"], "reader_visible": r["reader_visible"],
            "entries": r["entries"], "by_source": r["by_source"], "twins": r["twins"], "mirrors": r.get("mirrors"),
            "gap_reason": clean(r.get("gap_reason")), "prevalence": prevalence[g],
            "after_scan": r["protocol"] is not None and r["protocol"] > scan["protocol_max"],
            "findings": sorted(f_by_cap.get(g, [])), "rules": sorted(r_by_cap.get(g, [])), "cli": row_cli(r),
        })

    sdk_families = collections.OrderedDict()
    for c in columns:
        if c["kind"] == "sdk":
            sdk_families.setdefault(c["sdk"], [])
            if c["version"] not in sdk_families[c["sdk"]]:
                sdk_families[c["sdk"]].append(c["version"])
    filed_projects = sorted({f["project"] for f in findings if f["state"] == "filed"})
    summary = {
        "schema": "xdrcheck.site.summary/v1", "generated_by": REGEN,
        "scan": {k: scan[k] for k in ("first_ledger", "last_ledger", "ledgers", "transactions", "units",
                                      "protocol_min", "protocol_max", "failures_total")}
                | {"checks": len(scan["checks"]), "hash_links": scan["checks"][1]["checked"],
                   "tx_component_shapes_g3": scan["shapes"]["tx_component_shapes_g3"],
                   "tokens": scan["shapes"]["tokens"]},
        "corpus": {k: v for k, v in corpus_totals.items() if k != "core_protocols"}
                  | {"core_protocols": len(corpus_totals["core_protocols"])},
        "prevalence": prev_meta,
        "sdk": {"families": {k: v for k, v in sdk_families.items()}, "columns_public": set_sizes["public"],
                "sdk_columns_public": sum(1 for c in columns if c["kind"] == "sdk" and "public" in c["sets"]),
                "columns_pr": set_sizes["pr"], "columns_required": set_sizes["required"]},
        "pipelines": {"replayed": ["wallet-backend", "stellar-etl"], "rigs": ["wallet-backend", "stellar-etl", "Horizon"],
                      "acceptance_pairs": len(pipelines["wallet-backend"]["acceptance_pairs"])},
        "findings": {"records": ftotals["records"], "filed": ftotals["state"].get("filed", 0),
                     "known_upstream": ftotals["state"].get("duplicate-of", 0),
                     "not_a_defect": ftotals["state"].get("not-a-defect", 0),
                     "filed_projects": len(filed_projects),
                     "awaiting_review_total": ftotals["awaiting_review_total"]},
        "lint": {"rules": len(lint), "default_rules": sum(1 for r in lint if r["default"])},
        "row_labels": [r["group"] for r in rows],
        "replay_defects": [{"topic": (s.get("topic") or "").replace("`", ""), "entries": s.get("entries") or []}
                           for s in ((results["known_defects"] or {}).get("defects") or [])
                           if s.get("project") == "wallet-backend" and s.get("coverage") == "reproduced"],
        "results": {k: results[k + "_source"]
                    for k in ("conformance", "replay", "known_defects", "entry_prevalence", "acceptance")}
                   | {"siblings": "evidence/results/sibling-matrix.json" if siblings else None},
        "entry_prevalence": (results["entry_prevalence"] or {}).get("totals"),
        "golden": {k: v for k, v in golden.items() if k != "by_operation"},
        "replay": None if not replay else {
            "pairs": len(replay["pairs"]), "pairs_reproduced": sum(1 for p in replay["pairs"] if p["reproduced"]),
            "pairs_current_passes": sum(1 for p in replay["pairs"] if p["current_passes"]),
            "pair_entries": len({r["entry"] for p in replay["pairs"] for r in p["rows"]}),
            "inputs": sorted({c["input"] for c in replay["columns"] if c["pipeline"] == "wallet-backend"}),
            "current_entries": sum(1 for x in replay["entries"].values() if replay["current_key"] in x),
            "current_failing": len(replay["current_failing"])},
        "siblings": None if not siblings else {
            "classes": len(siblings["classes"]), "families": len(siblings["family_order"]),
            "families_with_driver": len(siblings["families_with_driver"]),
            "reproduces_cells": siblings["totals"].get("reproduces", 0), "top": siblings["top"]},
        "acceptance": (results["acceptance"] or {}).get("totals"),
        "links": LINKS,
    }
    files = {
        "summary.json": summary,
        "scan.json": {"schema": "xdrcheck.site.scan/v1", "generated_by": REGEN, **scan},
        "corpus.json": {"schema": "xdrcheck.site.corpus/v1", "generated_by": REGEN, "totals": corpus_totals,
                        "rows": cap_rows, "entries": entries, "golden": golden, "cli_preface": CLI_PREFACE, "cli": cli_templates(replay),
                        "entry_prevalence": {"scan": (results["entry_prevalence"] or {}).get("scan"),
                                             "totals": (results["entry_prevalence"] or {}).get("totals")},
                        "sources": {k: results[k + "_source"] for k in ("conformance", "replay", "entry_prevalence")},
                        "risk_shapes": [{"key": k, "label": l} for k, l, _ in RISK_SHAPES]},
        "findings.json": {"schema": "xdrcheck.site.findings/v1", "generated_by": REGEN, "findings": findings,
                          "totals": ftotals, "lint_rules": lint, "severity_order": SEVERITY_ORDER},
        "matrix.json": {"schema": "xdrcheck.site.matrix/v1", "generated_by": REGEN, "columns": columns,
                        "set_sizes": set_sizes, "conformance": conf, "source": results["conformance_source"]},
        "replay.json": {"schema": "xdrcheck.site.replay/v1", "generated_by": REGEN, "pipelines_pinned": pipelines,
                        "replay": replay, "source": results["replay_source"]},
        "siblings.json": {"schema": "xdrcheck.site.siblings/v1", "generated_by": REGEN, "siblings": siblings,
                          "source": "evidence/results/sibling-matrix.json" if siblings else None},
    }
    for name, payload in files.items():
        assert_public(name, payload, allowed)
    rendered = {f"{OUT_DASH}/{n}": json.dumps(p, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n"
                for n, p in files.items()}
    rendered[f"{OUT_LANDING}/summary.json"] = rendered[f"{OUT_DASH}/summary.json"]
    return rendered


def main(argv):
    global TRACKED, SRC_REV
    if len(argv) >= 2 and argv[0] == "--from":
        SRC_REV, argv = argv[1], argv[2:]
    TRACKED = tracked()
    rendered = generate()
    if argv == ["--check"]:
        stale = []
        for path, text in sorted(rendered.items()):
            p = os.path.join(ROOT, path)
            cur = open(p, encoding="utf-8").read() if os.path.isfile(p) else None
            if cur != text:
                stale.append(path)
        if stale:
            print("build_data: stale or missing: " + ", ".join(stale) + f"\n  regenerate with: {REGEN}",
                  file=sys.stderr)
            return 1
        print(f"build_data: {len(rendered)} data files current")
        return 0
    if argv:
        print(__doc__, file=sys.stderr)
        return 2
    for path, text in rendered.items():
        p = os.path.join(ROOT, path)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(text)
    print(f"build_data: wrote {len(rendered)} files")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

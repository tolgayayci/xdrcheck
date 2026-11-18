"""guide/VERIFICATION.md: the authors' verification report for the indexer-hardening guide.

Built by build.py from verification.template.md (the prose) and the repository (every number): guide/claims.yaml,
corpus/fields.yaml, the guide page, the checklist, corpus/index.json and the manifests, corpus/mirrors.json,
pins.toml, evidence/mainnet-scan/chain-summary.txt and code-refs.tsv.

code-refs.tsv records, for every code line a claim cites, whether that file and those lines exist at the pinned
commit. It is written by `build.py --resolve-refs` from clones of the three upstream repositories (the only step that
needs them); the normal build and `--check` read it and fail when a claim cites a reference the file does not hold,
so the file cannot fall behind claims.yaml.

Derived evidence classes (claims.yaml stores only `verification: executed | code_reference`):
- corpus entry: executed, and the claim cites a corpus entry (a `corpus` source or `corpus_entries`);
- probe: executed, no corpus entry, at least one `probe` source;
- executed, source not recorded: executed, but the record lists neither a corpus entry nor a probe;
- code reference: `verification: code_reference`, whatever its sources."""
import json, os, re, subprocess, string, tomllib

CLASSES = [("corpus", "Corpus entry"), ("probe", "Probe"), ("norecord", "Executed, source not recorded"),
           ("code", "Code reference")]

# Families of `probe` sources. A probe source that fits none fails the build, so a new kind of probe gets a
# description here before it is counted. A source can fit more than one family.
PROBE_FAMILIES = [
    ("local-core", re.compile(r"local-core (?:probe|scenario run)"),
     "a run of the pinned stellar-core v30.0.0 release on a local network",
     "[evidence/local-core](../evidence/local-core/README.md), the corpus scenarios"),
    ("captured", re.compile(r"^history, (?:pubnet|testnet)|captured (?:pubnet|testnet) ledger|captured lake object"),
     "a ledger (or its object metadata) captured from the public ledger data set",
     "the corpus entry's `history` source; `xdrcheck-corpus refetch`"),
    ("sdk-matrix", re.compile(r"SDK decoding matrix"),
     "the cross-SDK decoding matrix: hand-built vectors run through each SDK release",
     "[evidence/sdk-matrix](../evidence/sdk-matrix/README.md)"),
    ("print-xdr", re.compile(r"print-xdr"),
     "stellar-core v30.0.0's offline decoder (`print-xdr`) on hand-built inputs",
     "[evidence/core-print-xdr](../evidence/core-print-xdr/README.md)"),
    ("scan", re.compile(r"pubnet scan of ledgers"),
     "the scan of every pubnet ledger",
     "[evidence/mainnet-scan](../evidence/mainnet-scan/README.md)"),
    ("network-config", re.compile(r"network configuration read"),
     "a read of the live network configuration at a stated ledger",
     "the ledger number in the claim"),
    ("replay", re.compile(r"^replay of "),
     "a replay of an indexer over corpus ledgers",
     "[evidence/wallet-backend-replay](../evidence/wallet-backend-replay/README.md)"),
    ("design", re.compile(r"design (?:recommendation|analysis)|test design"),
     "design reasoning: not a measurement",
     "the claim's own text"),
    ("docs-page", re.compile(r"^existing developers\.stellar\.org"),
     "an existing developers.stellar.org page: a citation, not a measurement",
     "stellar-docs at the pinned commit"),
]

# No reference to an upstream issue, pull request or advisory (claim sources carry some; this report leaves them
# out). Local paths and internal names are caught for every tracked file by scripts/py/check_public.py.
LEAK = [re.compile(r"[\w.-]#\d+\b"), re.compile(r"/(?:issues|pull|discussions)/\d"), re.compile(r"advisories/GHSA")]

REPOS = {None: "core", "xdr": "xdr", "env": "env"}
REPO_NAMES = {"core": "stellar-core", "xdr": "stellar-xdr", "env": "rs-soroban-env"}
TSV_HEAD = "repo\tcommit\tpath\tlines\tfile_lines\tstatus\n"


def evidence_class(c):
    if c["verification"] == "code_reference":
        return "code"
    kinds = {s["kind"] for s in c["source"]}
    if "corpus" in kinds or c.get("corpus_entries"):
        return "corpus"
    return "probe" if "probe" in kinds else "norecord"


def probe_families(ref):
    return [name for name, rx, _, _ in PROBE_FAMILIES if rx.search(ref)]


def cited_entries(c):
    out = list(c.get("corpus_entries") or [])
    out += [s["ref"] for s in c["source"] if s["kind"] == "corpus" and s["ref"] not in out]
    return out


# ------------------------------------------------------------------ code references at the pinned commits


def code_refs(claims, code_re):
    """Every (repo, path, range) a claim's code source cites, in first-seen order."""
    seen = []
    for c in claims:
        for s in c["source"]:
            if s["kind"] != "code":
                continue
            for seg in s["ref"].split(";"):
                m = code_re.match(seg.strip())
                if not m:
                    raise ValueError("%s: code reference %r does not parse" % (c["claim_id"], seg))
                prefix, path, ranges = m.groups()
                for r in ranges.split(","):
                    key = (REPOS[prefix], path, r.strip())
                    if key not in seen:
                        seen.append(key)
    return seen


def commits(fields):
    p = fields["pins"]
    return {"core": p["stellar_core"]["commit"], "xdr": p["stellar_xdr"]["commit"], "env": p["soroban_env_host"]["commit"]}


def resolve_refs(claims, fields, code_re, srcs):
    """code-refs.tsv from clones: srcs maps core/xdr/env to a git clone holding the pinned commit."""
    pins = commits(fields)
    cache, rows = {}, []
    for repo, path, rng in sorted(code_refs(claims, code_re)):
        if (repo, path) not in cache:
            r = subprocess.run(["git", "-C", srcs[repo], "show", "%s:%s" % (pins[repo], path)], capture_output=True)
            cache[(repo, path)] = r.stdout.decode("utf-8", "replace").count("\n") if r.returncode == 0 else None
        n = cache[(repo, path)]
        a, _, b = rng.partition("-")
        lo, hi = int(a), int(b or a)
        status = "no-file" if n is None else ("ok" if 1 <= lo <= hi <= n else "out-of-range")
        rows.append("%s\t%s\t%s\t%s\t%s\t%s\n" % (repo, pins[repo], path, rng, "" if n is None else n, status))
    return TSV_HEAD + "".join(rows)


def read_refs_tsv(path):
    rows = {}
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        lines = f.read().split("\n")
    for line in lines[1:]:
        if line:
            repo, commit, p, rng, n, status = line.split("\t")
            rows[(repo, p, rng)] = (commit, n, status)
    return rows


# ------------------------------------------------------------------ helpers


def md_cell(text):
    return " ".join(str(text).split()).replace("|", "\\|")


def page_sections(page):
    """anchor -> (level, title, top-level anchor), in page order."""
    out, top = {}, ""
    for line in page.split("\n"):
        m = re.match(r"^(#{2,6}) (.*?)\s*\{#([^}]+)\}\s*$", line)
        if m:
            lv, title, anchor = len(m.group(1)), m.group(2), m.group(3)
            if lv == 2:
                top = anchor
            out[anchor] = (lv, title, top)
    return out


def top_of(anchor, sections):
    a = (anchor or "").lstrip("#")
    if not a:
        return ""
    if a.startswith("vf-"):
        return "validated-fields"
    return sections[a][2]


def counts_row(label, cs):
    n = lambda k: sum(1 for c in cs if evidence_class(c) == k)
    return "| %s | %d | %d | %d | %s | %s |\n" % (
        label, len(cs), sum(c["kind"] == "fact" for c in cs), sum(c["kind"] == "recommendation" for c in cs),
        " | ".join(str(n(k)) for k, _ in CLASSES), sum(c["reviewer_status"] == "unreviewed" for c in cs))


def counts_head(first):
    return ("| %s | Claims | Facts | Recommendations | %s | Unreviewed |\n" % (first, " | ".join(l for _, l in CLASSES)) +
            "|" + " --- |" * (5 + len(CLASSES)) + "\n")


def code_links(c, pins, limit=None):
    out = []
    for s in c["source"]:
        if s["kind"] == "code":
            for u in pins.links(s["ref"]):
                out.append("[%s](%s)" % (u.rsplit("/", 1)[-1], u))
    if limit and len(out) > limit:
        out = out[:limit] + ["%d more in `claims.csv`" % (len(out) - limit)]
    return out


def evidence_text(c, pins):
    parts = []
    ents = cited_entries(c)
    if ents:
        parts.append("corpus: " + ", ".join("`%s`" % e for e in ents))
    fams = []
    for s in c["source"]:
        if s["kind"] == "probe":
            for f in probe_families(s["ref"]):
                if f not in fams:
                    fams.append(f)
    if fams:
        parts.append("probe: " + ", ".join(fams))
    links = code_links(c, pins, limit=3)
    if links:
        parts.append("code: " + ", ".join(links))
    other = sorted({s["kind"].upper() for s in c["source"] if s["kind"] in ("cap", "sep")})
    if other:
        parts.append(" and ".join(other) + " text")
    return "; ".join(parts) or "none recorded"


# ------------------------------------------------------------------ the report


def build_report(ctx):
    """ctx: claims, fields, page, checklist, pins (build.Pins), index_ids, ids_exist (callable), refs (tsv rows or
    None), verdicts, others (high-risk lists), unverified (code_only, published, withheld), questions (titles),
    root, template text. Returns (text, errors)."""
    claims, fields, page, pins = ctx["claims"], ctx["fields"], ctx["page"], ctx["pins"]
    root, errors = ctx["root"], []
    sections = page_sections(page)
    toml = tomllib.load(open(os.path.join(root, "pins.toml"), "rb"))
    v = {}

    # --- totals
    cls = {c["claim_id"]: evidence_class(c) for c in claims}
    n_cls = {k: sum(1 for x in cls.values() if x == k) for k, _ in CLASSES}
    v.update(claims=len(claims), facts=sum(c["kind"] == "fact" for c in claims),
             recommendations=sum(c["kind"] == "recommendation" for c in claims),
             executed=sum(c["verification"] == "executed" for c in claims),
             code_reference=sum(c["verification"] == "code_reference" for c in claims),
             n_corpus=n_cls["corpus"], n_probe=n_cls["probe"], n_norecord=n_cls["norecord"], n_code=n_cls["code"],
             unreviewed=sum(c["reviewer_status"] == "unreviewed" for c in claims),
             reviewed=sum(c["reviewer_status"] in ("confirmed", "corrected") for c in claims),
             disputed=sum(c["reviewer_status"] == "disputed" for c in claims),
             author_notes=sum(1 for c in claims if c.get("reviewer_note")),
             author_note_ids=", ".join(c["claim_id"] for c in claims if c.get("reviewer_note")))
    if sum(n_cls.values()) != len(claims):
        errors.append("VERIFICATION.md: the evidence classes do not add up to the claim count")

    # --- source kinds
    sk = {}
    for c in claims:
        for s in c["source"]:
            sk[s["kind"]] = sk.get(s["kind"], 0) + 1
    v.update({"src_" + k: sk.get(k, 0) for k in ("code", "corpus", "probe", "cap", "sep", "issue")})
    v["src_total"] = sum(sk.values())

    # --- pins
    p = fields["pins"]
    v.update(core_version=toml["stellar_core"]["version"], core_commit=toml["stellar_core"]["commit"],
             core_binary=toml["stellar_core"]["binary_sha256"], core_image=toml["stellar_core"]["image"].split("@")[0],
             xdr_tag=toml["stellar_xdr_definitions"]["tag"], xdr_commit=toml["stellar_xdr_definitions"]["commit"],
             env_commit=p["soroban_env_host"]["commit"], env_crate=toml["rust"]["soroban_env_host"],
             rs_xdr=toml["rust"]["stellar_xdr"], go_sdk=toml["go"]["go_stellar_sdk"], js_sdk=toml["js"]["stellar_sdk"],
             py_sdk=toml["python"]["stellar_sdk"], wb_commit=toml["pipelines"]["wallet_backend"]["current"],
             etl_tag=toml["pipelines"]["stellar_etl"]["tag"], etl_commit=toml["pipelines"]["stellar_etl"]["commit"],
             docs_commit=toml["docs"]["commit"], protocol=toml["protocol"]["max_supported"],
             js_cols=", ".join(toml["conformance"]["columns"]["js"]), go_cols=", ".join(toml["conformance"]["columns"]["go"]),
             rust_cols=", ".join(toml["conformance"]["columns"]["rust"]),
             py_cols=", ".join(toml["conformance"]["columns"]["python"]))
    if p["stellar_core"]["commit"] != v["core_commit"] or p["stellar_xdr"]["commit"] != v["xdr_commit"]:
        errors.append("VERIFICATION.md: corpus/fields.yaml pins differ from pins.toml")
    ats = {}
    for c in claims:
        for s in c["source"]:
            if s["kind"] == "code":
                ats[s["at"]] = ats.get(s["at"], 0) + 1
    v["code_at_rows"] = "".join("| %s | %d |\n" % (md_cell(a), n) for a, n in sorted(ats.items(), key=lambda kv: -kv[1]))

    # --- code references resolved
    refs = ctx["refs"]
    from_claims = code_refs(claims, ctx["code_re"])
    v["ref_unique"] = len(from_claims)
    v["ref_files"] = len({(r, pth) for r, pth, _ in from_claims})
    if refs is None:
        errors.append("guide/review/code-refs.tsv is missing; run build.py --resolve-refs with the upstream clones")
        refs = {}
    stale = [k for k in from_claims if k not in refs]
    if stale:
        errors.append("guide/review/code-refs.tsv does not hold %d code reference(s) claims.yaml cites (first: %s); "
                      "run build.py --resolve-refs" % (len(stale), ":".join(stale[0])))
    pins_c = commits(fields)
    wrong = [k for k in from_claims if k in refs and refs[k][0] != pins_c[k[0]]]
    if wrong:
        errors.append("guide/review/code-refs.tsv was resolved at another commit for %s; run build.py --resolve-refs"
                      % ":".join(wrong[0]))
    bad_refs = [k for k in from_claims if k in refs and refs[k][2] != "ok"]
    for k in bad_refs:
        errors.append("code reference %s %s:%s does not exist at the pinned commit (%s)" % (
            REPO_NAMES[k[0]], k[1], k[2], refs[k][2]))
    v["ref_ok"] = sum(1 for k in from_claims if k in refs and refs[k][2] == "ok")
    v["ref_by_repo"] = "".join("| %s | `%s` | %d | %d |\n" % (
        REPO_NAMES[r], pins_c[r][:12], sum(1 for k in from_claims if k[0] == r),
        len({pth for rr, pth, _ in from_claims if rr == r})) for r in ("core", "env", "xdr"))
    v["fields_code_refs"] = sum(len(r.get("core_checks", [])) for r in fields["fields"])

    # --- corpus provenance of cited entries
    index = ctx["index"]
    by_id = {e["id"]: e for e in index}
    cited = []
    for c in claims:
        for e in cited_entries(c):
            if e not in cited:
                cited.append(e)
    def members(eid):
        if eid in by_id:
            return [by_id[eid]]
        base = eid.split(".", 1)[0]
        if base in by_id:
            return [by_id[base]]
        return [e for i, e in by_id.items() if i.startswith(eid + ".")]
    ents = {}
    for eid in cited:
        for e in members(eid):
            ents[e["id"]] = e
    if any(not members(e) for e in cited):
        errors.append("VERIFICATION.md: a cited corpus entry is not in corpus/index.json")
    src_n, kind_n = {}, {}
    for e in ents.values():
        kind_n[e["kind"]] = kind_n.get(e["kind"], 0) + 1
        for var in e.get("variants", []):
            src_n[var["source"]] = src_n.get(var["source"], 0) + 1
    v["cited_ids"] = len(cited)
    v["cited_entries"] = len(ents)
    v["cited_kinds"] = ", ".join("%d %s" % (n, k) for k, n in sorted(kind_n.items(), key=lambda kv: -kv[1]))
    v["cited_variants"] = sum(src_n.values())
    v["variant_sources"] = ", ".join("%d %s" % (n, k) for k, n in sorted(src_n.items(), key=lambda kv: -kv[1]))
    repro, regen = {}, {}
    for e in ents.values():
        try:
            m = json.load(open(os.path.join(root, "corpus", e["manifest"]), encoding="utf-8"))
        except (OSError, ValueError, KeyError):
            errors.append("VERIFICATION.md: no manifest for %s" % e["id"])
            continue
        for var in m.get("variants", []):
            s = var.get("source") or {}
            if s.get("kind") == "local-core":
                repro[s.get("reproducibility")] = repro.get(s.get("reproducibility"), 0) + 1
            if s.get("kind") == "history":
                regen[bool(s.get("regenerated"))] = regen.get(bool(s.get("regenerated")), 0) + 1
    v["lc_repro"] = ", ".join("%d %s" % (n, k) for k, n in sorted(repro.items(), key=lambda kv: str(kv[0])))
    v["hist_regen_true"], v["hist_regen_false"] = regen.get(True, 0), regen.get(False, 0)
    mir = json.load(open(os.path.join(root, "corpus", "mirrors.json"), encoding="utf-8"))
    mapped = {m["entry"] for m in mir["mapped"]}
    opmapped = {m["entry"] for m in mir["operations"]}
    lc_cited = [i for i, e in ents.items() if "local-core" in e.get("sources", [])]
    v.update(lc_cited=len(lc_cited), lc_mapped=sum(1 for i in lc_cited if i in mapped),
             lc_opmapped=sum(1 for i in lc_cited if i in opmapped),
             mirror_lc=mir["counts"]["local_core_entries"], mirror_mapped=mir["counts"]["mapped"],
             mirror_ops=mir["counts"]["unmapped_every_operation_mapped"])
    chain = {}
    for line in open(os.path.join(root, "evidence", "mainnet-scan", "chain-summary.txt"), encoding="utf-8"):
        k, _, val = line.rstrip("\n").partition("\t")
        chain[k] = val
    first, _, last = chain["unit_range"].partition("-")
    v.update(scan_first="{:,}".format(int(first)), scan_last="{:,}".format(int(last)), scan_ledgers="{:,}".format(int(chain["ledgers"])),
             scan_links="{:,}".format(int(chain["hash_links_checked"])), scan_mismatch=chain["hash_mismatches"],
             scan_refusals=chain["refusals"])

    # --- probe families
    fam_n, fam_claims = {}, {}
    for c in claims:
        for s in c["source"]:
            if s["kind"] != "probe":
                continue
            fs = probe_families(s["ref"])
            if not fs:
                errors.append("%s: probe source %r fits no family of guide/review/verification.py" % (c["claim_id"], s["ref"]))
            for f in fs:
                fam_n[f] = fam_n.get(f, 0) + 1
                fam_claims.setdefault(f, set()).add(c["claim_id"])
    v["probe_rows"] = "".join("| %s | %s | %d | %d | %s |\n" % (
        name, desc, fam_n.get(name, 0), len(fam_claims.get(name, ())), where)
        for name, _, desc, where in PROBE_FAMILIES)
    v["scan_claims"] = len(fam_claims.get("scan", ()))
    v["design_claims"] = ", ".join(sorted(fam_claims.get("design", set()) | fam_claims.get("docs-page", set())))

    # --- anomalies
    v["norecord_ids"] = ", ".join(c["claim_id"] for c in claims if cls[c["claim_id"]] == "norecord") or "none"
    nocode = [c for c in claims if cls[c["claim_id"]] == "code" and not any(s["kind"] == "code" for s in c["source"])]
    v["nocode_n"] = len(nocode)
    v["nocode_ids"] = ", ".join("%s (%s)" % (c["claim_id"], "+".join(sorted({s["kind"] for s in c["source"]})))
                                for c in nocode) or "none"

    # --- per section
    groups = {}
    for c in claims:
        groups.setdefault(top_of(c["guide_anchor"], sections), []).append(c)
    outline = [("", "Opening note (before the first section)"),
               ("validated-fields", "Validated versus unvalidated fields"), ("caps", "Caps"),
               ("participants-from-meta", "Participants from meta"),
               ("muxed-and-signed-payload", "Muxed and signed-payload handling"), ("checklist", "Checklist")]
    known = {a for a, _ in outline}
    for g in groups:
        if g not in known:
            errors.append("VERIFICATION.md: claims under the section #%s, which the report's outline lacks" % g)
    v["section_totals"] = counts_head("Guide section") + "".join(
        counts_row("%s%s" % (t, " (`#%s`)" % a if a else ""), groups.get(a, [])) for a, t in outline) + \
        counts_row("**All claims**", claims)
    for a, _ in outline[1:5]:
        sub = {}
        for c in groups.get(a, []):
            an = c["guide_anchor"].lstrip("#")
            key = "vf" if an.startswith("vf-") else an
            sub.setdefault(key, []).append(c)
        order = [x for x in sections if sections[x][2] == a and x in sub]
        rows = []
        if "vf" in sub:
            rows.append(counts_row("Field-table lines (`#vf-nn`)", sub["vf"]))
        for x in order:
            rows.append(counts_row("%s (`#%s`)" % (md_cell(sections[x][1]), x), sub[x]))
        key = a.replace("-", "_")
        v["sec_" + key] = counts_head("Subsection") + "".join(rows)
        cs = groups.get(a, [])
        es = []
        for c in cs:
            es += [e for e in cited_entries(c) if e not in es]
        fams = {}
        for c in cs:
            for s in c["source"]:
                if s["kind"] == "probe":
                    for f in probe_families(s["ref"]):
                        fams.setdefault(f, set()).add(c["claim_id"])
        refs_here = code_refs(cs, ctx["code_re"])
        v["ev_" + key] = "".join([
            "- Corpus entries cited (%d): %s.\n" % (len(es), ", ".join("`%s`" % e for e in sorted(es)) or "none"),
            "- Probes, by family (claims citing each): %s.\n" % (
                ", ".join("%s %d" % (f, len(fams[f])) for f, *_ in PROBE_FAMILIES if f in fams) or "none"),
            "- Code: %d distinct line ranges in %d files (stellar-core %d, rs-soroban-env %d, stellar-xdr %d).\n" % (
                len(refs_here), len({(r, pth) for r, pth, _ in refs_here}),
                *[sum(1 for k in refs_here if k[0] == r) for r in ("core", "env", "xdr")]),
        ])

    # --- field table
    code_only, published, withheld = ctx["unverified"]
    st = {}
    for r in fields["fields"]:
        st[r["id"]] = r["status"]
        for pp in r.get("parts", []):
            st[pp["id"]] = pp["status"]
    v.update(table_lines=len(published), table_code_only=code_only, table_withheld=withheld,
             table_demonstrated=len(published) - code_only, table_rows=len(fields["fields"]),
             table_validated=sum(1 for i in published if st.get(i) == "validated"),
             table_passed=sum(1 for i in published if st.get(i) == "passed_through"),
             table_partial=sum(1 for i in published if st.get(i) == "partially_validated"),
             vf_claims=len([c for c in claims if c["guide_anchor"].startswith("#vf-")]))

    # --- high risk
    verdicts, others = ctx["verdicts"], ctx["others"]
    hr = verdicts + others
    v.update(hr_total=len(hr), hr_verdicts=len(verdicts), hr_others=len(others),
             hr_code=sum(1 for c in hr if cls[c["claim_id"]] == "code"),
             hr_corpus=sum(1 for c in hr if cls[c["claim_id"]] == "corpus"),
             hr_probe=sum(1 for c in hr if cls[c["claim_id"]] == "probe"),
             hr_norecord=sum(1 for c in hr if cls[c["claim_id"]] == "norecord"),
             hr_verdicts_code=sum(1 for c in verdicts if cls[c["claim_id"]] == "code"),
             hr_others_code=sum(1 for c in others if cls[c["claim_id"]] == "code"))
    label = dict(CLASSES)
    def hr_rows(cs):
        return "| Claim | Field-table lines | Evidence class | What backs it |\n| --- | --- | --- | --- |\n" + "".join(
            "| %s | %s | %s | %s |\n" % (c["claim_id"], ", ".join(c.get("fields") or []) or "—", label[cls[c["claim_id"]]],
                                         evidence_text(c, pins)) for c in cs)
    v["hr_verdict_table"] = hr_rows(verdicts)
    v["hr_other_table"] = hr_rows(others)

    # --- checklist
    items = re.findall(r"^\| \[HC-(\d)(\d\d)\]\(#hc-\d+\) \| (.*?) \| (linter(?: \(opt-in\))?|manual) \| (.*?) \|",
                       ctx["checklist"], re.M)
    fam = {"1": "Trusting fields stellar-core does not validate", "2": "No depth or size cap on recursive structures",
           "3": "Participants from the envelope instead of the meta", "4": "Assumptions about the ledger's form",
           "5": "Storage, versions and protocol boundaries"}
    rows = []
    for f, name in fam.items():
        its = [x for x in items if x[0] == f]
        rules = sorted({x[4] for x in its if x[3].startswith("linter")})
        rows.append("| %s | %d | %d | %s | %d |\n" % (name, len(its), sum(1 for x in its if x[3].startswith("linter")),
                                                      ", ".join(rules) or "—", sum(1 for x in its if x[3] == "manual")))
    if sum(1 for x in items if x[0] in fam) != len(items) or not items:
        errors.append("VERIFICATION.md: a checklist item outside the five families, or no items")
    v.update(checklist_items=len(items), checklist_linter=sum(1 for x in items if x[3].startswith("linter")),
             checklist_manual=sum(1 for x in items if x[3] == "manual"),
             checklist_rules=len({x[4] for x in items if x[3].startswith("linter")}),
             checklist_table="| Family | Items | Checked by xdrlint | Rules | Checked by hand |\n| --- | --- | --- | --- | --- |\n"
             + "".join(rows),
             checklist_entries=len({e for e in re.findall(r"`([a-z0-9-]+/[a-z0-9.*-]+)`", ctx["checklist"])}))

    # --- open items
    v["questions_n"] = len(ctx["questions"])
    held = [w.split(" ", 1)[0] for w in ctx["withheld_lines"]]
    v["held_lines"] = ", ".join(held)

    try:
        text = string.Template(ctx["template"]).substitute(v)
    except (KeyError, ValueError) as e:
        errors.append("verification.template.md: unknown or malformed placeholder %s" % e)
        return "", errors
    text = re.sub(r"\A<!--.*?-->\n\n", "", text, flags=re.S)

    # --- checks on the output
    for line_no, line in enumerate(text.split("\n"), 1):
        for rx in LEAK:
            m = rx.search(line)
            if m:
                errors.append("VERIFICATION.md:%d: %r: no references to issues or pull requests" % (
                    line_no, m.group(0)))
    for cid in sorted(set(re.findall(r"\bC-\d{3,4}\b", text))):
        if cid not in cls:
            errors.append("VERIFICATION.md names %s, which is not a claim" % cid)
    rowids = set(st) | {r["id"] for r in fields["fields"]}
    for vf in sorted(set(re.findall(r"\bVF-\d{2}[a-z]?\b", text))):
        if vf not in rowids:
            errors.append("VERIFICATION.md names %s, which is not a field-table row or part" % vf)
    for held_id in held:
        if text.count(held_id) < 2:
            errors.append("VERIFICATION.md: the held-back line %s is not discussed in the known limits" % held_id)
    for cid in re.findall(r"claim: (C-\d+)", "\n".join(_section(page, "not-yet-established"))):
        if cid not in ctx["template"]:
            errors.append("verification.template.md: the open item %s of #not-yet-established is not discussed" % cid)
    for m in re.finditer(r"\]\(([^)#\s]+)(?:#[^)]*)?\)", text):
        target = m.group(1)
        if re.match(r"^[a-z]+://", target):
            continue
        if not os.path.exists(os.path.normpath(os.path.join(root, "guide", target))):
            errors.append("VERIFICATION.md: the link %r does not resolve" % target)
    for tok in sorted(set(re.findall(r"`([a-z0-9]+(?:-[a-z0-9]+)*/[a-z0-9]+(?:[.-][a-z0-9]+)*)`", text))):
        group = tok.split("/", 1)[0]
        if group in ctx["groups"] and not ctx["ids_exist"](tok):
            errors.append("VERIFICATION.md cites %r, which is not an entry of corpus/index.json" % tok)
    return text, errors


def _section(page, anchor):
    out, inside = [], False
    for line in page.split("\n"):
        if re.match(r"^#{2,6} ", line):
            inside = line.rstrip().endswith("{#%s}" % anchor)
        elif inside:
            out.append(line)
    return out

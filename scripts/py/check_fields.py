#!/usr/bin/env python3
"""Check the guide's field-table source (corpus/fields.yaml) and claim map (guide/claims.yaml).

Always checked (no network, no upstream sources needed):
- fields.yaml validates against corpus/schema/fields.schema.json;
- row IDs are unique and ascending, part IDs belong to their row, partially-validated rows have parts,
  every stage code is defined in `stages`, every code_ref parses, an unverified row says why;
- every `demonstrated_by` ID is canonical (a row or `<row>.<member>` of corpus/plan.json);
- the stellar-core and stellar-xdr commits in `pins` equal pins.toml;
- every row or part a manifest entry cites in its `fields` block exists, under the same status;
- guide/claims.yaml (if present) validates against claims.schema.json, its claim IDs are unique, every
  field ID and corpus entry it names exists, and every row has at least one claim.

With --print-refs, also print, for every code reference (core_checks[].code_ref, and references written
inside `stages` and row text), the cited lines from the pinned commit, so a reviewer can read them.
A reference whose file or lines do not exist at the pinned commit is a failure.

Upstream sources for --print-refs, one per pin: `--src core=PATH`, `--src xdr=PATH`, `--src env=PATH`
(or XDRCHECK_SRC_CORE / XDRCHECK_SRC_XDR / XDRCHECK_SRC_ENV). PATH is either a git clone of the repository (read with
`git -C PATH show <commit>:<path>`, so any checkout state works) or a directory holding the tree at the
pinned commit. Default: .cache/src/<name>-<commit>. Reference prefixes: none = stellar-core,
`xdr:` = stellar-xdr, `env:` = rs-soroban-env at core's host pin.

Exit 1 on any failure."""
import argparse, json, os, re, subprocess, sys, tomllib
import jsonschema, yaml

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
SOURCES = {"core": "stellar_core", "xdr": "stellar_xdr", "env": "soroban_env_host"}  # name -> pins key
REF_RE = re.compile(r"((?:xdr:|env:)?[A-Za-z0-9_./-]+\.(?:cpp|h|rs|x)):(\d+(?:-\d+)?(?:,\s*\d+(?:-\d+)?)*)")
SEG_RE = re.compile(r"^((?:xdr:|env:)?[A-Za-z0-9_./-]+):(\d+(?:-\d+)?(?:,\s*\d+(?:-\d+)?)*)$")
ENTRY_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*(/[a-z0-9]+([.-][a-z0-9]+)*)+$")


def load(rel, kind="json"):
    if kind == "toml":
        with open(os.path.join(ROOT, rel), "rb") as f:
            return tomllib.load(f)
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return json.load(f) if kind == "json" else yaml.safe_load(f)


def schema_errors(doc, schema_rel, label):
    v = jsonschema.Draft202012Validator(load(schema_rel))
    return [f"{label}: {e.message[:200]} at /{'/'.join(map(str, e.absolute_path))}" for e in v.iter_errors(doc)]


def parse_ref(text):
    """'[xdr:|env:]path:1-2, 5; path2:9' -> [(source, path, [(1, 2), (5, 5)]), ...]; raises ValueError."""
    out = []
    for seg in text.split(";"):
        m = SEG_RE.match(seg.strip())
        if not m:
            raise ValueError(f"unparseable code reference segment {seg.strip()!r}")
        path, src = m.group(1), "core"
        if path.startswith(("xdr:", "env:")):
            src, path = path[:3], path[4:]
        ranges = []
        for part in m.group(2).split(","):
            a, _, b = part.strip().partition("-")
            a, b = int(a), int(b or a)
            if a < 1 or b < a:
                raise ValueError(f"bad line range {part.strip()!r} in {seg.strip()!r}")
            ranges.append((a, b))
        out.append((src, path, ranges))
    return out


def text_refs(text):
    """Code references written inside free text (stage descriptions, notes)."""
    return [m.group(0) for m in REF_RE.finditer(text or "")]


def canonical_ids():
    plan = load("corpus/plan.json")
    return {r["id"] for r in plan} | {f"{r['id']}.{m}" for r in plan for m in r.get("members", [])}


def check_fields(doc, canon, bad):
    bad += schema_errors(doc, "corpus/schema/fields.schema.json", "fields.yaml")
    rows = doc.get("fields") or []
    stages = doc.get("stages") or {}
    status = {}  # row or part ID -> status
    prev = 0
    for r in rows:
        rid = r.get("id", "?")
        num = int(rid[3:]) if re.fullmatch(r"VF-\d{2,3}", rid) else 0
        if rid in status:
            bad.append(f"{rid}: duplicate row ID")
        if num <= prev:
            bad.append(f"{rid}: rows must be in ascending ID order")
        prev = max(prev, num)
        status[rid] = r.get("status")
        parts = r.get("parts") or []
        if r.get("status") == "partially_validated" and not parts:
            bad.append(f"{rid}: partially_validated rows must carry parts (one status per published line)")
        for p in parts:
            pid = p.get("id", "?")
            if pid[:-1] != rid:
                bad.append(f"{rid}: part {pid} does not belong to this row")
            if pid in status:
                bad.append(f"{rid}: duplicate part ID {pid}")
            status[pid] = p.get("status")
        if r.get("verification") == "unverified" and not (r.get("unverified_parts") or r.get("verification_note")):
            bad.append(f"{rid}: verification unverified needs unverified_parts or verification_note (the reason)")
        for c in r.get("core_checks") or []:
            if c.get("stage") not in stages:
                bad.append(f"{rid}: stage {c.get('stage')!r} is not defined in `stages`")
            if "code_ref" in c:
                try:
                    parse_ref(c["code_ref"])
                except ValueError as e:
                    bad.append(f"{rid}: {e}")
        seen = set()
        for e in r.get("demonstrated_by") or []:
            if e not in canon:
                bad.append(f"{rid}: demonstrated_by {e!r} is not a canonical entry ID (corpus/plan.json)")
            if e in seen:
                bad.append(f"{rid}: demonstrated_by lists {e!r} twice")
            seen.add(e)
    pins, toml = doc.get("pins") or {}, load("pins.toml", "toml")
    for key, want in (("stellar_core", toml["stellar_core"]["commit"]),
                      ("stellar_xdr", toml["stellar_xdr_definitions"]["commit"])):
        if (pins.get(key) or {}).get("commit") != want:
            bad.append(f"fields.yaml: pins.{key}.commit differs from pins.toml ({want})")
    for key in SOURCES.values():
        if not (pins.get(key) or {}).get("commit"):
            bad.append(f"fields.yaml: pins.{key}.commit is missing")
    return status


def check_manifest_citations(status, bad):
    n = 0
    mdir = os.path.join(ROOT, "corpus", "manifest")
    for dirpath, _, files in os.walk(mdir):
        for f in sorted(files):
            if not f.endswith(".json"):
                continue
            rel = os.path.relpath(os.path.join(dirpath, f), ROOT)
            with open(os.path.join(dirpath, f), encoding="utf-8") as fh:
                cited = json.load(fh).get("fields") or {}
            for listed, ids in cited.items():
                for vf in ids:
                    n += 1
                    if vf not in status:
                        bad.append(f"{rel}: cites {vf}, which is not a row or part in fields.yaml")
                    elif status[vf] != listed:
                        bad.append(f"{rel}: cites {vf} under {listed}, but fields.yaml says {status[vf]}")
    return n


def check_claims(claims, rows, status, canon, bad):
    bad += schema_errors(claims, "corpus/schema/claims.schema.json", "claims.yaml")
    seen, covered = set(), set()
    for c in claims.get("claims") or []:
        cid = c.get("claim_id", "?")
        if cid in seen:
            bad.append(f"claims.yaml: duplicate claim ID {cid}")
        seen.add(cid)
        for vf in c.get("fields") or []:
            if vf not in status:
                bad.append(f"claims.yaml: {cid} names {vf}, which is not in fields.yaml")
            covered.add(re.sub(r"[a-z]$", "", vf))
        for e in c.get("corpus_entries") or []:
            if e not in canon:
                bad.append(f"claims.yaml: {cid} names {e!r}, which is not a canonical entry ID")
        for s in c.get("source") or []:
            if s.get("kind") == "corpus" and s.get("ref") not in canon:
                bad.append(f"claims.yaml: {cid} cites corpus entry {s.get('ref')!r}, which is not canonical")
            if s.get("kind") == "code":
                try:
                    parse_ref(s.get("ref", ""))
                except ValueError as e:
                    bad.append(f"claims.yaml: {cid}: {e}")
    for r in rows:
        if r.get("id") not in covered:
            bad.append(f"claims.yaml: no claim names {r.get('id')}")
    return len(seen)


class Sources:
    """Reads files at the pinned commits from a git clone or an exported tree."""

    def __init__(self, pins, overrides):
        self.cache, self.where = {}, {}
        for name, key in SOURCES.items():
            commit = (pins.get(key) or {}).get("commit", "")
            path = overrides.get(name) or os.environ.get(f"XDRCHECK_SRC_{name.upper()}") or \
                os.path.join(ROOT, ".cache", "src", f"{name}-{commit}")
            self.where[name] = (path, commit)

    def lines(self, src, path):
        if (src, path) not in self.cache:
            root, commit = self.where[src]
            if os.path.isdir(os.path.join(root, ".git")) or os.path.isfile(os.path.join(root, ".git")):
                p = subprocess.run(["git", "-C", root, "show", f"{commit}:{path}"], capture_output=True)
                if p.returncode != 0:
                    raise FileNotFoundError(f"{src}:{path} at {commit[:12]} ({p.stderr.decode().strip()[:120]})")
                data = p.stdout
            else:
                full = os.path.join(root, path)
                if not os.path.isfile(full):
                    raise FileNotFoundError(f"{src}:{path} not found under {root} "
                                            f"(pass --src {src}=<clone or tree at {commit[:12]}>)")
                with open(full, "rb") as f:
                    data = f.read()
            self.cache[(src, path)] = data.decode("utf-8", errors="replace").split("\n")
        return self.cache[(src, path)]


def print_refs(doc, srcs, bad):
    refs = []  # (label, claim text, ref text)
    for code, text in (doc.get("stages") or {}).items():
        refs += [(f"stage {code}", text, t) for t in text_refs(text)]
    for r in doc.get("fields") or []:
        for c in r.get("core_checks") or []:
            if "code_ref" in c:
                refs.append((f"{r['id']} {c['stage']}", c["what"], c["code_ref"]))
        for key in ("status_detail", "reader_may_assume", "reader_must_not_assume", "code_ref_note",
                    "verification_note"):
            refs += [(f"{r['id']} {key}", r[key], t) for t in text_refs(r.get(key))]
    segments = 0
    for label, claim, ref in refs:
        print(f"=== {label}: {claim}\n    {ref}")
        try:
            parsed = parse_ref(ref)
        except ValueError as e:
            bad.append(f"{label}: {e}")
            continue
        for src, path, ranges in parsed:
            segments += 1
            try:
                lines = srcs.lines(src, path)
            except FileNotFoundError as e:
                bad.append(f"{label}: {e}")
                print(f"    !! {e}")
                continue
            for a, b in ranges:
                print(f"--- {'' if src == 'core' else src + ':'}{path}:{a}{'' if a == b else f'-{b}'}")
                if b > len(lines):
                    bad.append(f"{label}: {path}:{a}-{b} is past the end of the file ({len(lines)} lines)")
                for i in range(a, min(b, len(lines)) + 1):
                    print(f"{i:6}  {lines[i - 1]}")
        print()
    return len(refs), segments


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--print-refs", action="store_true", help="print the cited source lines")
    ap.add_argument("--src", action="append", default=[], metavar="NAME=PATH",
                    help="upstream source for core, xdr or env (git clone or tree at the pinned commit)")
    args = ap.parse_args()
    overrides = {}
    for s in args.src:
        name, _, path = s.partition("=")
        if name not in SOURCES or not path:
            ap.error(f"--src expects one of {', '.join(SOURCES)}=PATH, got {s!r}")
        overrides[name] = path

    bad = []
    doc = load("corpus/fields.yaml", "yaml")
    canon = canonical_ids()
    status = check_fields(doc, canon, bad)
    rows = doc.get("fields") or []
    n_cites = check_manifest_citations(status, bad)
    n_claims = 0
    if os.path.exists(os.path.join(ROOT, "guide", "claims.yaml")):
        n_claims = check_claims(load("guide/claims.yaml", "yaml"), rows, status, canon, bad)
    n_checks = sum(1 for r in rows for c in r.get("core_checks") or [] if "code_ref" in c)
    summary = (f"fields: {len(rows)} rows, {sum(len(r.get('parts') or []) for r in rows)} parts, "
               f"{n_checks} code_refs; manifest citations checked: {n_cites}; claims: {n_claims}")
    if args.print_refs:
        n_refs, n_segs = print_refs(doc, Sources(doc.get("pins") or {}, overrides), bad)
        summary += f"; printed {n_refs} references ({n_segs} file segments)"
    print(summary)
    for b in bad:
        print("FAIL", b)
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()

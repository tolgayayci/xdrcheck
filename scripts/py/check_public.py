#!/usr/bin/env python3
"""Fail if any file in the repository (tracked, or untracked and not ignored) contains machine-local paths,
private names, references to the project's internal working files, or internal planning labels. Run before
every commit.

Internal planning labels are vocabulary of the development process, not of the kit: plan task IDs (`X-NN`),
internal component-owner and worktree names, citations of the internal design notes and decision records, and
internal requirement IDs. Say what the code does instead, or cite the public page in `docs/` or `evidence/`. The
public vocabulary that looks similar stays allowed (ALLOWED below): finding IDs `F-NNNN`, CAP and SEP numbers,
xdrlint rule IDs `XDRnnn`, guide row, claim and checklist IDs (`VF-NN`, `C-NNNN`, `HC-NNN`), the manifest's
matching rules (`P-1`, `S-1`, `M-1`), and the golden checks `AG-1`…`AG-4` that docs/acceptance.md and
docs/architecture.md define. The acceptance checks have word IDs (`roundtrip`, `replay-regression`, …); their
former numbered IDs are a label.

Context terms are words that do not belong in a self-standing open-source project: the vocabulary of how the
project was funded and reviewed, and the names of other projects and people working on the same problem.
`context-terms.sha256`, next to this script, holds them hashed the same way as the private names (its own salt), so
the guard does not itself spell them out; they are searched for in every scanned file, including the files that
hold the rules. Regenerate it with `check_public.py --hash-context-terms FILE` from a plain list kept outside the
repository.

Private names are never written here in plain text. `private-terms.sha256`, next to this script, holds the
SHA-256 of a public salt and each lowercased name. The scan splits text into tokens of letters, digits, `.`, `_`
and `-`, and hashes each token, the runs of up to four of its `.`/`_`/`-`-separated parts (as written and joined
by `-`), its camel-case words, and each pair of adjacent tokens joined by one space or by `-`. A hash in the list is a problem. When XDRCHECK_OVERLAY is set,
the plain list in `$XDRCHECK_OVERLAY/public-terms.txt` (one name per line, never committed) is also searched for as
case-insensitive text; that list is the authority before a push, and the hashed list is the guard that CI runs.

Report-like files (any scanned file that declares the `xcc.report/v1` schema) must not carry the machine's
hostname (`header.run.host`); the tools leave it out unless XDRCHECK_REPORT_HOST=1.

Usage:
    check_public.py                  self-test, then scan the tree; exit 1 on any problem
    check_public.py --selftest       run only the self-test
    check_public.py --tree DIR       self-test, then scan every file under DIR (not the repository) with every rule
                                     and no exemption: for a directory that leaves the repository, such as an
                                     extracted release archive or a reports directory before it is attached anywhere
    check_public.py --rev REV        self-test, then scan the tree of commit REV (read from git, no checkout)
    check_public.py --revs RANGE     the same at every commit of `git rev-list RANGE` (each blob is scanned once)
    check_public.py --messages RANGE the message of every commit of `git rev-list RANGE`
    check_public.py --hash-terms FILE  print a private-terms.sha256 for the plain list FILE (one name per line)
    check_public.py --hash-context-terms FILE  the same for context-terms.sha256

--rev, --revs and --messages take `--categories LIST` (comma-separated; default all) to pick rule categories:
local-path, private, internal, handle, host, labels, context. Every scan ends with one count per category.

Every `re.compile(r"…")` line here is also read by `xdrcheck report redact` (go/cmd/xdrcheck/report.go) and translated to
Go's RE2: keep those patterns on one line and free of lookahead. Patterns that are not banned are compiled from
plain strings so that redact does not read them. Redact reads `private-terms.sha256` with the same tokenizer.
"""
import collections, hashlib, os, re, subprocess, sys, tempfile
BANNED = [
    (re.compile(r"/home/[A-Za-z0-9]"), "machine-local home path"),
    (re.compile(r"/Users/[A-Za-z0-9]"), "machine-local home path"),
    (re.compile(r"(?<![\w.-])/root/"), "machine-local root path"),
    (re.compile(r"/tmp/claude"), "machine-local scratch path"),
    (re.compile(r"(?<![\w-])references/"), "internal research folder"),
    (re.compile(r"\(not published\)"), "citation of an unpublished internal document"),
    (re.compile(r"\bTRACKING\.md\b|\bBUILD_PLAN\.md\b|\bdesign-review-2026|\bresearch-gap-review"), "internal working file"),
    (re.compile(r"\bsamples/(blobs|decoded|manifest|chains)/"), "path into the internal design samples"),
    (re.compile(r"\b(?:decoded|captured|written) by A\d{1,2}\b|\b(?:agent|probe) (?:A|G|RV)\d{1,2}\b"), "internal probe identifier"),
    (re.compile(r"\bADR[ -]?0\d{3}\b"), "internal decision-record number"),
    (re.compile(r"\b[a-z0-9]+(?:-[a-z0-9]+)+-2026-11-12(?:\.md)?\b"), "internal research-note name"),
    (re.compile(r"project research \("), "citation of internal research"),
]
LOCAL_PATH_RULES = 4  # the first BANNED rules are machine-local paths; the rest are internal references
# Internal planning labels, by category. Every match is reported unless it is public vocabulary (ALLOWED).
LABELS = [
    # 1. plan task IDs and workstream labels: `R-18`, `(H-07)`, `task V-01`, `C-H3`, `W8`
    (re.compile(r"\b[A-Z]{1,2}-\d{2}\b|\bC-H\d+\b|\btasks? [A-Z]{1,3}-\d+[a-z]?|(?<![\w:/+=-])W\d{1,2}\b|\bworkstream\b"), "plan task ID"),
    # 2. internal component-owner and worktree names, research-probe and review labels
    (re.compile(r"\b(?:rust-(?:core|gen|intake|meta|scn)|go-(?:adapter|conform|replay|serve)|drv-(?:extra|go|js|rust)|lint-(?:core|rules)|content-\d|findings-\d)\b|\bwt/[a-z]"), "internal component-owner or worktree name"),
    (re.compile(r"\((?:G|RV)\d{1,2}[,)]|\b(?:G|RV)\d{1,2}(?:'s| spike| probe| brief| throwaway| transcript| helpers| bounded)\b|(?:#|//|\"\"\")\s*(?:G|RV)\d{1,2}:|\b(?:as in|from|by) (?:G|RV)\d{1,2}\b"), "research-probe label"),
    (re.compile(r"\bruling \d+[a-z]?\b|(?://|#)\s*[AB]\d{1,2}(?::| /)|\b[AB]\d{1,2}\s*[–-]\s*[AB]\d{1,2}\b"), "internal review label"),
    # 3. the internal design notes, decision records and planning files
    (re.compile(r"(?<![\w/.-])design/[A-Za-z]|\bARCHITECTURE\.md\b|\badr/\d|\bADR[ -]?\d+\b|\(design[:)]|\bmanifest spec\b"), "internal design citation"),
    (re.compile(r"\b(?:corpus-pipeline|cli-reference|conformance-runner|guide[- ]outline|findings-process|coverage-matrix|coverage-plan|entry-id-map|maintenance-and-upgrade-plan)\b|\bfields\.draft\b|(?<![\w-])(?:linter|adapters)\.md\b"), "internal design file"),
    (re.compile(r"\bMISSION_BRIEF\b|\bBUILD_PLAN\b|\bBUILD_AGENT_RULES\b|\bbuild-tasks\.json\b|\bTRACKING\.md\b"), "internal planning file"),
    # 4. internal requirement IDs: `FR-2b`, `NFR-1a`, `MS-7`, `EXP-8`, `SHAPE-8`, …
    (re.compile(r"\b(?:NFR|FR|MS|BRF|TRK|EXP|EVAL|SHAPE|SPEC|DEL|SIG|BG|DIFF)-\d+[a-z]?\b"), "internal requirement ID"),
    # 5. the former numbered acceptance-check IDs (now `roundtrip`, `replay-regression`, …); a plain-string pattern,
    # so `xdrcheck report redact` does not read it
    (re.compile("\\bCHK-\\d"), "former acceptance-check ID"),
]
# Public vocabulary a label rule may also match; built without a raw-string compile so `xdrcheck report redact`
# does not read it as a banned pattern.
ALLOWED = re.compile("|".join([
    r"F-\d{4}",                          # finding IDs
    r"(?:CAP|SEP)-\d+",                  # Stellar CAPs and SEPs
    r"XDR\d{3}",                         # xdrlint rule IDs
    r"VF-\d{2,3}[a-z]?", r"C-\d{3,4}", r"HC-\d{3}",  # guide field rows, claims, checklist items
    r"[PSM]-\d",                         # the manifest's matching rules (docs/manifest.md §6.5–§6.7)
    r"AG-\d",                           # golden checks (docs/acceptance.md, docs/architecture.md)
]))
# The entry-ID registry is a frozen contract: its `serves` field cites the requirement each row was planned
# for, and its free-text fields were written with it. It is the one place the label rules do not apply.
LABELS_EXEMPT = ("corpus/plan.json", "corpus/schema/examples/plan/")
# The GitHub module path is the repository's public import path, and the core-next image name is fixed to the
# public name; the named maintainer is written in one form, `Tolga Yaycı ([@tolgayayci](https://github.com/tolgayayci))`
# (docs/maintenance.md section 2). These are the only allowed occurrences of the handle (scripts/py/check_slug.py
# limits where the repository ones may appear).
HANDLE = re.compile(r"(?i)tolga")
HANDLE_OK = re.compile(r"github\.com/tolgayayci/xdrcheck\b|ghcr\.io/tolgayayci/xdrcheck-core-next\b|Tolga Yaycı \(\[@tolgayayci\]|\[@tolgayayci\]\(https://github\.com/|github\.com/tolgayayci\)")
# Files that hold the rules themselves, or that never ship: only the private-name rules apply to them.
SKIP = {"scripts/py/check_public.py", "scripts/py/check_slug.py", "CLAUDE.md", "AGENTS.md", ".gitignore"}
BINARY = (".zst", ".xdr", ".gz", ".wasm", ".b64", ".png", ".jar", ".lock", ".woff2", ".woff", ".ttf")
# A report header's run block naming the machine (`"host": "<name>"`); the schema's own `"host": {` is not a value.
# Single-quoted on purpose: `xdrcheck report redact` drops the host field itself and must not read this as a pattern.
REPORT_SCHEMA = '"xcc.report/v1"'
REPORT_HOST = re.compile(r'"host"\s*:\s*"[^"]')
# Untracked files that belong to other work in this folder are not part of the kit (the working-tree scan
# only; a commit is scanned whole).
NOT_OURS = ("apps/", "package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml")
CATEGORIES = ("local-path", "private", "internal", "handle", "host", "labels", "context")

# ---- private names: hashed list ----
TERMS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "private-terms.sha256")
CONTEXT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "context-terms.sha256")
TOKEN = re.compile("[A-Za-z0-9._-]+")
SEPARATOR = re.compile("([._-])")
CAMEL = re.compile("[A-Z]+(?![a-z])|[A-Z]?[a-z0-9]+")
MAX_PARTS = 4


def term_hash(salt, term):
    return hashlib.sha256((salt + ":" + term.lower()).encode("utf-8")).hexdigest()


def load_terms(path=TERMS_FILE):
    """(salt, set of hex digests) of a private-terms.sha256 file."""
    salt, hashes = None, set()
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("salt "):
            salt = line[len("salt "):]
        elif re.fullmatch("[0-9a-f]{64}", line):
            hashes.add(line)
        else:
            raise SystemExit(f"{path}: unreadable line {line!r}")
    if salt is None or not hashes:
        raise SystemExit(f"{path}: no salt or no hashes")
    return salt, hashes


def candidates(tok):
    """Every string of tok a private name could be: tok, runs of its separated parts, its camel-case words."""
    out = {tok.lower()}
    parts = SEPARATOR.split(tok)
    words, seps = parts[0::2], parts[1::2]
    for i, w in enumerate(words):
        acc = w
        if w:
            out.add(w.lower())
        norm = w
        for j in range(i + 1, min(len(words), i + MAX_PARTS)):
            acc += seps[j - 1] + words[j]
            norm += "-" + words[j]
            out.add(acc.lower())
            out.add(norm.lower())
        for c in CAMEL.findall(w):
            out.add(c.lower())
    out.discard("")
    return out


class Terms:
    """Matches private names from the hashed list (and the overlay's plain list, when given)."""

    def __init__(self, salt, hashes, plain=()):
        self.salt, self.hashes, self.cache = salt, set(hashes), {}
        self.plain = [re.compile("(?i)" + re.escape(p)) for p in plain]

    def _hit(self, s):
        h = self.cache.get(s)
        if h is None:
            h = self.cache[s] = term_hash(self.salt, s) in self.hashes
        return h

    def find(self, text):
        """Offsets of private names in text (hashed list, then plain list)."""
        hits = []
        toks = list(TOKEN.finditer(text))
        seen = set()
        for m in toks:
            t = m.group(0)
            if t in seen:
                continue
            seen.add(t)
            if any(self._hit(c) for c in candidates(t)):
                hits.append(m.start())
        for a, b in zip(toks, toks[1:]):
            x, y = a.group(0).lower(), b.group(0).lower()
            if self._hit(x + " " + y) or self._hit(x + "-" + y):
                hits.append(a.start())
        for rx in self.plain:
            m = rx.search(text)
            if m:
                hits.append(m.start())
        return sorted(set(hits))


def overlay_plain():
    ov = os.environ.get("XDRCHECK_OVERLAY") or os.environ.get("XCC_OVERLAY", "")  # the earlier name still applies
    p = os.path.join(ov, "public-terms.txt")
    if not ov or not os.path.isfile(p):
        return []
    return [l.strip() for l in open(p, encoding="utf-8") if l.strip() and not l.startswith("#")]


def label_hits(text):
    """(offset, reason, label) for every internal planning label in text."""
    hits = []
    for rx, why in LABELS:
        for m in rx.finditer(text):
            if not ALLOWED.fullmatch(m.group(0)):
                hits.append((m.start(), why, m.group(0)))
    return sorted(hits)


def text_hits(text, terms, skip=False, exempt=False):
    """(offset, category, reason, length) for every problem in one file's text. A skipped file is checked for
    private names only; an exempt one skips the label rules."""
    hits = [(at, "private", "private name (hashed list or overlay list)", 0) for at in terms.find(text)]
    hits += [(at, "context", "context term (hashed list): funding, review or another project's name", 0)
             for at in context_terms().find(text)]
    if skip:
        return hits
    for i, (rx, why) in enumerate(BANNED):
        m = rx.search(text)
        if m:
            hits.append((m.start(), "local-path" if i < LOCAL_PATH_RULES else "internal", why, m.end() - m.start()))
    for m in HANDLE.finditer(text):
        ctx = text[max(0, m.start() - 11): m.end() + 30]
        if not HANDLE_OK.search(ctx):
            hits.append((m.start(), "handle", "personal name or handle", m.end() - m.start()))
            break
    if REPORT_SCHEMA in text:
        m = REPORT_HOST.search(text)
        if m:
            hits.append((m.start(), "host", "report header carries the machine hostname", m.end() - m.start()))
    if not exempt:
        for at, why, label in label_hits(text):
            hits.append((at, "labels", f"{why} {label!r}", len(label)))
    return hits


_CONTEXT = []


def context_terms():
    """The hashed context terms (context-terms.sha256), loaded once."""
    if not _CONTEXT:
        _CONTEXT.append(Terms(*load_terms(CONTEXT_FILE)))
    return _CONTEXT[0]


def show(text, at, n, cat):
    """A snippet around a hit; a private name or a context term is never printed."""
    if cat in ("private", "context"):
        return ""
    return ": " + repr(text[max(0, at - 40): at + n + 40])


# Self-test: each line must (or must not) be reported by the label rules.
MUST_FLAG = [
    "//! `xdrcheck-corpus coverage` (task R-15): per-CAP coverage",
    "    /// Write SEP-51 decoded sidecars (R-03)",
    'echo "replay-full: not implemented yet (needs H-10 and H-14)"',
    "the C-H3 review item", "the W8 workstream", "owned by W8.",
    "agent `rust-gen`", "default prefix xdrcheck-go-serve", "branch wt/sweep-1", "Owner: `rust-meta`.",
    "# golden-mirror spike (G6, 2026-11-12)", "Helpers copied from G5's scenario731.mjs", '"source_of_claim": "G2 brief"',
    "# G4 spike transcript: wallet-backend#716", '"""G6: split a record-marked stream', "fixed salt, as in G3",
    "// A8 / ruling 3b: L1 on a ledger.", "// A1: a declared op", "review items A1–A8",
    "see design/ci.md", "ARCHITECTURE.md §4", "adr/0007-oracle.md", "ADR 17", "(design: cli-reference §2)",
    "`corpus-pipeline` §8", "conformance-runner §16", "guide outline §1.2", "see findings-process.md",
    "adapters.md §3", "manifest spec §11", "BUILD_PLAN", "build-tasks.json", "MISSION_BRIEF",
    "verify-memory: ## NFR-2", "## FR-2c: regenerate", "## MS-7: one table", "SHAPE-8", "EXP-1", "EVAL-6",
    "BRF-1", "TRK-5", "SPEC-2", "DIFF-6", "CH" "K-1a", "check CH" "K-5a/b/c", "(CH" "K-6)",
]
MUST_PASS = [
    "finding F-0001 and F-0028", "CAP-67, CAP-0084 and SEP-23, SEP-51", "rules XDR101 and XDR201",
    "row VF-21, VF-46a, VF-100", "claim C-6104 and C-001", "checklist HC-201", "rules P-1…P-6, S-1, M-7",
    "roundtrip, sdk-regression, findings-linked (AG-1, AG-4)", "CHKSUM-1", "wallet-backend#729", "UTF-8, SHA-256, P-256, RFC 5531 §3.1",
    "go-stellar-sdk v0.8.0", "lint/docs/XDR101.md", "docs/manifest.md §6.11", "docs/replay-harness.md §2.2",
    "check_cli_reference.py", "golden-mirror", "the local-core probe L16", "const G1 = kp('g1')",
    "testnet checkpoint 4378879", "github.com/aws/aws-sdk-go-v2 h1:W3/vL6EtCIatICGy9ab29QhMuae+cOKPWcMxv02CO+Q=",
    "xdrcheck-serve", "xdrcheck-replay", "lint-fixtures", "findings/README.md", "design-core-default",
    "docs/use-in-sdk-ci.md", "docs/ci-isolation.md", "scripts/release.sh",
]
# Self-test of the hashed list, with a made-up name (never a real one): every spelling below must be found.
PLANT = "zq-plantedname"
PLANT_PAIR = "Zq Plantword"
PLANT_FLAG = ["a zq-plantedname here", "path/to/ZQ-PlantedName/x", "x.zq-plantedname.y", "build_zq-plantedname_1",
              "zq_plantedname", "zq plantedname", "see Zq Plantword docs"]
PLANT_PASS = ["zqplantedname", "zqplanted-name", "zq-planted", "Zq Plantwords", "zq to plantedname"]


def selftest(terms):
    bad = [f"self-test: not reported: {s!r}" for s in MUST_FLAG if not label_hits(s)]
    bad += [f"self-test: reported {label_hits(s)[0][2]!r} ({label_hits(s)[0][1]}) in {s!r}" for s in MUST_PASS if label_hits(s)]
    planted = Terms(terms.salt, {term_hash(terms.salt, PLANT), term_hash(terms.salt, PLANT_PAIR)})
    bad += [f"self-test: hashed name not found in {s!r}" for s in PLANT_FLAG if not planted.find(s)]
    bad += [f"self-test: hashed name wrongly found in {s!r}" for s in PLANT_PASS if planted.find(s)]
    for b in bad:
        print("FAIL " + b)
    return len(bad)


def scan(terms, tree=None):
    """Scan the repository's files, or with tree every file under that directory, with no skip or exemption."""
    if tree is None:
        root = subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip()
        files = subprocess.check_output(["git", "ls-files", "--cached", "--others", "--exclude-standard"], cwd=root, text=True).split("\n")
        not_ours, skip, exempt = NOT_OURS, SKIP, LABELS_EXEMPT
    else:
        root = tree
        files = sorted(os.path.relpath(os.path.join(d, n), root) for d, _, names in os.walk(root) for n in names)
        not_ours, skip, exempt = (), set(), ()
    bad = n = 0
    for f in files:
        if not f or (not_ours and f.startswith(not_ours)) or f.endswith(BINARY):
            continue
        p = os.path.join(root, f)
        if not os.path.isfile(p):
            continue
        text = open(p, encoding="utf-8", errors="ignore").read()
        n += 1
        for at, cat, why, ln in sorted(text_hits(text, terms, f in skip, bool(exempt) and f.startswith(exempt))):
            line = text.count("\n", 0, at) + 1
            print(f"FAIL {f}:{line}: {why}{show(text, at, ln, cat)}")
            bad += 1
    print(f"public-tree scan{'' if tree is None else ' of ' + os.path.basename(os.path.normpath(tree))}: {n} files, {bad} problems")
    return bad


# ---- commits: trees and messages, read from git without a checkout ----

def git(*args, data=None):
    r = subprocess.run(["git", *args], input=data, capture_output=True)
    if r.returncode != 0:
        raise SystemExit(f"git {' '.join(args)}: {r.stderr.decode(errors='replace').strip()}")
    return r.stdout


def rev_list(spec):
    if not spec or spec.startswith("-"):
        raise SystemExit(f"not a revision range: {spec!r}")
    return git("rev-list", spec, "--").decode().split()


def tree_blobs(rev):
    """(path, blob id) of every regular file in the tree of commit rev."""
    out = []
    for rec in git("ls-tree", "-r", "-z", "--full-tree", rev + "^{commit}", "--").decode("utf-8", "replace").split("\x00"):
        if not rec:
            continue
        meta, path = rec.split("\t", 1)
        mode, kind, oid = meta.split()
        if kind == "blob" and mode in ("100644", "100755"):
            out.append((path, oid))
    return out


class Blobs:
    """Reads blobs through one `git cat-file --batch` process."""

    def __init__(self):
        self.p = subprocess.Popen(["git", "cat-file", "--batch"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    def read(self, oid):
        self.p.stdin.write(oid.encode() + b"\n")
        self.p.stdin.flush()
        hdr = self.p.stdout.readline().split()
        if len(hdr) != 3:
            raise SystemExit(f"git cat-file: cannot read {oid}")
        data = self.p.stdout.read(int(hdr[2]))
        self.p.stdout.read(1)
        return data

    def close(self):
        self.p.stdin.close()
        self.p.wait()


def scan_revs(terms, revs, cats, label):
    """Scan the tree of every commit in revs; each (blob, rule set) is scanned once. Prints every problem once,
    with the first commit (in rev-list order) and the number of commits that hold it."""
    blobs, cache = Blobs(), {}
    first, holders, counts = {}, collections.Counter(), collections.Counter()
    bad_commits = 0
    for c in revs:
        bad_here = False
        for f, oid in tree_blobs(c):
            if f.endswith(BINARY):  # a commit holds only what is committed: no untracked exemption
                continue
            key = (oid, f in SKIP, f.startswith(LABELS_EXEMPT))
            if key not in cache:
                text = blobs.read(oid).decode("utf-8", "ignore")
                cache[key] = [(text.count("\n", 0, at) + 1, cat, why + show(text, at, ln, cat))
                              for at, cat, why, ln in sorted(text_hits(text, terms, key[1], key[2])) if cat in cats]
            for line, cat, msg in cache[key]:
                k = (f, line, cat, msg)
                if k not in first:
                    first[k] = c
                    counts[cat] += 1
                holders[k] += 1
                bad_here = True
        bad_commits += bad_here
    blobs.close()
    for (f, line, cat, msg), c in first.items():
        print(f"FAIL {c[:12]} {f}:{line}: [{cat}] {msg} (in {holders[(f, line, cat, msg)]} commit(s))")
    summary(label, len(revs), bad_commits, counts, cats)
    return len(first)


def scan_messages(terms, revs, cats):
    counts, bad = collections.Counter(), 0
    for c in revs:
        msg = git("log", "-1", "--format=%B", c, "--").decode("utf-8", "replace")
        hits = [h for h in text_hits(msg, terms) if h[1] in cats]
        for at, cat, why, ln in sorted(hits):
            print(f"FAIL {c[:12]} message: [{cat}] {why}{show(msg, at, ln, cat)}")
            counts[cat] += 1
        bad += bool(hits)
    summary("commit-message scan", len(revs), bad, counts, cats)
    return sum(counts.values())


def summary(label, n, bad, counts, cats):
    per = ", ".join(f"{c} {counts[c]}" for c in CATEGORIES if c in cats)
    print(f"{label}: {n} commit(s), {bad} with problems, {sum(counts.values())} problem(s) ({per})")


def main(args):
    terms = None
    if args[:1] in (["--hash-terms"], ["--hash-context-terms"]) and len(args) == 2:
        context = args[0] == "--hash-context-terms"
        salt = load_terms(CONTEXT_FILE if context else TERMS_FILE)[0]
        if context:
            print("# check_public.py context terms: sha256 of '<salt>:<lowercased term>', one per line. Generated by")
            print("# check_public.py --hash-context-terms from a plain list kept outside the repository.")
        else:
            print("# check_public.py private names: sha256 of '<salt>:<lowercased name>', one per line. Generated by")
            print("# check_public.py --hash-terms from the plain list, which lives only in the private overlay.")
        print("salt " + salt)
        for t in sorted({term_hash(salt, l.strip()) for l in open(args[1], encoding="utf-8") if l.strip() and not l.startswith("#")}):
            print(t)
        return 0
    salt, hashes = load_terms()
    terms = Terms(salt, hashes, overlay_plain())
    cats = set(CATEGORIES)
    if "--categories" in args:
        i = args.index("--categories")
        if i + 1 >= len(args):
            print("usage: --categories LIST")
            return 1
        cats = set(args[i + 1].split(","))
        if not cats <= set(CATEGORIES):
            print(f"unknown categories {sorted(cats - set(CATEGORIES))}; known: {', '.join(CATEGORIES)}")
            return 1
        del args[i:i + 2]
    failed = selftest(terms)
    print(f"public-tree scan self-test: {len(MUST_FLAG)} labels reported, {len(MUST_PASS)} public strings kept, "
          f"{len(PLANT_FLAG)} hashed-name spellings found, {failed} problems")
    if args[:1] == ["--tree"] and len(args) == 2 and os.path.isdir(args[1]):
        failed += scan(terms, args[1])
    elif args[:1] == ["--tree"]:
        print("usage: check_public.py --tree DIR (an existing directory)")
        failed += 1
    elif args[:1] == ["--rev"] and len(args) == 2:
        failed += scan_revs(terms, rev_list(args[1] + "^!") if not args[1].startswith("-") else rev_list(args[1]), cats,
                            f"public-tree scan of {args[1]}")
    elif args[:1] == ["--revs"] and len(args) == 2:
        failed += scan_revs(terms, rev_list(args[1]), cats, f"public-tree scan of {args[1]}")
    elif args[:1] == ["--messages"] and len(args) == 2:
        failed += scan_messages(terms, rev_list(args[1]), cats)
    elif args and args != ["--selftest"]:
        print(__doc__.split("Usage:")[1].split("--rev, --revs")[0])
        failed += 1
    elif not args:
        failed += scan(terms)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

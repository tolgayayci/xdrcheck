#!/usr/bin/env python3
"""Hardcoded-slug check: the repository's own owner/repo is never written into a file by hand, except where a
fixed name is the point.

Allowed:
- the Go module paths (`github.com/<owner>/<repo>/{go,lint,packages,drivers}/…`), which are import paths;
- the published core-next image name, which is fixed to the public name so its digest pin survives a move;
- the repository URL itself in the few files that must carry a real link (URL_FILES).
Rejected everywhere else: the slug in any other form, the repository's former slug (outside FORMER_OK), an image
name derived from `github.repository`, and a reusable workflow named by owner/repo inside this repository's own
workflows (in-repo calls use `./.github/workflows/…`). Docs and examples write `OWNER/REPO` instead.

Usage: check_slug.py [--root DIR] | --self-test. Exit 1 on any finding."""
import os, re, subprocess, sys, tempfile

OWNER, REPO = "tolgayayci", "xdrcheck"
# The former slug, built in pieces so this file does not hold it.
FORMER = re.compile("stellar-" + "xdr-cap-" + "coverage")
FORMER_OK = ("NOTICE",)
SLUG = re.compile(r"(?i)\b" + OWNER + r"/[A-Za-z0-9_.-]+")
MODULE = re.compile(r"github\.com/" + OWNER + "/" + REPO + r"/(?:go|lint|packages|drivers)(?![\w.-])")
IMAGE = re.compile(r"ghcr\.io/" + OWNER + "/" + REPO + r"-core-next(?![\w.-])")
URL = re.compile(r"https://github\.com/" + OWNER + "/" + REPO + r"(?![\w.-])")
# Files that carry the real repository URL, and why.
URL_FILES = {
    "README.md": "the CI status badges on the front page",
    "action/fetch-release.sh": "the default release source of the pin helper",
    "packages/rust/Cargo.toml": "crate metadata (repository)",
    "release/Dockerfile": "OCI image source label",
    "guide/checklist.mdx": "a link from the published guide to the rule pages",
    "lint/internal/ruledoc/ruledoc.go": "the rule-page base URL SARIF output links to",
}
DERIVED_IMAGE = re.compile(r"ghcr\.io/\$\{\{\s*github\.repository")
REMOTE_WORKFLOW = re.compile(r"uses:\s*[\w.-]+/[\w.-]+/\.github/workflows/")
# The two checkers hold the allowed forms as patterns.
SKIP = {"scripts/py/check_slug.py", "scripts/py/check_public.py"}
BINARY = (".zst", ".xdr", ".gz", ".wasm", ".b64", ".png", ".jar")


def files(root):
    try:
        out = subprocess.check_output(["git", "ls-files", "-z"], cwd=root, stderr=subprocess.DEVNULL)
        return [f for f in out.decode().split("\0") if f]
    except (subprocess.CalledProcessError, FileNotFoundError):
        return sorted(os.path.relpath(os.path.join(d, f), root) for d, _, fs in os.walk(root) for f in fs)


def check_text(path, text):
    bad = []
    for n, line in enumerate(text.split("\n"), 1):
        if FORMER.search(line) and path not in FORMER_OK:
            bad.append((path, n, "former repository slug"))
        for m in SLUG.finditer(line):
            s = m.start()
            ctx = line[max(0, s - 20):]
            pre = line[:s]
            if pre.endswith("github.com/") and MODULE.match(line, s - len("github.com/")):
                continue
            if pre.endswith("ghcr.io/") and IMAGE.match(line, s - len("ghcr.io/")):
                continue
            if pre.endswith("https://github.com/") and URL.match(line, s - len("https://github.com/")) \
                    and path in URL_FILES:
                continue
            bad.append((path, n, f"hardcoded owner/repo {m.group(0)!r} (write OWNER/REPO or derive it): {ctx[:80].strip()}"))
        if DERIVED_IMAGE.search(line):
            bad.append((path, n, "image name derived from github.repository; use the fixed public image name"))
        if path.startswith(".github/workflows/") and REMOTE_WORKFLOW.search(line):
            bad.append((path, n, "reusable workflow named by owner/repo; call it as ./.github/workflows/…"))
    return bad


def scan(root):
    bad = []
    for f in files(root):
        if f in SKIP or f.endswith(BINARY):
            continue
        p = os.path.join(root, f)
        if not os.path.isfile(p) or os.path.islink(p):
            continue
        try:
            text = open(p, encoding="utf-8").read()
        except UnicodeDecodeError:
            continue
        bad += check_text(f, text)
    return bad


def self_test():
    planted = {
        "docs/a.md": "see https://github.com/" + OWNER + "/" + REPO + "/blob/main/README.md\n",
        "docs/b.md": "former " + OWNER + "/stellar-" + "xdr-cap-" + "coverage here\n",
        "docs/c.md": "uses: " + OWNER + "/" + REPO + "@v30\n",
        ".github/workflows/x.yml": "    uses: " + OWNER + "/" + REPO + "/.github/workflows/sdk.yml@main\n",
        "scripts/d.sh": "img=ghcr.io/${{ github.repository }}-core-next\n",
        "examples/e.yml": "curl https://github.com/" + OWNER.upper() + "/other/releases\n",
    }
    clean = {
        "go/x.go": 'import "github.com/' + OWNER + "/" + REPO + '/go/internal/pins"\n',
        "lint/README.md": "go install github.com/" + OWNER + "/" + REPO + "/lint/cmd/xdrlint@<version>\n",
        "action/fetch-release.sh": "DEFAULT_REPO_URL=https://github.com/" + OWNER + "/" + REPO + "\n",
        "scripts/f.sh": "IMAGE=ghcr.io/" + OWNER + "/" + REPO + "-core-next\n",
        "docs/g.md": "curl https://github.com/OWNER/REPO/releases/download/v1/x\n",
        ".github/workflows/y.yml": "    uses: ./.github/workflows/sdk.yml\n",
        "NOTICE": "formerly stellar-" + "xdr-cap-" + "coverage\n",
    }
    failed = 0
    with tempfile.TemporaryDirectory() as d:
        for name, body in {**planted, **clean}.items():
            os.makedirs(os.path.join(d, os.path.dirname(name)), exist_ok=True)
            open(os.path.join(d, name), "w").write(body)
        hits = {p for p, _, _ in scan(d)}
    for name in planted:
        if name not in hits:
            print(f"self-test: planted slug in {name} not caught", file=sys.stderr)
            failed = 1
    for name in clean:
        if name in hits:
            print(f"self-test: allowed form in {name} rejected", file=sys.stderr)
            failed = 1
    print(f"check_slug self-test: {len(planted)} planted caught, {len(clean)} allowed forms pass" if not failed
          else "check_slug self-test: FAILED")
    return failed


def main(args):
    if args == ["--self-test"]:
        return self_test()
    root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
    if args[:1] == ["--root"] and len(args) == 2:
        root = args[1]
    elif args:
        print(__doc__, file=sys.stderr)
        return 2
    bad = scan(root)
    for p, n, why in bad:
        print(f"{p}:{n}: {why}")
    print(f"check_slug: {len(bad)} finding(s)" if bad else "check_slug: no hardcoded owner/repo")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

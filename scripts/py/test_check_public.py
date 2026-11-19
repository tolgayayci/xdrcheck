#!/usr/bin/env python3
"""Self-test of the history scans of check_public.py (--rev, --revs, --messages) on a throwaway repository.

A made-up private name is planted in one intermediate commit and in one commit message, an internal planning
label in another file and a context term in a third; the scans must find each, at that commit only, and the tip
must stay clean. No real private name appears here: the planted one is hashed with the shipped salt into an
in-memory list. The shipped context-term list is also checked against spellings of its terms, each split in the
source so that this file passes the scan, and against public text it must leave alone.

Usage: test_check_public.py   (exit 1 on any failure)
"""
import contextlib, io, os, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import check_public as cp  # noqa: E402

ENV = dict(os.environ, GIT_AUTHOR_NAME="fixture", GIT_AUTHOR_EMAIL="fixture@example.invalid",
           GIT_COMMITTER_NAME="fixture", GIT_COMMITTER_EMAIL="fixture@example.invalid",
           GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
PLANT = "zq-plantedname"
CONTEXT = "R" + "FP"
# Spellings the shipped context-term list must find (each term split, so this file itself passes the scan).
CONTEXT_FLAG = ["the " + CONTEXT + " checklist", "S" + "CF funding", "r" + "fp_check", "Stellar Commu" + "nity Fund",
                "sight" + "ings.json", "public sight" + "ing", "Hacker" + "One report", "mile" + "stone acceptance",
                "Mile" + "stones 1-3", "Eren" + "Topaal", "ABS" + "-gmbh", "shape" + "kit", "Ledger" + "Witness"]
# Public text it must leave alone.
CONTEXT_PASS = ["grant access to the bucket", "acceptance tests", "known-defects.json", "roundtrip", "sight",
                "fund", "community", "a mile" + "stoned", "shape kit", "s" + "cfx", "the request body", "proposals"]
failures = []


def git(repo, *args):
    return subprocess.run(["git", "-C", repo, *args], env=ENV, check=True, capture_output=True, text=True).stdout.strip()


def put(repo, rel, text):
    p = os.path.join(repo, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    open(p, "w").write(text)


def commit(repo, msg):
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "--allow-empty", "-m", msg)
    return git(repo, "rev-parse", "HEAD")


def check(cond, what):
    if not cond:
        failures.append(what)


def run(fn, *args):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        n = fn(*args)
    return n, out.getvalue()


def check_context_terms():
    ctx = cp.context_terms()
    check(len(ctx.hashes) >= 20, "the shipped context-term list holds fewer than 20 terms")
    for s in CONTEXT_FLAG:
        check(ctx.find(s), f"context term not found in {s!r}")
    for s in CONTEXT_PASS:
        check(not ctx.find(s), f"context term wrongly found in {s!r}")


def main():
    check_context_terms()
    salt, hashes = cp.load_terms()
    check(len(hashes) >= 2, "the shipped hashed list holds fewer than two names")
    terms = cp.Terms(salt, hashes | {cp.term_hash(salt, PLANT)})
    with tempfile.TemporaryDirectory() as repo:
        git(repo, "init", "-q", "-b", "main")
        put(repo, "docs/a.md", "public text\n")
        c1 = commit(repo, "add the first page")
        put(repo, "docs/b.md", "notes from the Zq-PlantedName workspace\n")
        put(repo, "docs/c.md", "see BUILD" + "_PLAN for details\n")  # split, so this file passes the scan
        put(repo, "apps/site/page.md", "hosted by zq-plantedname\n")  # untracked-only exemptions do not apply to commits
        put(repo, "docs/d.md", "written for the " + CONTEXT + "\n")
        c2 = commit(repo, "add notes kept in " + PLANT)
        os.remove(os.path.join(repo, "docs/b.md"))
        os.remove(os.path.join(repo, "docs/c.md"))
        os.remove(os.path.join(repo, "apps/site/page.md"))
        os.remove(os.path.join(repo, "docs/d.md"))
        c3 = commit(repo, "drop the notes")
        cwd = os.getcwd()
        os.chdir(repo)
        try:
            all_cats = set(cp.CATEGORIES)
            n, out = run(cp.scan_revs, terms, cp.rev_list("main"), all_cats, "t")
            check(n == 4, f"--revs: want 4 problems (planted name twice, label, context term), got {n}:\n{out}")
            check(f"FAIL {c2[:12]} docs/d.md:1: [context]" in out, f"--revs: planted context term not found:\n{out}")
            check(CONTEXT not in out, "--revs printed the context term")
            check(f"FAIL {c2[:12]} apps/site/page.md:1: [private]" in out, f"--revs: name under apps/ not found:\n{out}")
            check(f"FAIL {c2[:12]} docs/b.md:1: [private]" in out, f"--revs: planted name not found at {c2[:12]}:\n{out}")
            check(f"FAIL {c2[:12]} docs/c.md:1: [labels]" in out, f"--revs: planted label not found:\n{out}")
            check(PLANT not in out.lower(), "--revs printed the private name")
            n, out = run(cp.scan_revs, terms, cp.rev_list("main"), all_cats - {"labels"}, "t")
            check(n == 3 and "labels 0" not in out, f"--categories without labels: want 3 problems, got {n}:\n{out}")
            n, out = run(cp.scan_revs, terms, cp.rev_list(c3 + "^!"), all_cats, "t")
            check(n == 0, f"--rev at the tip: want 0, got {n}:\n{out}")
            n, out = run(cp.scan_revs, terms, cp.rev_list(c1 + "^!"), all_cats, "t")
            check(n == 0, f"--rev at the first commit: want 0, got {n}:\n{out}")
            n, out = run(cp.scan_messages, terms, cp.rev_list("main"), all_cats)
            check(n == 1 and f"FAIL {c2[:12]} message: [private]" in out, f"--messages: want the planted message, got {n}:\n{out}")
            check(PLANT not in out.lower(), "--messages printed the private name")
            # The command line: a range that would read as an option is refused; a label in history fails.
            script = os.path.join(HERE, "check_public.py")
            r = subprocess.run([sys.executable, script, "--revs", "--all"], capture_output=True, text=True)
            check(r.returncode != 0 and "not a revision range" in r.stdout + r.stderr, f"--revs --all accepted: {r.stdout}{r.stderr}")
            r = subprocess.run([sys.executable, script, "--revs", "main"], capture_output=True, text=True)
            check(r.returncode == 1 and "[labels]" in r.stdout, f"--revs main: exit {r.returncode}\n{r.stdout}{r.stderr}")
            r = subprocess.run([sys.executable, script, "--rev", "main"], capture_output=True, text=True)
            check(r.returncode == 0, f"--rev main: exit {r.returncode}\n{r.stdout}{r.stderr}")
        finally:
            os.chdir(cwd)
    for f in failures:
        print("FAIL " + f)
    print(f"history scan self-test: planted name, label, context term and message checked, {len(failures)} problems")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""The repository's own rules for CI files, on top of actionlint (run by scripts/ci/check-workflows.sh).

Workflows (.github/workflows/*.yml) and local actions (.github/actions/*/action.yml):
- every `uses:` is a local action, or an allowed action pinned by a full commit SHA with its version in a
  trailing comment (`# v1.2.3`); one SHA per action across all files;
- every version-like string (x.y.z) outside those comments appears in pins.toml.
Workflows only:
- token permissions are exactly `contents: read` at the top, and no job asks for more, except the scopes
  .github/write-jobs.toml grants a named job (one stanza per job: workflow, job, scopes, why); every stanza
  names a job that exists;
- no `pull_request_target`, no `secrets.` context, no `continue-on-error`, no `*-latest` runner;
- every job has an explicit `timeout-minutes`;
- every job runs exactly one documented `make` target (a target of the Makefile or of an included mk/*.mk with a
  `##` description), or, for a
  check that has no target yet, exactly one placeholder script under scripts/ci/ and no `make`;
- a workflow whose jobs split `make test-drivers` with DRIVERS=a,b covers every directory under drivers/ with a
  Makefile (or, for DIR@VERSION items, every version its Makefile lists), unless one of its jobs runs
  `make test-drivers` without DRIVERS.
Exit 1 on any failure. `--self-test` runs the rules against a planted tree (one violation per rule, and one
clean workflow) and exits 1 unless each violation is reported and the clean file passes.
"""
import glob
import os
import re
import shutil
import sys
import tempfile
import tomllib

import yaml

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
ALLOWED = re.compile(r"^(actions/[A-Za-z0-9_.-]+|jdx/mise-action)(/[A-Za-z0-9_./-]+)?$")
USES = re.compile(r"^\s*(?:-\s+)?uses:\s*([^\s#]+)\s*(?:#\s*(.*?))?\s*$")
VERSION_COMMENT = re.compile(r"^v\d+(\.\d+)*$")
VERSION = re.compile(r"(?<![\w.])v?(\d+\.\d+\.\d+)(?![\w.])")
MAKE_CALL = re.compile(r"(?<![\w/.-])make((?:[ \t]+[^\s;&|]+)*)")
PLACEHOLDER = re.compile(r"(?<![\w/.-])scripts/ci/([a-z0-9-]+)\.sh(?![\w.-])")

errors = []
WRITE_JOB_KEYS = {"workflow", "job", "scopes", "why"}


def write_jobs():
    """(workflow file, job) -> the permission scopes that job may write, from .github/write-jobs.toml. Nothing
    else may ask for write access."""
    path = os.path.join(ROOT, ".github", "write-jobs.toml")
    if not os.path.isfile(path):
        return {}
    with open(path, "rb") as f:
        doc = tomllib.load(f)
    out = {}
    if set(doc) - {"job"}:
        fail(path, f"unknown top-level keys {sorted(set(doc) - {'job'})}")
    for i, st in enumerate(doc.get("job", []), 1):
        if set(st) != WRITE_JOB_KEYS:
            fail(path, f"stanza {i}: keys must be exactly {sorted(WRITE_JOB_KEYS)}, has {sorted(st)}")
            continue
        key = (st["workflow"], st["job"])
        if key in out:
            fail(path, f"stanza {i}: {key[0]} job {key[1]} listed twice")
        if not st["why"].strip() or not st["scopes"]:
            fail(path, f"stanza {i}: empty scopes or why")
        out[key] = set(st["scopes"])
    return out


def fail(path, msg):
    errors.append(f"{os.path.relpath(path, ROOT)}: {msg}")


def documented_targets():
    """Targets with a `##` description in the Makefile and in the fragments it includes (mk/*.mk)."""
    targets = set()
    for path in [os.path.join(ROOT, "Makefile")] + sorted(glob.glob(os.path.join(ROOT, "mk", "*.mk"))):
        with open(path) as f:
            for line in f:
                m = re.match(r"^([a-z][a-z0-9-]*):[^=].*##\s", line)
                if m:
                    targets.add(m.group(1))
    return targets


def check_text(path, pins_text, pinned):
    with open(path) as f:
        lines = f.read().split("\n")
    for n, line in enumerate(lines, 1):
        m = USES.match(line)
        body = line
        if m:
            ref, comment = m.group(1), m.group(2)
            body = line[: line.index(ref) + len(ref)]
            if ref.startswith("./"):
                if not glob.glob(os.path.join(ROOT, ref, "action.y*ml")):
                    fail(path, f"line {n}: local action {ref} has no action.yml")
            elif ref.startswith("docker://"):
                fail(path, f"line {n}: container actions are not allowed: {ref}")
            else:
                action, _, sha = ref.partition("@")
                if not ALLOWED.match(action):
                    fail(path, f"line {n}: {action} is not a GitHub-maintained action or jdx/mise-action")
                if not re.fullmatch(r"[0-9a-f]{40}", sha):
                    fail(path, f"line {n}: {ref} is not pinned by a full commit SHA")
                if not comment or not VERSION_COMMENT.match(comment):
                    fail(path, f"line {n}: {ref} has no trailing version comment such as `# v1.2.3`")
                repo = "/".join(action.split("/")[:2])
                seen = pinned.setdefault(repo, (sha, comment, path, n))
                if seen[:2] != (sha, comment):
                    fail(path, f"line {n}: {repo} pinned as {sha} {comment}, elsewhere as {seen[0]} {seen[1]}")
        for v in VERSION.finditer(body):
            if v.group(1) not in pins_text:
                fail(path, f"line {n}: version {v.group(0)} is not in pins.toml")


def is_placeholder(name):
    script = os.path.join(ROOT, "scripts", "ci", name + ".sh")
    return os.path.isfile(script) and "not implemented yet" in open(script).read()


def run_texts(job):
    return [s["run"] for s in job.get("steps") or [] if isinstance(s, dict) and isinstance(s.get("run"), str)]


def check_workflow(path, targets, granted):
    with open(path) as f:
        text = f.read()
    doc = yaml.safe_load(text)
    on = doc.get("on", doc.get(True))  # YAML 1.1 reads the key `on` as true
    events = on if isinstance(on, (dict, list)) else [on]
    if "pull_request_target" in events:
        fail(path, "pull_request_target is not allowed")
    if doc.get("permissions") != {"contents": "read"}:
        fail(path, "top-level permissions must be exactly `contents: read`")
    if re.search(r"\bsecrets\.", text):
        fail(path, "uses the secrets context; CI needs no secrets")
    if re.search(r"^\s*continue-on-error:", text, re.M):
        fail(path, "continue-on-error hides failures")
    driver_jobs = []  # per job running make test-drivers: the DRIVERS it names, or None for all
    for name, job in (doc.get("jobs") or {}).items():
        where = f"job {name}"
        if "timeout-minutes" not in job:
            fail(path, f"{where} has no timeout-minutes")
        perms = job.get("permissions")
        may_write = granted.get((os.path.basename(path), name), set())
        if perms is not None and (not isinstance(perms, dict) or any(
                v not in ("read", "none") and not (v == "write" and k in may_write) for k, v in perms.items())):
            fail(path, f"{where} asks for more than read permissions")
        runs_on = str(job.get("runs-on", ""))
        if "latest" in runs_on:
            fail(path, f"{where} runs on a floating image ({runs_on})")
        runs = run_texts(job)
        # Each make call's targets: its arguments that are neither options nor variable assignments.
        calls = [[a for a in m.group(1).split() if not a.startswith("-") and "=" not in a]
                 for r in runs for m in MAKE_CALL.finditer(r)]
        stubs = [m.group(1) for r in runs for m in PLACEHOLDER.finditer(r) if is_placeholder(m.group(1))]
        if not calls and len(stubs) == 1:
            continue
        if stubs:
            fail(path, f"{where} runs placeholder(s) {stubs} besides other commands")
        if len(calls) != 1 or len(calls[0]) != 1:
            fail(path, f"{where} must run exactly one make target, runs {calls}")
        elif calls[0][0] not in targets:
            fail(path, f"{where} runs make {calls[0][0]}, which is not a documented Makefile target")
        elif calls[0][0] == "test-drivers":
            picked = [m.group(1) for r in runs for m in re.finditer(r"(?<![\w])DRIVERS=([\w.,@-]+)", r)]
            driver_jobs.append(set(",".join(picked).split(",")) - {""} if picked else None)
    if driver_jobs and None not in driver_jobs:
        picked = set().union(*driver_jobs)
        missing = []
        for mk in sorted(glob.glob(os.path.join(ROOT, "drivers", "*", "Makefile"))):
            d = os.path.basename(os.path.dirname(mk))
            if d in picked:
                continue
            # DIR@VERSION items cover the directory when they name every version its Makefile lists in VERSIONS.
            m = re.search(r"^VERSIONS\s*:?=\s*(.*)$", open(mk).read(), re.M)
            versions = m.group(1).split() if m else []
            gone = [v for v in versions if f"{d}@{v}" not in picked]
            if not versions or gone:
                missing.append(d if not versions or len(gone) == len(versions) else f"{d}@{','.join(gone)}")
        if missing:
            fail(path, f"the jobs running make test-drivers with DRIVERS leave out {', '.join(missing)}")


def run():
    with open(os.path.join(ROOT, "pins.toml")) as f:
        pins_text = f.read()
    targets = documented_targets()
    workflows = sorted(glob.glob(os.path.join(ROOT, ".github", "workflows", "*.y*ml")))
    actions = sorted(glob.glob(os.path.join(ROOT, ".github", "actions", "*", "action.y*ml")))
    if not workflows:
        fail(os.path.join(ROOT, ".github", "workflows"), "no workflow files")
    pinned = {}
    granted = write_jobs()
    for path in workflows + actions:
        check_text(path, pins_text, pinned)
    jobs = set()
    for path in workflows:
        check_workflow(path, targets, granted)
        with open(path) as f:
            doc = yaml.safe_load(f) or {}
        jobs |= {(os.path.basename(path), j) for j in (doc.get("jobs") or {})}
    for wf, job in sorted(set(granted) - jobs):
        fail(os.path.join(ROOT, ".github", "write-jobs.toml"), f"grants {wf} job {job}, which does not exist")
    return workflows, actions


CLEAN = """name: clean
on:
  workflow_dispatch:
permissions:
  contents: read
jobs:
  ok:
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    permissions:
      issues: write
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - run: make frag-target
"""
# file -> (workflow text, a fragment of the problem it must produce)
PLANTED = {
    "unpinned.yml": (CLEAN.replace("@3d3c42e5aac5ba805825da76410c181273ba90b1", "@v7"), "not pinned by a full commit SHA"),
    "foreign.yml": (CLEAN.replace("actions/checkout", "someone/checkout"), "not a GitHub-maintained action"),
    "notimeout.yml": (CLEAN.replace("    timeout-minutes: 5\n", ""), "has no timeout-minutes"),
    "write.yml": (CLEAN, "asks for more than read permissions"),
    "toplevel.yml": (CLEAN.replace("  contents: read\njobs", "  contents: write\njobs"), "top-level permissions"),
    "secret.yml": (CLEAN.replace("make frag-target", "make frag-target ${{ secrets.X }}"), "secrets context"),
    "target.yml": (CLEAN.replace("make frag-target", "make undocumented"), "not a documented Makefile target"),
    "latest.yml": (CLEAN.replace("ubuntu-24.04", "ubuntu-latest"), "floating image"),
    "drivers.yml": (CLEAN.replace("    permissions:\n      issues: write\n", "").replace("make frag-target", "make test-drivers DRIVERS=a"),
                    "leave out b"),
}


def self_test():
    global ROOT
    real = ROOT
    failed = 0
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, ".github", "workflows"))
        os.makedirs(os.path.join(d, "mk"))
        shutil.copy(os.path.join(real, "pins.toml"), d)
        with open(os.path.join(d, "Makefile"), "w") as f:
            f.write("include $(sort $(wildcard mk/*.mk))\n")
        with open(os.path.join(d, "mk", "a.mk"), "w") as f:
            f.write("frag-target: ## a target from a fragment\n\ttrue\ntest-drivers: ## driver tests\n\ttrue\n")
        for drv in ("a", "b"):
            os.makedirs(os.path.join(d, "drivers", drv))
            open(os.path.join(d, "drivers", drv, "Makefile"), "w").close()
        with open(os.path.join(d, ".github", "write-jobs.toml"), "w") as f:
            f.write('[[job]]\nworkflow = "clean.yml"\njob = "ok"\nscopes = ["issues"]\nwhy = "self-test"\n\n'
                    '[[job]]\nworkflow = "gone.yml"\njob = "ok"\nscopes = ["issues"]\nwhy = "self-test"\n')
        for name, text in [("clean.yml", CLEAN)] + [(n, t) for n, (t, _) in PLANTED.items()]:
            with open(os.path.join(d, ".github", "workflows", name), "w") as f:
                f.write(text)
        ROOT = d
        errors.clear()
        try:
            run()
        finally:
            ROOT = real
        got = list(errors)
        errors.clear()
    expect = {**{n: w for n, (_, w) in PLANTED.items()}, "write-jobs.toml": "does not exist"}
    for name, want in expect.items():
        if not any(e.split(":")[0].endswith(name) and want in e for e in got):
            print(f"self-test: {name}: expected a problem containing {want!r}; got {got}", file=sys.stderr)
            failed = 1
    clean = [e for e in got if e.split(":")[0].endswith("clean.yml")]
    if clean:
        print(f"self-test: the clean workflow was rejected: {clean}", file=sys.stderr)
        failed = 1
    print("check_workflows self-test: FAILED" if failed else
          f"check_workflows self-test: {len(expect)} planted problems reported, the clean workflow passes")
    return failed


def main(args):
    if args == ["--self-test"]:
        return self_test()
    if args:
        print(__doc__, file=sys.stderr)
        return 2
    workflows, actions = run()
    for e in errors:
        print(f"FAIL {e}")
    print(f"workflow rules: {len(workflows)} workflows, {len(actions)} local actions, {len(errors)} problems")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

#!/usr/bin/env python3
"""Run each SDK CI recipe (examples/sdk-ci/<lang>/workflow.yml) the way an SDK maintainer would, offline, so the
recipes cannot rot.

For each language this lays out a scratch "SDK repository": the pinned SDK's own source (or, where the source is
not in the caches, its built package) at the root, the recipe's files where the workflow's header says to copy them,
and the in-repository wiring the recipe's comments ask for (Go: `replace github.com/stellar/go-stellar-sdk => ../`;
Rust: `stellar-xdr = { path = ".." }` and the lock file refreshed; Python: the SDK installed from the "checkout"
over the hash-pinned dependencies; JavaScript: the runner pointed at the SDK's own package directory with `--sdk .`).
Then it runs the workflow's own test step, its `run:` text taken from workflow.yml and executed verbatim in its
`working-directory`, with the corpus release replaced by this repository's corpus. Network steps (checkout, the
toolchain set-up, the release download) are not run; nothing here uses the network.

Each language is checked twice:
  - as committed: the run must pass (exit 0): the SDK's failures are exactly its expected-failures.txt;
  - with a new divergence: it must fail (exit 1; cargo test: 101) and name it NEW-FAILURE. Go: the working tree's ScVal decoder
    is patched to accept a value type the XDR does not declare; JavaScript: the 16.x line's package is the
    working tree (it refuses values nested deeper than its decoder allows); Rust and Python: the expected-failure
    list loses its lines (the SDK's real divergence is then new).

Usage: check_recipes.py [--work DIR] [LANG ...]    LANG: go rust python js (default all)

Needs the caches `make fetch-sdk` fills under $XDRCHECK_CACHE (default ~/.cache/xdrcheck): the go-stellar-sdk
driver's module cache, the Python driver's wheelhouse, the JavaScript drivers' npm caches, and stellar-xdr in the
cargo registry. Exit codes: 0 every recipe behaved, 1 one did not, 2 a cache or file is missing.
"""
import argparse, glob, os, re, shutil, stat, subprocess, sys, tomllib

import yaml

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
EX = os.path.join(ROOT, "examples", "sdk-ci")
CACHE = os.environ.get("XDRCHECK_CACHE") or os.path.expanduser("~/.cache/xdrcheck")
CORPUS = os.path.join(ROOT, "corpus")


class Missing(Exception):
    pass


def log(msg):
    print(f"check_recipes: {msg}", flush=True)


def need(path, what):
    if not os.path.exists(path):
        raise Missing(f"{what}: {path} is not there (make fetch-sdk)")
    return path


def copytree(src, dst):
    shutil.copytree(src, dst, symlinks=True)
    os.chmod(dst, os.stat(dst).st_mode | stat.S_IWUSR)
    for d, dirs, files in os.walk(dst):
        for n in dirs + files:
            p = os.path.join(d, n)
            if not os.path.islink(p):
                os.chmod(p, os.stat(p).st_mode | stat.S_IWUSR)


def toolchains():
    """The scratch repositories live outside this one, where a version manager would pick other toolchains: use
    the ones this repository pins (Go from its go.mod's toolchain as resolved here, Rust from rust-toolchain.toml)."""
    goroot = subprocess.run(["go", "env", "GOROOT"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()
    os.environ["PATH"] = os.path.join(goroot, "bin") + os.pathsep + os.environ["PATH"]
    with open(os.path.join(ROOT, "rust-toolchain.toml"), "rb") as f:
        os.environ["RUSTUP_TOOLCHAIN"] = tomllib.load(f)["toolchain"]["channel"]


def rmtree(path):
    """Remove a scratch tree, read-only module cache copies included."""
    for d, dirs, _ in os.walk(path):
        for n in dirs:
            p = os.path.join(d, n)
            if not os.path.islink(p):
                os.chmod(p, os.stat(p).st_mode | stat.S_IWUSR)
    shutil.rmtree(path, ignore_errors=True)


def test_step(lang):
    """The workflow's test step: the one whose name starts with "Run the corpus"."""
    with open(os.path.join(EX, lang, "workflow.yml")) as f:
        wf = yaml.safe_load(f)
    (job,) = wf["jobs"].values()
    steps = [s for s in job["steps"] if str(s.get("name", "")).startswith("Run the corpus")]
    if len(steps) != 1:
        raise Missing(f"{lang}/workflow.yml: expected one step named 'Run the corpus…', found {len(steps)}")
    env = {}
    for scope in (wf.get("env"), job.get("env"), steps[0].get("env")):
        env.update({k: str(v) for k, v in (scope or {}).items()})
    return steps[0]["run"], steps[0].get("working-directory", "."), env


def run_step(lang, repo, override, expect, needle=None):
    """Run the workflow's test step in the scratch repository; check its exit code (and output)."""
    script, wd, env = test_step(lang)
    for k, v in list(env.items()):
        if k in override:
            continue
        if "${{" in v:
            raise Missing(f"{lang}/workflow.yml: env {k} uses an expression the check does not provide: {v}")
    full = dict(os.environ)
    full.update(env)
    for k, v in override.items():
        if v is None:
            full.pop(k, None)
        else:
            full[k] = v
    cwd = os.path.join(repo, wd)
    p = subprocess.run(["bash", "-euo", "pipefail", "-c", script], cwd=cwd, env=full,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    out = p.stdout
    ok = p.returncode == expect and (needle is None or needle in out)
    tail = "\n".join(out.rstrip().splitlines()[-12:])
    if not ok:
        log(f"{lang}: expected exit {expect}{f' and {needle!r}' if needle else ''}, got exit {p.returncode}:\n{tail}")
        return False
    lines = [l for l in out.splitlines() if "expected failures" in l or "NEW-FAILURE" in l or l.startswith("entries ")]
    log(f"{lang}: exit {p.returncode} as expected; " + (lines[-1].strip() if lines else tail.splitlines()[-1]))
    return True


def sh(args, cwd, env=None):
    full = dict(os.environ)
    full.update(env or {})
    subprocess.run(args, cwd=cwd, env=full, check=True)


# ---------------------------------------------------------------- Go

def go_version():
    with open(os.path.join(EX, "go", "go.mod")) as f:
        m = re.search(r"^\s*github\.com/stellar/go-stellar-sdk (\S+)", f.read(), re.M)
    return m.group(1)


def check_go(work):
    v = go_version()
    modcache = need(os.path.join(CACHE, "conform", f"drivers-go-{v}", "gomod"), "go-stellar-sdk module cache")
    src = need(os.path.join(modcache, "github.com", "stellar", f"go-stellar-sdk@{v}"), "go-stellar-sdk source")
    repo = os.path.join(work, "go", "go-stellar-sdk")
    copytree(src, repo)
    dst = os.path.join(repo, "xdrcheck")
    os.makedirs(dst)
    for n in ("go.mod", "go.sum", "corpus_test.go", "expected-failures.txt"):
        shutil.copy(os.path.join(EX, "go", n), dst)
    # The recipe's go.mod comment: replace the SDK with the repository itself; the loader, which the SDK's
    # repository pins by commit (network), comes from this repository instead.
    sh(["go", "mod", "edit", "-replace", "github.com/stellar/go-stellar-sdk=../",
        "-replace", f"github.com/tolgayayci/xdrcheck/packages/go={ROOT}/packages/go"], dst)
    env = {"XDRCHECK_CORPUS": CORPUS, "GOPROXY": "off", "GOFLAGS": "-mod=readonly", "GOMODCACHE": modcache,
           "GOTOOLCHAIN": "local"}
    ok = run_step("go", repo, env, 0)
    # A regression in the working tree: ScVal decoding stops refusing a type the XDR does not declare.
    gen = os.path.join(repo, "xdr", "xdr_generated.go")
    with open(gen) as f:
        text = f.read()
    patched = text.replace("if _, ok := scValTypeMap[v]; !ok {", "if _, ok := scValTypeMap[v]; false && !ok {", 1)
    patched = patched.replace('return n, fmt.Errorf("union ScVal has invalid Type (ScValType) switch value \'%d\'", u.Type)',
                              "return n, nil", 1)
    if patched.count("false && !ok") != 1 or "union ScVal has invalid Type" in patched:
        raise Missing("go: xdr/xdr_generated.go no longer has the ScVal checks this check patches")
    with open(gen, "w") as f:
        f.write(patched)
    ok &= run_step("go", repo, env, 1, "NEW-FAILURE")
    return ok


# ---------------------------------------------------------------- Rust

def rust_version():
    with open(os.path.join(EX, "rust", "Cargo.toml"), "rb") as f:
        return tomllib.load(f)["dev-dependencies"]["stellar-xdr"]["version"].lstrip("=")


def check_rust(work):
    v = rust_version()
    cargo_home = os.environ.get("CARGO_HOME") or os.path.expanduser("~/.cargo")
    srcs = (glob.glob(os.path.join(cargo_home, "registry", "src", "*", f"stellar-xdr-{v}"))
            + glob.glob(os.path.join(CACHE, "conform", f"drivers-rust-{v}", "cargo", "registry", "src", "*", f"stellar-xdr-{v}")))
    if not srcs:
        raise Missing(f"rust: stellar-xdr {v} is not in the cargo registry (make fetch-sdk)")
    repo = os.path.join(work, "rust", "rs-stellar-xdr")
    copytree(srcs[0], repo)
    dst = os.path.join(repo, "xdrcheck")
    os.makedirs(os.path.join(dst, "tests"))
    for n in ("Cargo.toml", "Cargo.lock", "lib.rs", "expected-failures.txt"):
        shutil.copy(os.path.join(EX, "rust", n), dst)
    shutil.copy(os.path.join(EX, "rust", "tests", "corpus.rs"), os.path.join(dst, "tests"))
    # The recipe's Cargo.toml comment: stellar-xdr is the library itself (same features); the loader, which the
    # library's repository pins as a git dependency, comes from this repository.
    toml = os.path.join(dst, "Cargo.toml")
    with open(toml) as f:
        text = f.read()
    text2 = re.sub(r'stellar-xdr = \{ version = "=[^"]+",', 'stellar-xdr = { path = "..",', text)
    text2 = text2.replace('path = "../../../packages/rust"', f'path = "{ROOT}/packages/rust"')
    if text2 == text or 'path = ".."' not in text2:
        raise Missing("rust: Cargo.toml has no stellar-xdr version line to point at the library")
    with open(toml, "w") as f:
        f.write(text2)
    target = os.path.join(ROOT, "target", "sdk-ci-recipes")
    env = {"XDRCHECK_CORPUS": CORPUS, "CARGO_NET_OFFLINE": "true", "CARGO_TARGET_DIR": target}
    # The lock file refreshed once for the path dependency, as the recipe asks.
    sh(["cargo", "update", "--offline", "-p", "stellar-xdr"], dst, env)
    ok = run_step("rust", repo, env, 0)
    clear_list(os.path.join(dst, "expected-failures.txt"))
    ok &= run_step("rust", repo, env, 101, "NEW-FAILURE")  # cargo test's exit code for a failed test
    return ok


def clear_list(path):
    with open(path) as f:
        lines = [l for l in f if l.startswith("#") or not l.strip()]
    with open(path, "w") as f:
        f.writelines(lines)


# ---------------------------------------------------------------- Python

def check_python(work):
    with open(os.path.join(EX, "python", "requirements.txt")) as f:
        reqs = f.read()
    v = re.search(r"^stellar-sdk==(\S+)", reqs, re.M).group(1)
    wheels = need(os.path.join(CACHE, "conform", f"drivers-python-{v}", "wheels"), "stellar-sdk wheelhouse")
    (wheel,) = glob.glob(os.path.join(wheels, f"stellar_sdk-{v}-*.whl")) or [None]
    if wheel is None:
        raise Missing(f"python: no stellar_sdk {v} wheel in {wheels}")
    repo = os.path.join(work, "python", "py-stellar-base")
    dst = os.path.join(repo, "tests", "corpus")
    os.makedirs(dst)
    for n in ("test_corpus.py", "expected-failures.txt", "requirements.txt"):
        shutil.copy(os.path.join(EX, "python", n), dst)
    py = sys.executable
    venv = os.path.join(repo, ".venv")
    sh([py, "-I", "-m", "venv", venv], repo)
    pip = [os.path.join(venv, "bin", "python"), "-I", "-m", "pip", "install", "--isolated", "--disable-pip-version-check",
           "--quiet", "--no-index", "--find-links", wheels]
    # The workflow's install step, offline: the pins without the stellar-sdk line, then the SDK "checkout" (the
    # source is not in the caches: its pinned wheel stands for `pip install --no-deps .`), then the loader.
    filtered = os.path.join(work, "python", "requirements.txt")
    with open(filtered, "w") as f:
        f.write("".join(l for l in reqs.splitlines(True) if not l.startswith("stellar-sdk==")))
    sh(pip + ["--require-hashes", "--only-binary=:all:", "-r", filtered], repo)
    sh(pip + ["--no-deps", wheel], repo)
    sh(pip + ["--no-deps", os.path.join(ROOT, "packages", "python")], repo)
    sh([os.path.join(venv, "bin", "python"), "-I", "-m", "pip", "check", "--disable-pip-version-check"], repo)
    env = {"XDRCHECK_CORPUS": CORPUS, "XDRCHECK_CORPUS_SHA256": None}
    ok = run_step("python", repo, env, 0)
    clear_list(os.path.join(dst, "expected-failures.txt"))
    ok &= run_step("python", repo, env, 1, "NEW-FAILURE")
    return ok


# ---------------------------------------------------------------- JavaScript

def pin(section, key):
    with open(os.path.join(ROOT, "pins.toml"), "rb") as f:
        return tomllib.load(f)[section][key]


def js_tree(work, name, family, version):
    """npm ci of the driver's committed lock file from its npm cache, offline; the SDK package is then copied out
    as the "working tree after its build", its dependencies resolved from the parent node_modules."""
    lock = need(os.path.join(ROOT, "drivers", family, version, "package-lock.json"), f"{family} {version} lock file")
    cache = need(os.path.join(CACHE, "conform", f"drivers-{family}-{version}", "npm"), f"{family} {version} npm cache")
    ci = os.path.join(work, "js", name)
    os.makedirs(ci)
    shutil.copy(lock, os.path.join(ci, "package-lock.json"))
    shutil.copy(os.path.join(ROOT, "drivers", family, version, "package.json"), ci)
    sh(["npm", "ci", "--offline", "--ignore-scripts", "--loglevel=warn", "--no-audit", "--no-fund"], ci,
       {"npm_config_cache": cache, "npm_config_update_notifier": "false", "npm_config_logs_dir": os.path.join(ci, ".npm-logs")})
    repo = os.path.join(ci, "js-stellar-sdk")
    copytree(os.path.join(ci, "node_modules", "@stellar", "stellar-sdk"), repo)
    os.makedirs(os.path.join(repo, "xdrcheck"))
    shutil.copy(os.path.join(EX, "js", "expected-failures.txt"), os.path.join(repo, "xdrcheck"))
    return repo


def runner(work):
    """The installed runner, as the workflow's install step leaves it: $RUNNER_TEMP/xdrcheck/node_modules/.bin/
    xdrcheck-corpus-run. Here it is this repository's runner reading this repository's corpus."""
    tmp = os.path.join(work, "js", "runner-temp")
    b = os.path.join(tmp, "xdrcheck", "node_modules", ".bin")
    os.makedirs(b)
    shim = os.path.join(b, "xdrcheck-corpus-run")
    with open(shim, "w") as f:
        f.write(f'#!/usr/bin/env bash\nexec node "{ROOT}/packages/npm/bin/xdrcheck-corpus-run.mjs" --dir "{ROOT}" "$@"\n')
    os.chmod(shim, 0o755)
    return tmp


def check_js(work):
    tmp = runner(work)
    repo = js_tree(work, "ci", "js", pin("js", "stellar_sdk"))
    ok = run_step("js", repo, {"RUNNER_TEMP": tmp}, 0)
    # The 16.x line as the working tree: it refuses values nested deeper than its decoder allows.
    lines = [d for d in os.listdir(os.path.join(ROOT, "drivers", "js16")) if re.match(r"^\d+\.\d+\.\d+$", d)]
    old = max(lines, key=lambda d: tuple(int(x) for x in d.split(".")))
    repo16 = js_tree(work, "ci16", "js16", old)
    ok &= run_step("js", repo16, {"RUNNER_TEMP": tmp}, 1, "NEW-FAILURE")
    return ok


CHECKS = {"go": check_go, "rust": check_rust, "python": check_python, "js": check_js}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--work", help="scratch directory (default: a fresh directory under target/)")
    ap.add_argument("langs", nargs="*", metavar="LANG", help="go, rust, python, js (default: all)")
    a = ap.parse_args()
    work = a.work or os.path.join(ROOT, "target", "sdk-ci-recipes-work")
    rmtree(work)
    os.makedirs(work)
    toolchains()
    bad = [l for l in a.langs if l not in CHECKS]
    if bad:
        log(f"unknown language {bad}; choose from {list(CHECKS)}")
        return 2
    ok = True
    try:
        for lang in a.langs or list(CHECKS):
            ok &= CHECKS[lang](work)
    except Missing as e:
        log(str(e))
        return 2
    except subprocess.CalledProcessError as e:
        log(f"a set-up command failed: {' '.join(map(str, e.cmd))} (exit {e.returncode})")
        return 1
    if ok:
        rmtree(work)
        log("every recipe passes as committed and fails on a new divergence")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Run the jobs of a CI workflow on this machine the way a hosted runner would, from cold caches.

    scripts/ci/run-local.sh --tier pr|full [--job ID ...] [--sha REV] [--out DIR] [--parallel N] [--keep]
                            [--reuse EARLIER_OUT] [--cpus PAIRS]
    scripts/ci/run_local.py --self-test     (--reuse's artifact selection against a planted earlier run)

For each job of .github/workflows/pr.yml (tier pr) or full.yml (tier full), and the jobs it needs, in `needs:`
order:

1. a fresh clone of the commit under test (`git clone` of the repository, then that commit checked out): no build
   output, no ignored file, no file another job left behind;
2. a home directory of its own (HOME, with XDG_* unset): an empty kit cache, Go module and build caches, cargo
   registry, npm and pip caches. The job gets only what its `setup` step declares: `make fetch FETCH_ONLY=<the
   fetch: parts>` runs into that empty home (the network step, as on the runner), the `tools` artifact of the build
   job when `tools: "true"`, the downloaded report artifacts its steps ask for. Nothing is restored from a cache
   (GitHub's cache restore is not emulated: every run here is the cold, first run), so a job that reads an input
   its fetch parts do not provide fails here as it would on a cold runner;
3. the hosted runner's limits: 2 CPUs (taskset) and 7 GiB of memory without swap (a systemd user scope) for every
   step, and the job directory's size sampled while it runs, reported against the runner's free disk (about 13 GB,
   35 GB after the setup's free-disk step, which is not emulated: nothing is removed here);
4. every `run:` step exactly as the workflow writes it (bash -eo pipefail, the workflow, job and step `env:`, and
   GITHUB_ENV/GITHUB_OUTPUT/GITHUB_STEP_SUMMARY files), with `if:` conditions evaluated (success(), failure(),
   always(), !cancelled(), steps.*.outcome, needs.*.result, github.ref_type); after the setup the offline
   variables the setup action sets (GOPROXY=off, GOTOOLCHAIN=local, CARGO_NET_OFFLINE, PIP_NO_INDEX) apply and the
   job's make step runs with OFFLINE=1 as written (scripts/offline-run.sh: no network). `uses:` steps: checkout is
   the fresh clone; the setup action is emulated step by step (fetch, offline check, offline build); upload and
   download of artifacts copy to and from <out>/artifacts/<name>; cache save and restore are skipped. After each
   upload the uploaded copy is scanned for sites pending finding review (scripts/ci/withhold-pending.py on a copy):
   anything it would still withhold is a leak and fails the job.

Docker is the machine's own daemon (images already pulled stay; the runner pulls them by digest during the fetch).

Output under --out (default a new directory under $TMPDIR): <job>/log.txt per job, artifacts/, and summary.md and
summary.json: per job its result, wall time, the time of its fetch, the job directory's peak size and the notes of
what could not be emulated. Job directories are removed after each job unless --keep. Exit 0 when every job that ran
succeeded, 1 otherwise, 2 on a usage error.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time

import yaml

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
RUNNER_DISK_GB, RUNNER_DISK_FREED_GB = 13, 35
MEM = "7G"


def sh(cmd, **kw):
    return subprocess.run(cmd, shell=isinstance(cmd, str), check=True, text=True, capture_output=True, **kw).stdout


class Expr:
    """The few GitHub expressions the workflows use, evaluated in Python."""

    def __init__(self, job):
        self.job = job

    def ctx(self, name):
        j = self.job
        if name.startswith("steps."):
            parts = name.split(".")
            st = j.steps_state.get(parts[1], {})
            if parts[2] == "outcome" or parts[2] == "conclusion":
                return st.get("outcome", "")
            if parts[2] == "outputs":
                return st.get("outputs", {}).get(parts[3], "")
        if name.startswith("needs."):
            parts = name.split(".")
            return j.runner.results.get(parts[1], {}).get("result", "")
        if name.startswith("inputs."):
            return j.inputs.get(name.split(".", 1)[1], "")
        fixed = {
            "github.ref_type": "branch", "github.ref_name": "main", "github.ref": "refs/heads/main",
            "github.job": j.id, "github.server_url": "https://github.com", "github.repository": "local/run",
            "github.run_id": "0", "github.event.repository.default_branch": "main",
            "github.event.pull_request.number": "", "github.sha": j.runner.sha,
            "runner.temp": j.runner_temp, "runner.os": "Linux",
        }
        if name in fixed:
            return fixed[name]
        j.note(f"expression {name} is not emulated; read as empty")
        return ""

    def eval(self, text, default_status=True):
        if text is None or text == "":
            return self.job.status_ok() if default_status else True
        t = str(text).strip()
        if t.startswith("${{") and t.endswith("}}"):
            t = t[3:-2].strip()
        status = {"success()": self.job.status_ok(), "failure()": not self.job.status_ok(), "always()": True,
                  "cancelled()": False}
        has_status = any(f in t for f in status)
        for f, v in status.items():
            t = t.replace(f, " True " if v else " False ")
        t = re.sub(r"\b(steps|needs|inputs|github|runner)(\.[\w-]+)+", lambda m: repr(self.ctx(m.group(0))), t)
        t = t.replace("&&", " and ").replace("||", " or ")
        t = re.sub(r"!(?!=)", " not ", t)
        t = re.sub(r"\bcontains\(", "_contains(", t)
        v = eval(t, {"__builtins__": {}, "_contains": lambda a, b: b in a, "True": True, "False": False})
        if not has_status:
            v = v and self.job.status_ok()
        return v

    def sub(self, text):
        """${{ expr }} in a string: contexts and `a && 'x' || 'y'` forms."""
        def one(m):
            inner = m.group(1).strip()
            mm = re.fullmatch(r"(.+?)\s*&&\s*'([^']*)'\s*\|\|\s*'([^']*)'", inner)
            if mm:
                return mm.group(2) if self.eval(mm.group(1), default_status=False) else mm.group(3)
            if re.fullmatch(r"[\w.-]+", inner):
                return str(self.ctx(inner))
            self.job.note(f"expression {inner} is not emulated; read as empty")
            return ""
        return re.sub(r"\$\{\{(.*?)\}\}", one, str(text))


class Job:
    def __init__(self, runner, jid, spec, cpus):
        self.runner, self.id, self.spec, self.cpus = runner, jid, spec, cpus
        self.dir = os.path.join(runner.out, "jobs", jid)
        self.ws = os.path.join(self.dir, "ws")
        self.home = os.path.join(self.dir, "home")
        self.runner_temp = os.path.join(self.dir, "runner-temp")
        self.log_path = os.path.join(runner.out, "logs", jid + ".log")
        self.steps_state, self.inputs, self.notes, self.failed = {}, {}, [], False
        self.env = {}
        self.peak = 0
        self.fetch_s = 0.0
        self.expr = Expr(self)

    def note(self, msg):
        if msg not in self.notes:
            self.notes.append(msg)

    def status_ok(self):
        return not self.failed

    def log(self, msg):
        with open(self.log_path, "a") as f:
            f.write(msg.rstrip("\n") + "\n")

    # --- environment ---------------------------------------------------------------------------------------------
    def base_env(self):
        real = os.environ
        env = {k: v for k, v in real.items() if not k.startswith(("XDG_", "XDRCHECK_", "XCC_", "GO", "CARGO_",
                                                                     "npm_", "PIP_", "VIRTUAL_ENV", "MISE_"))
               and k not in ("PY", "MAKEFLAGS", "MAKELEVEL", "MFLAGS", "MAKEOVERRIDES", "OLDPWD", "PWD", "OFFLINE",
                             "REPORTS", "CORPUS", "MUTATE", "XDRCHECK", "XDRLINT", "TIER", "JOB", "SHA", "PARALLEL")}
        env.update({
            "HOME": self.home, "CI": "true", "GITHUB_ACTIONS": "true", "GITHUB_WORKSPACE": self.ws,
            "RUNNER_TEMP": self.runner_temp, "RUNNER_OS": "Linux", "GITHUB_JOB": self.id,
            "RUSTUP_HOME": real.get("RUSTUP_HOME", os.path.join(real["HOME"], ".rustup")),
            "CARGO_HOME": os.path.join(self.home, ".cargo"),
            "MISE_DATA_DIR": real.get("MISE_DATA_DIR", os.path.join(real["HOME"], ".local", "share", "mise")),
            "MISE_TRUSTED_CONFIG_PATHS": self.ws, "MISE_YES": "1",
        })
        cargo_bin = os.path.join(real.get("CARGO_HOME", os.path.join(real["HOME"], ".cargo")), "bin")
        # The hosted image's python3 can make a virtual environment; where this machine's cannot (no ensurepip),
        # python3 is the pinned mise Python, first on PATH even after a script evals `mise env` (which keeps PATH's
        # leading entries and appends the toolchains).
        shim = os.path.join(self.dir, "bin")
        if not os.path.isdir(shim):
            os.makedirs(shim)
            py = next((os.path.join(d, "python3") for d in self.runner.mise_path(self.ws, env).split(":")
                       if "/mise/installs/python/" in d and os.path.isfile(os.path.join(d, "python3"))), None)
            if py:
                for n in ("python3", "python"):
                    os.symlink(py, os.path.join(shim, n))
        env["PATH"] = shim + ":" + cargo_bin + ":" + self.runner.mise_path(self.ws, env)
        for k, v in (self.runner.workflow.get("env") or {}).items():
            env[k] = self.expr.sub(v)
        for k, v in (self.spec.get("env") or {}).items():
            env[k] = self.expr.sub(v)
        return env

    def wrap(self, argv):
        cpus = ",".join(map(str, self.cpus))
        return ["systemd-run", "--user", "--scope", "-q", "-p", f"MemoryMax={MEM}", "-p", "MemorySwapMax=0",
                "taskset", "-c", cpus] + argv

    def run_bash(self, script, env, name):
        for f in ("GITHUB_ENV", "GITHUB_OUTPUT", "GITHUB_STEP_SUMMARY"):
            env[f] = os.path.join(self.runner_temp, f"{f.lower()}-{len(self.steps_state)}")
            open(env[f], "a").close()
        path = os.path.join(self.runner_temp, f"step-{len(self.steps_state)}.sh")
        with open(path, "w") as f:
            f.write(script)
        self.log(f"\n##[step] {name}\n$ {script.strip()}")
        t = time.time()
        with open(self.log_path, "a") as logf:
            rc = subprocess.run(self.wrap(["bash", "--noprofile", "--norc", "-eo", "pipefail", path]), cwd=self.ws,
                                env=env, stdout=logf, stderr=subprocess.STDOUT).returncode
        outputs = {}
        for line in open(env["GITHUB_OUTPUT"]):
            if "=" in line:
                k, v = line.rstrip("\n").split("=", 1)
                outputs[k] = v
        for line in open(env["GITHUB_ENV"]):
            if "=" in line:
                k, v = line.rstrip("\n").split("=", 1)
                self.env[k] = v
        summ = open(env["GITHUB_STEP_SUMMARY"]).read()
        if summ.strip():
            with open(os.path.join(self.runner.out, "logs", self.id + ".summary.md"), "a") as f:
                f.write(summ)
        self.log(f"##[step] {name}: exit {rc} in {time.time() - t:.0f}s")
        return rc, outputs

    # --- steps ---------------------------------------------------------------------------------------------------
    def setup(self, w):
        inp = {"cache-name": "", "go-build-name": "", "caches": "cargo go", "save": "all", "rust": "true",
               "tools": "false", "own-gomod": "false", "free-disk": "false", "images": "", "fetch": "all",
               "build": "true"}
        inp.update({k: str(v).lower() if isinstance(v, bool) else str(v) for k, v in (w or {}).items()})
        if inp["free-disk"] == "true":
            self.note("free-disk not emulated (nothing removed; disk compared with the 35 GB it frees)")
        if inp["caches"].strip():
            self.note(f"cache restore not emulated ({inp['caches'].strip()}): cold")
        if inp["images"].strip():
            self.note("image cache not emulated (the machine's docker images are used)")
        env = self.job_env()
        if inp["own-gomod"] == "true":
            self.env["GOMODCACHE"] = os.path.join(self.home, ".cache", "xdrcheck", "gomod")
        if inp["tools"] == "true":
            tar = os.path.join(self.runner.out, "artifacts", "tools", "tools.tar")
            if not os.path.isfile(tar):
                self.log("##[error] no tools artifact (the build job did not upload it)")
                return 1
            subprocess.run(["tar", "-xf", tar], cwd=self.ws, check=True)
            self.env.update({"CORPUS": f"{self.ws}/target/release/xdrcheck-corpus",
                             "MUTATE": f"{self.ws}/target/release/xdrcheck-mutate",
                             "XDRCHECK": f"{self.ws}/go/bin/xdrcheck"})
        parts = "" if inp["fetch"] in ("false", "") else inp["fetch"]
        if parts:
            env = self.job_env()
            t = time.time()
            # The only networked step: not in a namespace, not on 2 CPUs (the runner's download is not CPU-bound
            # either way, and the fetch's own builds are timed with the job).
            rc, _ = self.run_bash(f'make fetch FETCH_ONLY="{parts}"\n', env, f"setup: make fetch FETCH_ONLY={parts}")
            self.fetch_s = time.time() - t
            if rc:
                return rc
        self.env.update({"CARGO_NET_OFFLINE": "true", "GOPROXY": "off", "GOTOOLCHAIN": "local", "PIP_NO_INDEX": "1"})
        rc, _ = self.run_bash("scripts/ci/offline-check.sh\n", self.job_env(), "setup: offline check")
        if rc:
            return rc
        if inp["build"] == "true":
            rc, _ = self.run_bash("scripts/offline-run.sh make build\n", self.job_env(), "setup: make build (offline)")
            if rc:
                return rc
        return 0

    def job_env(self):
        env = self.base_env()
        env.update(self.env)
        return env

    def upload(self, w):
        name = self.expr.sub(w.get("name", "artifact"))
        dest = os.path.join(self.runner.out, "artifacts", name)
        shutil.rmtree(dest, ignore_errors=True)
        os.makedirs(dest)
        paths = [self.expr.sub(p).strip() for p in str(w.get("path", "")).splitlines() if p.strip()]
        found = 0
        for p in paths:
            if p.startswith("!"):
                continue
            p = os.path.expanduser(p.replace("~", self.home, 1)) if p.startswith("~") else p
            base = p if os.path.isabs(p) else os.path.join(self.ws, p)
            matches = [base] if os.path.exists(base) else [
                os.path.join(os.path.dirname(base), f) for f in (os.listdir(os.path.dirname(base))
                                                                 if os.path.isdir(os.path.dirname(base)) else [])
                if fnmatch.fnmatch(f, os.path.basename(base))]
            for m in matches:
                found += 1
                rel = os.path.basename(m.rstrip("/"))
                if os.path.isdir(m):
                    shutil.copytree(m, dest if len(paths) == 1 else os.path.join(dest, rel), dirs_exist_ok=True)
                else:
                    shutil.copy2(m, dest)
        if not found and w.get("if-no-files-found") == "error":
            self.log(f"##[error] upload {name}: no files")
            return 1
        # What would be published: scan a copy for anything the withhold step should have taken out.
        with tempfile.TemporaryDirectory() as tmp:
            copy = os.path.join(tmp, "a")
            shutil.copytree(dest, copy)
            r = subprocess.run([sys.executable, "-I", os.path.join(ROOT, "scripts/ci/withhold-pending.py"), copy],
                               text=True, capture_output=True)
            leaked = [l for l in r.stdout.splitlines() if "withheld" in l]
            if r.returncode or leaked:
                self.log(f"##[error] upload {name}: names sites pending finding review: {leaked or r.stderr}")
                self.note(f"LEAK in artifact {name}")
                return 1
        self.log(f"##[step] upload {name}: {found} path(s), scanned clean")
        return 0

    def download(self, w):
        dest = os.path.join(self.ws, self.expr.sub(w.get("path", ".")))
        os.makedirs(dest, exist_ok=True)
        root = os.path.join(self.runner.out, "artifacts")
        names = [w["name"]] if w.get("name") else [n for n in sorted(os.listdir(root))
                                                   if fnmatch.fnmatch(n, w.get("pattern", "*"))]
        for n in names:
            src = os.path.join(root, n)
            if not os.path.isdir(src):
                self.log(f"##[error] download: no artifact {n}")
                return 1
            target = dest if (w.get("merge-multiple") or w.get("name")) else os.path.join(dest, n)
            shutil.copytree(src, target, dirs_exist_ok=True)
        self.log(f"##[step] download {', '.join(names)} into {w.get('path', '.')}")
        return 0

    def sample(self, stop):
        while not stop.wait(30):
            try:
                n = int(sh(["du", "-sxb", self.dir]).split()[0])
                self.peak = max(self.peak, n)
            except Exception:
                pass

    def run(self):
        start = time.time()
        os.makedirs(self.runner_temp, exist_ok=True)
        real_home = self.home
        os.makedirs(real_home, exist_ok=True)
        # HOME is a short symlink to the job's home (a hosted runner's home path is 12 characters): tools put Unix
        # sockets under it (the replay adapter's database), and a socket path may not exceed 107 bytes.
        while True:
            link = "/tmp/r" + os.urandom(3).hex()  # 12 characters, as long as a hosted runner's home path
            try:
                os.symlink(real_home, link)
                break
            except FileExistsError:
                continue
        self.home = link
        open(self.log_path, "w").close()
        sh(["git", "clone", "-q", "--shared", self.runner.src, self.ws])
        sh(["git", "-C", self.ws, "checkout", "-q", "--detach", self.runner.sha])
        stop = threading.Event()
        th = threading.Thread(target=self.sample, args=(stop,), daemon=True)
        th.start()
        try:
            for i, step in enumerate(self.spec.get("steps") or []):
                sid = step.get("id") or f"_{i}"
                name = step.get("name") or step.get("uses") or "run"
                if not self.expr.eval(step.get("if")):
                    self.steps_state[sid] = {"outcome": "skipped"}
                    self.log(f"##[step] {name}: skipped (if: {step.get('if', 'success()')})")
                    continue
                rc, outputs = 0, {}
                uses = step.get("uses", "")
                w = {k: (self.expr.sub(v) if isinstance(v, str) else v) for k, v in (step.get("with") or {}).items()}
                if uses.startswith("actions/checkout"):
                    pass
                elif uses == "./.github/actions/setup":
                    rc = self.setup(w)
                elif uses.startswith("actions/upload-artifact"):
                    rc = self.upload(w)
                elif uses.startswith("actions/download-artifact"):
                    rc = self.download(w)
                elif uses.startswith("actions/cache"):
                    self.log(f"##[step] {name}: cache step skipped (not emulated)")
                elif uses:
                    self.note(f"step {uses} not emulated")
                else:
                    env = self.job_env()
                    for k, v in (step.get("env") or {}).items():
                        env[k] = self.expr.sub(v)
                    rc, outputs = self.run_bash(self.expr.sub(step["run"]), env, name)
                self.steps_state[sid] = {"outcome": "failure" if rc else "success", "outputs": outputs}
                if rc:
                    self.failed = True
        finally:
            stop.set()
            th.join()
            try:
                self.peak = max(self.peak, int(sh(["du", "-sxb", self.dir]).split()[0]))
            except Exception:
                pass
        wall = time.time() - start
        if os.path.islink(self.home):
            os.unlink(self.home)
        if not self.runner.keep:
            subprocess.run(["chmod", "-R", "u+w", self.dir], capture_output=True)
            shutil.rmtree(self.dir, ignore_errors=True)
        return {"job": self.id, "name": self.spec.get("name", self.id), "result": "failure" if self.failed else "success",
                "wall_s": round(wall), "fetch_s": round(self.fetch_s), "peak_disk_gb": round(self.peak / 1e9, 1),
                "timeout_min": self.spec.get("timeout-minutes"), "notes": self.notes}


class Runner:
    def __init__(self, a):
        self.tier, self.keep = a.tier, a.keep
        self.out = os.path.abspath(a.out or tempfile.mkdtemp(prefix=f"ci-local-{a.tier}-"))
        os.makedirs(os.path.join(self.out, "logs"), exist_ok=True)
        os.makedirs(os.path.join(self.out, "artifacts"), exist_ok=True)
        self.sha = sh(["git", "-C", ROOT, "rev-parse", a.sha]).strip()
        self.src = os.path.join(self.out, "src.git")
        if not os.path.isdir(self.src):
            sh(["git", "clone", "-q", "--bare", "--no-local", ROOT, self.src])
        wf = {"pr": "pr.yml", "full": "full.yml"}[a.tier]
        # The workflow as the commit under test has it, not as the working tree has it.
        self.workflow = yaml.safe_load(sh(["git", "-C", ROOT, "show", f"{self.sha}:.github/workflows/{wf}"]))
        self.jobs = self.workflow["jobs"]
        self.results = {}
        self.parallel = a.parallel
        self.cpus = a.cpus
        want = a.job or list(self.jobs)
        unknown = [j for j in want if j not in self.jobs]
        if unknown:
            raise SystemExit(f"run-local: no job {', '.join(unknown)} in {wf}")
        self.selected = set()

        def add(j):
            if j in self.selected:
                return
            self.selected.add(j)
            for n in self.needs(j):
                add(n)
        for j in want:
            add(j)
        # --reuse DIR: the report artifacts of an earlier run (its <out>/artifacts) stand in for every needed job
        # except the ones asked for and the build job (whose tools must be this commit's); those jobs are not run.
        # The earlier artifacts of the jobs that do run here are not copied: a job after them must read only what
        # they upload in this run, never an old file they no longer write.
        self.reused = set()
        if a.reuse:
            src = os.path.join(os.path.abspath(a.reuse), "artifacts")
            if not os.path.isdir(src):
                raise SystemExit(f"run-local: {src} is not an artifacts directory")
            self.reused = {j for j in self.selected if j not in want and j != "build"}
            copied, left = reuse_artifacts(self.jobs, self.selected - self.reused, src,
                                           os.path.join(self.out, "artifacts"))
            print(f"run-local: --reuse: {len(copied)} artifact(s) copied from {src}; not copied (made by jobs run "
                  f"here): {', '.join(left) or 'none'}", flush=True)

    def mise_path(self, ws, env):
        """PATH with the toolchains mise.toml pins first, as the setup's mise step gives the job: their install
        directories (as this machine's mise has them) ahead of the rest of PATH."""
        if getattr(self, "_path", None) is None:
            rest = env.get("PATH", os.environ["PATH"]).split(":")
            first = []
            try:
                real = dict(os.environ, MISE_TRUSTED_CONFIG_PATHS=ws)
                out = subprocess.run(["mise", "env", "-s", "bash"], cwd=ws, env=real, text=True, capture_output=True,
                                     check=True).stdout
                m = re.search(r"^export PATH='?([^'\n]*)'?$", out, re.M)
                first = [d for d in (m.group(1).split(":") if m else []) if "/mise/installs/" in d]
            except Exception as e:
                print(f"run-local: mise env failed ({e}); PATH as it is", file=sys.stderr)
            if not first:
                print("run-local: no mise toolchain found for mise.toml; the job uses PATH as it is", file=sys.stderr)
            # Nothing of this user's own bin directories (~/.local/bin, ~/go/bin, ...): a hosted runner has none, and
            # a stray tool there (another Go) would shadow the pinned one. Only the mise toolchains and rustup's
            # proxies (added by the caller) come from the home directory.
            home = os.environ["HOME"].rstrip("/") + "/"
            rest = [d for d in rest if not d.startswith(home) or "/mise/installs/" in d]
            self._path = ":".join(first + [d for d in rest if d not in first])
        return self._path

    def needs(self, j):
        n = self.jobs[j].get("needs") or []
        return [n] if isinstance(n, str) else list(n)

    def run(self):
        print(f"run-local: {self.tier} tier at {self.sha[:12]}, {len(self.selected)} job(s), output in {self.out}",
              flush=True)
        pending = [j for j in self.jobs if j in self.selected]
        cpu_sets = [tuple(int(c) for c in pair.split(",")) for pair in self.cpus.split(";")][: self.parallel]
        free = list(cpu_sets)
        running = {}
        lock = threading.Lock()
        done_ev = threading.Event()

        def worker(j, cpus):
            spec = self.jobs[j]
            job = Job(self, j, spec, cpus)
            if j in self.reused:
                res = {"job": j, "name": spec.get("name", j), "result": "success", "wall_s": 0, "fetch_s": 0,
                       "peak_disk_gb": 0, "timeout_min": spec.get("timeout-minutes"),
                       "notes": ["not run: its artifacts reused from an earlier run (--reuse)"]}
                with lock:
                    self.results[j] = res
                    running.pop(j, None)
                    free.append(cpus)
                    print(f"  reused   {j}", flush=True)
                    done_ev.set()
                return
            cond = spec.get("if")
            if cond:
                ok = Expr(job).eval(cond, default_status=False)
            else:
                ok = all(self.results.get(n, {}).get("result") == "success" for n in self.needs(j))
            if not ok:
                res = {"job": j, "name": spec.get("name", j), "result": "skipped", "wall_s": 0, "fetch_s": 0,
                       "peak_disk_gb": 0, "timeout_min": spec.get("timeout-minutes"), "notes": ["a needed job failed"]}
            else:
                try:
                    res = job.run()
                except Exception as e:  # report and go on with the other jobs
                    res = {"job": j, "name": spec.get("name", j), "result": "error", "wall_s": 0, "fetch_s": 0,
                           "peak_disk_gb": 0, "timeout_min": spec.get("timeout-minutes"), "notes": [repr(e)]}
            to = res.get("timeout_min")
            if to and res["wall_s"] > to * 60:
                res["notes"].append(f"over its timeout-minutes ({to})")
                res["result"] = "timeout"
            with lock:
                self.results[j] = res
                running.pop(j, None)
                free.append(cpus)
                print(f"  {res['result']:8} {res['wall_s']:6}s  fetch {res['fetch_s']:5}s  disk {res['peak_disk_gb']:5} GB  {j}",
                      flush=True)
                done_ev.set()

        while pending or running:
            with lock:
                ready = [j for j in pending if all(n in self.results for n in self.needs(j))]
                while ready and free:
                    j = ready.pop(0)
                    pending.remove(j)
                    cpus = free.pop(0)
                    running[j] = threading.Thread(target=worker, args=(j, cpus), daemon=True)
                    running[j].start()
                done_ev.clear()
            done_ev.wait(5)
        self.write_summary()
        return 0 if all(r["result"] == "success" for r in self.results.values()) else 1

    def write_summary(self):
        order = [j for j in self.jobs if j in self.results]
        rows = [self.results[j] for j in order]
        with open(os.path.join(self.out, "summary.json"), "w") as f:
            json.dump({"tier": self.tier, "sha": self.sha, "jobs": rows}, f, indent=2)
        lines = [f"# Local CI emulation: {self.tier} tier at {self.sha[:12]}", "",
                 "Each job from a fresh clone, its own empty home, only its declared fetch parts and artifacts, on 2 "
                 f"CPUs with {MEM} of memory (scripts/ci/run_local.py). Cold: no cache restored. Peak disk is the "
                 f"job directory (clone, home, caches); a hosted runner has about {RUNNER_DISK_GB} GB free "
                 f"({RUNNER_DISK_FREED_GB} GB after free-disk).", "",
                 "| Job | Result | Wall | Fetch | Peak disk | Timeout | Notes |", "|---|---|---|---|---|---|---|"]
        for r in rows:
            lines.append(f"| {r['job']} | {r['result']} | {r['wall_s'] // 60} min {r['wall_s'] % 60} s | "
                         f"{r['fetch_s']} s | {r['peak_disk_gb']} GB | {r['timeout_min']} min | {'; '.join(r['notes'])} |")
        with open(os.path.join(self.out, "summary.md"), "w") as f:
            f.write("\n".join(lines) + "\n")
        print("\n".join(lines))


def uploaded_names(jobs, run):
    """The artifact names the jobs in `run` upload, as fnmatch patterns (an expression in a name matches anything)."""
    names = set()
    for j in run:
        for step in jobs[j].get("steps") or []:
            if str(step.get("uses", "")).startswith("actions/upload-artifact"):
                name = str((step.get("with") or {}).get("name", "artifact"))
                names.add(re.sub(r"\$\{\{.*?\}\}", "*", name))
    return names


def reuse_artifacts(jobs, run, src, dest):
    """Copy the artifacts under src into dest, except the build's tools and every artifact a job in `run` uploads.
    Returns (copied, not copied) names."""
    made = uploaded_names(jobs, run) | {"tools"}
    copied, left = [], []
    for n in sorted(os.listdir(src)):
        if any(fnmatch.fnmatchcase(n, p) for p in made):
            left.append(n)
            continue
        shutil.copytree(os.path.join(src, n), os.path.join(dest, n), dirs_exist_ok=True)
        copied.append(n)
    return copied, left


def self_test():
    """--reuse against a planted earlier run: the artifacts of the jobs that run are not copied, the others are."""
    jobs = yaml.safe_load("""
build: {steps: [{uses: actions/upload-artifact@x, with: {name: tools}}]}
static: {needs: build, steps: [{run: "true"}, {uses: actions/upload-artifact@x, with: {name: reports-static}}]}
replay: {needs: build, steps: [{uses: actions/upload-artifact@x, with: {name: "reports-replay-${{ matrix.part }}"}}]}
corpus: {needs: build, steps: [{uses: actions/upload-artifact@x, with: {name: reports-corpus}}]}
""")
    failed = 0
    with tempfile.TemporaryDirectory() as d:
        src, dest = os.path.join(d, "old"), os.path.join(d, "new")
        for n in ("tools", "reports-static", "reports-replay-a", "reports-corpus", "acceptance-report"):
            os.makedirs(os.path.join(src, n))
            with open(os.path.join(src, n, "stale.txt"), "w") as f:
                f.write("from the earlier run\n")
        os.makedirs(dest)
        copied, left = reuse_artifacts(jobs, {"build", "static", "replay"}, src, dest)
        want_copied, want_left = ["acceptance-report", "reports-corpus"], ["reports-replay-a", "reports-static", "tools"]
        if copied != want_copied or left != want_left or sorted(os.listdir(dest)) != want_copied:
            print(f"self-test: copied {copied} (want {want_copied}), not copied {left} (want {want_left}), "
                  f"dest {sorted(os.listdir(dest))}", file=sys.stderr)
            failed = 1
    print("run_local self-test: FAILED" if failed else
          "run_local self-test: --reuse copies no artifact of a job that runs, and every other one")
    return failed


def main():
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--tier", required=True, choices=["pr", "full"])
    ap.add_argument("--job", action="append", help="a job id (repeatable); default every job of the tier")
    ap.add_argument("--sha", default="HEAD", help="the commit to run (default HEAD); its committed files only")
    ap.add_argument("--out", help="output directory (default a new one under $TMPDIR)")
    ap.add_argument("--parallel", type=int, default=1, choices=[1, 2, 3, 4], help="jobs at a time, 2 CPUs each")
    ap.add_argument("--keep", action="store_true", help="keep each job's directory")
    ap.add_argument("--reuse", help="an earlier run's output directory: its report artifacts stand in for the needed "
                                    "jobs other than --job and build, which are not run (the artifacts of the jobs "
                                    "that run are not copied)")
    ap.add_argument("--cpus", default="0,1;2,3;4,5;6,7",
                    help="the CPU pairs jobs run on, one pair per parallel job (default 0,1;2,3;4,5;6,7)")
    a = ap.parse_args()
    return Runner(a).run()


if __name__ == "__main__":
    sys.exit(main())

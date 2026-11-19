#!/usr/bin/env python3
"""Run a composite action's steps the way a GitHub runner does, locally, for the action's self-test.

It reads action.yml, fills the inputs (the given ones over the defaults), and runs each step in order:
`run:` steps with bash (`--noprofile --norc -eo pipefail`, as the runner does) and the runner's files
(GITHUB_OUTPUT, GITHUB_ENV, GITHUB_STEP_SUMMARY) and variables (GITHUB_ACTION_PATH, GITHUB_WORKSPACE, RUNNER_TEMP,
GITHUB_SHA, ...); `uses: actions/upload-artifact` is replaced by a copy of its `path` into ARTIFACTS/<name>,
failing as the real one does when the path is missing and if-no-files-found is `error`. Expressions are the
subset action.yml uses: `${{ inputs.X }}`, `${{ github.X }}`, `${{ runner.temp }}`, `${{ steps.ID.outputs.X }}`
and, in `if:`, `always()`, `success()`, `failure()`, `&&`, `||`, `==`, `!=` and string literals. Anything else is an
error, so the simulation never silently differs from the real runner on what the file uses.

Usage:
    simulate.py ACTION_DIR OUT_DIR [name=value ...]

Writes OUT_DIR/result.json (each step's outcome, the action's outputs) and OUT_DIR/step-summary.md, copies
artifacts to OUT_DIR/artifacts/<name>/, and exits 0 when every step that ran succeeded, else 1.
"""
import json
import os
import re
import shutil
import subprocess
import sys

import yaml

EXPR = re.compile(r"\$\{\{\s*(.*?)\s*\}\}")
REF = re.compile(r"^(inputs|github|runner|steps)\.([A-Za-z0-9_.-]+)$")


class Ctx:
    def __init__(self, action_dir, out, given):
        self.action_dir = os.path.abspath(action_dir)
        self.out = os.path.abspath(out)
        self.temp = os.path.join(self.out, "runner-temp")
        self.workspace = os.environ.get("GITHUB_WORKSPACE") or os.getcwd()
        self.github = {
            "sha": "0" * 40, "workspace": self.workspace, "repository": "local/selftest",
            "action_repository": "", "action_ref": "", "action_path": self.action_dir,
        }
        self.runner = {"temp": self.temp, "os": "Linux"}
        self.given = given
        self.inputs = {}
        self.steps = {}
        self.env = {}

    def ref(self, expr):
        m = REF.match(expr)
        if not m:
            raise SystemExit(f"simulate: unsupported expression {expr!r}")
        scope, path = m.groups()
        if scope == "inputs":
            return self.inputs.get(path, "")
        if scope == "github":
            return self.github[path]
        if scope == "runner":
            return self.runner[path]
        sid, _, key = path.partition(".outputs.")
        return self.steps.get(sid, {}).get("outputs", {}).get(key, "")

    def subst(self, text):
        return EXPR.sub(lambda m: str(self.ref(m.group(1))), text) if isinstance(text, str) else text

    def cond(self, text, failed):
        expr = EXPR.sub(lambda m: m.group(1), str(text)).strip()
        out = []
        for tok in re.findall(r"'[^']*'|&&|\|\||==|!=|\(|\)|[A-Za-z_][A-Za-z0-9_.-]*\(\)|[A-Za-z_][A-Za-z0-9_.-]*", expr):
            if tok == "&&":
                out.append(" and ")
            elif tok == "||":
                out.append(" or ")
            elif tok in ("==", "!=", "(", ")"):
                out.append(f" {tok} ")
            elif tok.startswith("'"):
                out.append(repr(tok[1:-1]))
            elif tok == "always()":
                out.append(" True ")
            elif tok == "success()":
                out.append(f" {not failed} ")
            elif tok == "failure()":
                out.append(f" {failed} ")
            else:
                out.append(repr(self.ref(tok)))
        return bool(eval("".join(out), {"__builtins__": {}}, {}))


def read_kv(path):
    vals = {}
    if not os.path.exists(path):
        return vals
    lines = open(path, encoding="utf-8").read().split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        if "<<" in line and ("=" not in line or line.index("<<") < line.index("=")):
            k, delim = line.split("<<", 1)
            j = lines.index(delim, i + 1)
            vals[k] = "\n".join(lines[i + 1:j])
            i = j + 1
            continue
        if "=" in line:
            k, v = line.split("=", 1)
            vals[k] = v
        i += 1
    return vals


def main():
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    action_dir, out = sys.argv[1], sys.argv[2]
    given = dict(a.split("=", 1) for a in sys.argv[3:])
    ctx = Ctx(action_dir, out, given)
    shutil.rmtree(ctx.out, ignore_errors=True)
    os.makedirs(ctx.temp)
    action = yaml.safe_load(open(os.path.join(ctx.action_dir, "action.yml"), encoding="utf-8"))
    declared = action.get("inputs") or {}
    for k in given:
        if k not in declared:
            raise SystemExit(f"simulate: action.yml has no input {k!r}")
    for k, spec in declared.items():
        ctx.inputs[k] = given[k] if k in given else ctx.subst(str((spec or {}).get("default", "")))
        if (spec or {}).get("required") and not ctx.inputs[k]:
            raise SystemExit(f"simulate: required input {k!r} not given")
    if action["runs"]["using"] != "composite":
        raise SystemExit("simulate: not a composite action")

    summary = os.path.join(ctx.out, "step-summary.md")
    open(summary, "w").close()
    failed = False
    results = []
    for n, step in enumerate(action["runs"]["steps"], 1):
        sid = step.get("id") or f"step{n}"
        name = ctx.subst(step.get("name") or sid)
        if not ctx.cond(step.get("if", "success()"), failed):
            results.append({"step": name, "outcome": "skipped"})
            ctx.steps[sid] = {"outputs": {}, "outcome": "skipped"}
            continue
        outputs, ok = {}, True
        if "run" in step:
            if step.get("shell") != "bash":
                raise SystemExit(f"simulate: step {name!r}: only shell: bash is simulated")
            files = {k: os.path.join(ctx.temp, f"{k.lower()}-{n}") for k in ("GITHUB_OUTPUT", "GITHUB_ENV")}
            for p in files.values():
                open(p, "w").close()
            env = dict(os.environ)
            env.update(ctx.env)
            env.update({k: ctx.subst(str(v)) for k, v in (step.get("env") or {}).items()})
            env.update(files)
            env.update({
                "GITHUB_ACTION_PATH": ctx.action_dir, "GITHUB_WORKSPACE": ctx.workspace, "RUNNER_TEMP": ctx.temp,
                "GITHUB_SHA": ctx.github["sha"], "GITHUB_REPOSITORY": ctx.github["repository"],
                "GITHUB_STEP_SUMMARY": summary, "GITHUB_ACTIONS": "true", "CI": "true",
            })
            script = os.path.join(ctx.temp, f"step-{n}.sh")
            open(script, "w").write(ctx.subst(step["run"]))
            print(f"simulate: ▶ {name}", flush=True)
            p = subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", script],
                               cwd=ctx.workspace, env=env)
            ok = p.returncode == 0
            outputs = read_kv(files["GITHUB_OUTPUT"])
            ctx.env.update(read_kv(files["GITHUB_ENV"]))
            results.append({"step": name, "outcome": "success" if ok else "failure", "exit": p.returncode})
        elif "uses" in step:
            uses = step["uses"].split("@")[0]
            with_ = {k: ctx.subst(str(v)) for k, v in (step.get("with") or {}).items()}
            if uses != "actions/upload-artifact":
                raise SystemExit(f"simulate: step {name!r}: {uses} is not simulated")
            src, art = with_.get("path", ""), with_.get("name", "")
            print(f"simulate: ▶ {name} ({art} from {src})", flush=True)
            if not art or not src or not os.path.isdir(src) or not os.listdir(src):
                ok = with_.get("if-no-files-found", "warn") != "error"
                print(f"simulate: upload-artifact: nothing at {src!r}", flush=True)
            else:
                shutil.copytree(src, os.path.join(ctx.out, "artifacts", art))
            results.append({"step": name, "outcome": "success" if ok else "failure", "artifact": art})
        else:
            raise SystemExit(f"simulate: step {name!r} has neither run nor uses")
        ctx.steps[sid] = {"outputs": outputs, "outcome": "success" if ok else "failure"}
        failed = failed or not ok

    outs = {k: ctx.subst(str(v.get("value", ""))) for k, v in (action.get("outputs") or {}).items()}
    res = {"inputs": ctx.inputs, "steps": results, "outputs": outs, "conclusion": "failure" if failed else "success"}
    json.dump(res, open(os.path.join(ctx.out, "result.json"), "w"), indent=2)
    print(f"simulate: {res['conclusion']}; outputs {json.dumps(outs)}", flush=True)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()

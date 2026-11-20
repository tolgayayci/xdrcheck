#!/usr/bin/env python3
"""The "latest" canary columns of the nightly canary job (scripts/nightly/canary.sh).

For each SDK family with a conformance driver (js, go, python, rust), the newest published version of the SDK
(from `xdrcheck pins latest --json`) is compared with the versions pins.toml [conformance.columns] allows. A family
whose newest version is already a pinned column needs no canary. For the others this script builds a
throw-away column directory set outside the working tree, in the layout of the private overlay's sets file
(drivers/sets.toml with [pins], [columns] and [sets] canary), so `xdrcheck conform run --overlay DIR --set canary`
runs the newest SDK through the pinned driver code without changing a tracked file:

    canary.py plan        --root ROOT --latest latest.json [--json plan.json]
    canary.py materialise --root ROOT --plan plan.json --overlay DIR     (network: package managers)
    canary.py rename      --plan plan.json --matrix matrix.json --out renamed.json

`plan` is offline; it prints one line per family and writes the plan. `materialise` writes the column
directories: each copies the newest pinned column's directory, links the shared driver sources, sets the new
SDK version and resolves a lock file with the family's own package manager (npm, go, pip, cargo), which is the
only networked step. `rename` rewrites the canary columns of a matrix to the ids of the pinned columns they
were made from, so `xdrcheck conform diff <pinned matrix> <renamed>` lists exactly the cells whose verdict moved
between the pinned and the newest version. Exit codes: 0 done; 2 bad input or a step failed.
"""
import argparse
import glob
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tomllib

# family -> (the tracked pin that names its newest release, files a version directory carries, shared
# entries the version directory refers to with "..")
FAMILIES = {
    "js": ("js.stellar_sdk", ["Makefile"], ["src", "test", "version.mk"]),
    "go": ("go.go_stellar_sdk", ["Makefile", "main.go", "go.mod"], ["driver", "views", "version.mk"]),
    "python": ("python.stellar_sdk", ["Makefile"], ["src", "test", "version.mk"]),
    "rust": ("rust.stellar_xdr", ["Makefile", "Cargo.toml"], ["src", "driver.mk"]),
}


def die(msg):
    print(f"canary: {msg}", file=sys.stderr)
    sys.exit(2)


def version_key(v):
    v = v.lstrip("v").split("-")[0].split("+")[0]
    return [int(p) for p in v.split(".") if p.isdigit()]


def plan(root, latest_rows):
    pins = tomllib.load(open(os.path.join(root, "pins.toml"), "rb"))
    sets = tomllib.load(open(os.path.join(root, "drivers", "sets.toml"), "rb"))
    # The columns live in drivers/sets.d/, one family per file.
    sets.setdefault("columns", {})
    for frag in sorted(glob.glob(os.path.join(root, "drivers", "sets.d", "*.toml"))):
        sets["columns"].update(tomllib.load(open(frag, "rb")).get("columns", {}))
    latest = {r["key"]: r for r in latest_rows}
    families = []
    for fam, (key, _, _) in FAMILIES.items():
        row = latest.get(key)
        allowed = pins["conformance"]["columns"].get(fam, [])
        if row is None or not row.get("latest"):
            families.append({"family": fam, "status": "unknown",
                             "note": f"no newest version for {key} ({(row or {}).get('error', 'not tracked')})"})
            continue
        newest = row["latest"]
        if newest in allowed:
            families.append({"family": fam, "status": "pinned", "version": newest,
                             "note": f"newest {newest} is a pinned column"})
            continue
        # The template: the highest pinned version of the family that has public columns.
        cols = {cid: c for cid, c in sets["columns"].items() if c.get("sdk") == fam and c.get("kind") == "sdk"}
        if not cols:
            die(f"drivers/sets.d has no {fam} column")
        top = max({c["version"] for c in cols.values()}, key=version_key)
        templates = sorted(cid for cid, c in cols.items() if c["version"] == top and not c.get("levels"))
        canary = []
        for cid in templates:
            c = dict(cols[cid])
            c["version"] = newest
            c["role"] = "extra"
            c["dir"] = f"drivers/{fam}/{newest}"
            new_id = f"{fam}@{newest}" + (f":{c['profile']}" if c.get("profile") else "")
            canary.append({"id": new_id, "template": cid, "column": c})
        families.append({"family": fam, "status": "canary", "version": newest, "template_version": top,
                         "template_dir": cols[templates[0]]["dir"], "columns": canary,
                         "note": f"newest {newest} is not pinned (newest pinned {top}); canary columns "
                                 + ", ".join(x["id"] for x in canary)})
    return {"families": families}


def run(cmd, cwd, env=None):
    print("  $ " + " ".join(cmd), flush=True)
    r = subprocess.run(cmd, cwd=cwd, env={**os.environ, **(env or {})})
    if r.returncode != 0:
        die(f"{' '.join(cmd)} failed in {cwd} (exit {r.returncode})")


def materialise(root, p, overlay, cache):
    os.makedirs(os.path.join(overlay, "drivers"), exist_ok=True)
    sets = {"pins": {}, "columns": {}, "sets": {"canary": []}}
    for f in p["families"]:
        if f["status"] != "canary":
            continue
        fam, v = f["family"], f["version"]
        _, files, shared = FAMILIES[fam]
        src_dir = os.path.join(root, f["template_dir"])
        fam_dir = os.path.join(overlay, "drivers", fam)
        dst = os.path.join(fam_dir, v)
        shutil.rmtree(dst, ignore_errors=True)
        os.makedirs(dst)
        for s in shared:
            link = os.path.join(fam_dir, s)
            if not os.path.lexists(link):
                os.symlink(os.path.join(root, "drivers", fam, s), link)
        for name in files:
            shutil.copy(os.path.join(src_dir, name), os.path.join(dst, name))
        pkg_cache = os.path.join(cache, f"{fam}-{v}")
        os.makedirs(pkg_cache, exist_ok=True)
        print(f"canary: {fam} {v} in {dst}", flush=True)
        if fam == "js":
            json.dump({"name": f"xdrcheck-canary-js-{v}", "private": True, "license": "Apache-2.0",
                       "dependencies": {"@stellar/stellar-sdk": v}}, open(os.path.join(dst, "package.json"), "w"), indent=2)
            run(["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"], dst,
                {"npm_config_cache": os.path.join(pkg_cache, "npm"), "npm_config_update_notifier": "false"})
        elif fam == "go":
            text = open(os.path.join(dst, "Makefile")).read()
            open(os.path.join(dst, "Makefile"), "w").write(re.sub(r"(?m)^VERSION := .*$", f"VERSION := {v}", text))
            env = {"GOMODCACHE": os.path.join(pkg_cache, "gomod"), "GOFLAGS": "-mod=mod", "GOWORK": "off",
                   "GOTOOLCHAIN": "local"}
            run(["go", "mod", "edit", f"-module=canary/drivers/go/{v}", f"-require=github.com/stellar/go-stellar-sdk@{v}"], dst, env)
            run(["go", "mod", "tidy"], dst, env)
        elif fam == "python":
            wheels = os.path.join(pkg_cache, "resolve")
            shutil.rmtree(wheels, ignore_errors=True)
            run([sys.executable, "-I", "-m", "pip", "download", "--isolated", "--disable-pip-version-check",
                 "--only-binary=:all:", "--dest", wheels, f"stellar-sdk=={v}"], dst)
            lines = [f"# canary column: PyPI stellar-sdk {v} and what it installs, resolved for this interpreter"]
            for w in sorted(os.listdir(wheels)):
                m = re.match(r"^([^-]+)-([^-]+)-", w)
                if not m or not w.endswith(".whl"):
                    die(f"unexpected download {w}")
                name = m.group(1).replace("_", "-").lower()
                digest = hashlib.sha256(open(os.path.join(wheels, w), "rb").read()).hexdigest()
                lines.append(f"{name}=={m.group(2)} --hash=sha256:{digest}")
            open(os.path.join(dst, "requirements.txt"), "w").write("\n".join(lines) + "\n")
        elif fam == "rust":
            cargo = open(os.path.join(dst, "Cargo.toml")).read()
            cargo, n = re.subn(r'(stellar-xdr = \{ version = ")=[^"]+(")', rf"\g<1>={v}\g<2>", cargo)
            if n != 1:
                die("drivers/rust Cargo.toml: no stellar-xdr version to replace")
            open(os.path.join(dst, "Cargo.toml"), "w").write(cargo)
            run(["cargo", "generate-lockfile", "--manifest-path", "Cargo.toml"], dst,
                {"CARGO_HOME": os.path.join(pkg_cache, "cargo")})
        sets["pins"].setdefault(fam, []).append(v)
        for c in f["columns"]:
            sets["columns"][c["id"]] = c["column"]
            sets["sets"]["canary"].append(c["id"])
    with open(os.path.join(overlay, "drivers", "sets.toml"), "w") as out:
        out.write("# Canary columns written by scripts/nightly/canary.py; throw-away, never committed.\n")
        out.write("[pins]\n")
        for fam, vs in sorted(sets["pins"].items()):
            out.write(f"{fam} = {json.dumps(vs)}\n")
        out.write("\n[sets]\ncanary = " + json.dumps(sets["sets"]["canary"]) + "\n")
        for cid, c in sorted(sets["columns"].items()):
            out.write(f'\n[columns."{cid}"]\n')
            for k, val in c.items():
                out.write(f"{k} = {json.dumps(val)}\n")
    print(f"canary: wrote {len(sets['columns'])} column(s) to {overlay}/drivers/sets.toml")


def rename(p, matrix_path, out_path):
    ids = {c["id"]: c["template"] for f in p["families"] if f["status"] == "canary" for c in f["columns"]}
    m = json.load(open(matrix_path))
    for cell in m.get("cells", []):
        cell["column"] = ids.get(cell.get("column"), cell.get("column"))
    for col in m.get("columns", []):
        col["id"] = ids.get(col.get("id"), col.get("id"))
    json.dump(m, open(out_path, "w"))
    print(f"canary: {len(ids)} canary column(s) renamed to their pinned templates in {out_path}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("plan")
    a.add_argument("--root", required=True)
    a.add_argument("--latest", required=True)
    a.add_argument("--json")
    b = sub.add_parser("materialise")
    b.add_argument("--root", required=True)
    b.add_argument("--plan", required=True)
    b.add_argument("--overlay", required=True)
    b.add_argument("--cache", required=True)
    c = sub.add_parser("rename")
    c.add_argument("--plan", required=True)
    c.add_argument("--matrix", required=True)
    c.add_argument("--out", required=True)
    args = ap.parse_args()
    if args.cmd == "plan":
        p = plan(os.path.abspath(args.root), json.load(open(args.latest)))
        for f in p["families"]:
            print(f"{f['status']:<8} {f['family']:<7} {f['note']}")
        if args.json:
            json.dump(p, open(args.json, "w"), indent=2)
    elif args.cmd == "materialise":
        materialise(os.path.abspath(args.root), json.load(open(args.plan)), os.path.abspath(args.overlay),
                    os.path.abspath(args.cache))
    else:
        rename(json.load(open(args.plan)), args.matrix, args.out)


if __name__ == "__main__":
    main()

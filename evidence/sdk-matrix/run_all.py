"""Runs every vector through every SDK probe and writes results/*.jsonl and matrix.md.
Usage: python3 -I run_all.py [sdk-filter]      (from this directory; see README.md)
"""
import json, os, re, resource, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
os.chdir(HERE)
sys.path.insert(0, HERE)
VEC = "vectors/vectors.json"

def sdks():
    out = []
    for v in ["16.3.0", "16.3.1", "16.4.1", "17.2.0", "17.2.1", "17.3.0", "17.4.0"]:
        out.append(("js", v, ["node", "js/probe.mjs", f"js/{v}", VEC]))
    for v in ["v0.7.1", "v0.7.2", "v0.7.3", "v0.8.0"]:
        out.append(("go", v, [f"go/{v}/probe", VEC]))
    for v in ["28.0.0", "28.0.1", "30.0.0"]:
        d = "x" + v.replace(".", "_")
        out.append(("rust", f"{v} Limits{{500,len}}", [f"rust/target-{d}/release/probe", VEC, "limits"]))
        out.append(("rust", f"{v} Limits::none()", [f"rust/target-{d}/release/probe", VEC, "none"]))
    for v in ["17.0.0", "17.0.1"]:
        out.append(("python", v, [f"py/venv-{v}/bin/python", "-I", "py/probe.py", VEC]))
    return out

def run(cmd, ids, mem=False):
    if mem:
        cmd = ["systemd-run", "--user", "--scope", "-q", "-p", "MemoryMax=1G", "-p", "MemorySwapMax=0"] + cmd
    t0 = time.time()
    p = subprocess.Popen(cmd + ids, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        out, err = p.communicate(timeout=600)
    except subprocess.TimeoutExpired:
        p.kill(); out, err = p.communicate()
        err += "\nTIMEOUT"
    ru = resource.getrusage(resource.RUSAGE_CHILDREN)
    return out, err, p.returncode, time.time() - t0, ru.ru_maxrss

def main():
    flt = sys.argv[1] if len(sys.argv) > 1 else ""
    vectors = json.load(open(VEC))
    os.makedirs("results", exist_ok=True)
    for sdk, ver, cmd in sdks():
        if flt and flt not in f"{sdk} {ver}":
            continue
        rows = {}
        normal = [v["id"] for v in vectors if not v["params"].get("mem")]
        out, err, rc, dt, _ = run(cmd, normal)
        for line in out.splitlines():
            if line.startswith("{"):
                d = json.loads(line); rows[d["vector"]] = d
        missing = [i for i in normal if i not in rows]
        for i in missing:  # process died part-way: rerun one by one
            out, err, rc, dt, _ = run(cmd, [i])
            got = [json.loads(l) for l in out.splitlines() if l.startswith("{")]
            if got:
                rows[i] = got[0]
            else:
                tail = " | ".join([l for l in err.strip().splitlines() if l.strip()][:3])[:300]
                rows[i] = {"vector": i, "sdk": sdk, "version": ver, "outcome": "crash", "detail": f"exit {rc}: {tail}"}
        for v in vectors:
            if not v["params"].get("mem"):
                continue
            # fresh process per memory vector so peak RSS is attributable; ru_maxrss of children is cumulative max,
            # so measure in a child python that runs exactly one probe process
            meas = subprocess.run([sys.executable, "-I", "-c", MEAS, json.dumps(cmd + [v["id"]])], capture_output=True, text=True)
            m = json.loads(meas.stdout.strip().splitlines()[-1])
            got = [json.loads(l) for l in m["out"].splitlines() if l.startswith("{")]
            if got:
                d = got[0]
            else:
                tail = " | ".join([l for l in m["err"].strip().splitlines() if l.strip()][:3])[:300]
                d = {"vector": v["id"], "sdk": sdk, "version": ver, "outcome": "crash", "detail": f"exit {m['rc']}: {tail}"}
            d["detail"] = (d.get("detail") or "") + f" [peak RSS {m['maxrss_kb'] // 1024} MiB, MemoryMax=1G, {m['dt']:.2f}s]"
            rows[v["id"]] = d
        name = re.sub(r"[^A-Za-z0-9.]+", "_", f"{sdk}-{ver}").strip("_")
        with open(f"results/{name}.jsonl", "w") as fh:
            for v in vectors:
                d = rows.get(v["id"], {"vector": v["id"], "outcome": "missing"})
                d["sdk"], d["version_label"] = sdk, ver
                fh.write(json.dumps(d) + "\n")
        c = {}
        for d in rows.values():
            c[d["outcome"]] = c.get(d["outcome"], 0) + 1
        print(sdk, ver, c, flush=True)

MEAS = r'''
import json, os, resource, subprocess, sys, time
cmd = json.loads(sys.argv[1])
cmd = ["systemd-run", "--user", "--scope", "-q", "-p", "MemoryMax=1G", "-p", "MemorySwapMax=0"] + cmd
t0 = time.time()
p = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
ru = resource.getrusage(resource.RUSAGE_CHILDREN)
print(json.dumps({"out": p.stdout, "err": p.stderr, "rc": p.returncode, "maxrss_kb": ru.ru_maxrss, "dt": time.time() - t0}))
'''

def as_limit_runs():
    """Memory vectors again under an address-space cap (prlimit --as=1GiB) for the native-code probes; a calloc'd
    4 GiB request is lazy under MemoryMax, so only an AS cap shows whether the decoder *asks* for it."""
    rows = []
    for sdk, ver, cmd in sdks():
        if sdk not in ("rust", "python", "go"):
            continue
        for vid in [v["id"] for v in json.load(open(VEC)) if v["params"].get("mem")]:
            p = subprocess.run(["prlimit", "--as=1073741824"] + cmd + [vid], capture_output=True, text=True, timeout=120)
            got = [json.loads(l) for l in p.stdout.splitlines() if l.startswith("{")]
            d = got[0] if got else {"vector": vid, "outcome": "crash", "detail": f"exit {p.returncode}: " + " | ".join(p.stderr.strip().splitlines()[:1])}
            d.update(sdk=sdk, version_label=ver + " [prlimit --as=1GiB]")
            rows.append(d)
            print(sdk, ver, vid, d["outcome"], d.get("detail", "")[:100], flush=True)
    with open("results/extra_as_limit.jsonl", "w") as fh:
        for d in rows:
            fh.write(json.dumps(d) + "\n")

if __name__ == "__main__":
    main()
    if len(sys.argv) == 1:
        as_limit_runs()
        import depth_bisect
        depth_bisect.main()

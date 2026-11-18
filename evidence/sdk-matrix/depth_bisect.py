"""Finds, per SDK/version, the largest N for which a ScVal Vec nested N deep (innermost Void) decodes with
the probe's default decode entry point. Writes results/depth_boundaries.jsonl.
Usage: python3 -I depth_bisect.py [sdk-filter]
"""
import json, os, subprocess, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.chdir(os.path.dirname(os.path.abspath(__file__)))
import run_all  # noqa: E402

def nested(n):
    return ("00000010" + "00000001" + "00000001") * n + "00000001"

def decodes(cmd, n, tmpdir):
    path = os.path.join(tmpdir, "depth.json")
    json.dump([{"id": "8x", "group": 8, "level": "L0 codec", "title": f"nested {n}", "hex": nested(n),
                "params": {"type": "ScVal", "n": n}, "expect": {"accept": "info"}, "why": ""}], open(path, "w"))
    c = [a if a != run_all.VEC else path for a in cmd]
    p = subprocess.run(c + ["8x"], capture_output=True, text=True, timeout=600)
    lines = [json.loads(l) for l in p.stdout.splitlines() if l.startswith("{")]
    if not lines:
        return "crash", f"exit {p.returncode}: {p.stderr.strip()[:160]}"
    return lines[0]["outcome"], lines[0].get("detail", "")[:160]

def main():
    flt = sys.argv[1] if len(sys.argv) > 1 else ""
    tmpdir = os.path.join("vectors", "tmp"); os.makedirs(tmpdir, exist_ok=True)
    out = []
    for sdk, ver, cmd in run_all.sdks():
        if flt and flt not in f"{sdk} {ver}":
            continue
        lo, hi = 0, 5000
        o, d = decodes(cmd, hi, tmpdir)
        if o == "ok":
            row = {"sdk": sdk, "version": ver, "max_ok": f">={hi}", "first_fail": None, "fail_detail": ""}
            o2, d2 = decodes(cmd, 100000, tmpdir)
            row["n100000"] = f"{o2}: {d2}"
        else:
            fail_detail = d
            while hi - lo > 1:
                mid = (lo + hi) // 2
                o, d = decodes(cmd, mid, tmpdir)
                if o == "ok":
                    lo = mid
                else:
                    hi, fail_detail = mid, d
            row = {"sdk": sdk, "version": ver, "max_ok": lo, "first_fail": hi, "fail_detail": fail_detail[:120]}
        print(json.dumps(row), flush=True)
        out.append(row)
    with open("results/depth_boundaries.jsonl", "w" if not flt else "a") as fh:
        for r in out:
            fh.write(json.dumps(r) + "\n")

if __name__ == "__main__":
    main()

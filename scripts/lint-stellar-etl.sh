#!/usr/bin/env bash
# xdrlint on stellar-etl at the commit pinned in pins.toml ([pipelines.stellar_etl] commit), compared with the
# frozen lists in lint/expected/stellar-etl/: `make lint-stellar-etl`.
#
# Usage: scripts/lint-stellar-etl.sh [report dir]     (default reports; writes <dir>/lint-stellar-etl/)
#
# stellar-etl's go.mod requires a newer Go than the kit's toolchain, and a linter can only load packages its own
# toolchain accepts, so xdrlint is built here with the toolchain stellar-etl needs (pins.toml
# [pipelines.stellar_etl] go_toolchain) into the run directory; lint/bin/xdrlint is left alone. The run uses the
# shipped default profile (stellar-etl ships no xdrlint configuration) and the commit's frozen suppression file
# lint/expected/stellar-etl/<commit>.suppressions.yml. Every report must then be accounted for by one of:
#   - <commit>.expect.json: the expected reports, as (rule, file, function, suppressed) with a count (default 1),
#     compared by count; each suppression names the public finding record (findings/<id>/finding.json) that
#     accounts for its reports;
#   - <commit>.pending.json: reports awaiting an upstream report, as (rule, file, line) and nothing else, one entry per
#     report; their record and suppression stay in the private overlay until a maintainer approves them
#     (findings/README.md).
# The run fails on a report neither list accounts for, an expected report that is missing, a pending entry that
# matches no unsuppressed report, an unsuppressed report accounted for by the expected list instead of a
# suppression or a pending entry, an xdrlint exit status that disagrees with its report, or a suppression without a
# reason, reviewer, date, matching commit, line or anchor, or a finding record of the right range. Clean means
# that xdrlint exits 0 after the suppressions with no unsuppressed error left, pending ones included (the pending
# list, passed as -pending, keeps them out of the exit status, not out of the claim); the first line and the
# summary ("clean", "clean_statement") say
# whether it does, and XDRCHECK_LINT_REQUIRE_CLEAN=1 makes a run that is not clean fail.
#
# Sources, the toolchain and the modules come from the caches `make fetch` fills (scripts/fetch.d/lint-stellar-etl.sh);
# the run uses no network (GOPROXY=off), so it also runs under scripts/offline-run.sh (`OFFLINE=1`).
#
# Private overlay: with XDRCHECK_OVERLAY=DIR (outside this working tree) the run also loads
# DIR/lint/expected/stellar-etl/<commit>.suppressions.yml, every pending entry must then be resolved by an overlay
# suppression whose finding is an overlay-range record (above F-5000), and the reports go under DIR/reports/.
set -euo pipefail
cd "$(dirname "$0")/.."
root=$PWD
name=lint-stellar-etl
expected="$root/lint/expected/stellar-etl"

pin() { python3 -I -c 'import sys, tomllib
d = tomllib.load(open(sys.argv[1], "rb"))
for k in sys.argv[2].split("."): d = d[k]
print(d)' "$root/pins.toml" "$1"; }
commit="$(pin pipelines.stellar_etl.commit)"
toolchain="go$(pin pipelines.stellar_etl.go_toolchain)"
tree="${XDRCHECK_CACHE:-$HOME/.cache/xdrcheck}/lint/stellar-etl/$commit"
[ -f "$tree/.complete" ] || { echo "$name: no source tree for $commit; run make fetch" >&2; exit 2; }

overlay="${XDRCHECK_OVERLAY:-}"
if [ -n "$overlay" ]; then
  overlay="$(cd "$overlay" && pwd)"
  case "$overlay/" in "$root"/*) echo "$name: XDRCHECK_OVERLAY $overlay is inside the working tree" >&2; exit 2 ;; esac
  out="$overlay/reports/$name"
else
  out="${1:-reports}/$name"
  case "$out" in /*) ;; *) out="$root/$out" ;; esac
fi
# The interpreter: $PY when set (make passes its own), else .venv/bin/python, else python3.
py=${PY:-}
if [ -z "$py" ]; then
  py=python3
  [ -x "$root/.venv/bin/python" ] && py="$root/.venv/bin/python"
fi
"$py" -I -c 'import yaml' 2>/dev/null || { echo "$name: $py has no yaml module; set PY or run make fetch (it creates .venv)" >&2; exit 2; }

export GOTOOLCHAIN="$toolchain" GOFLAGS=-mod=readonly GOPROXY=off GOWORK=off XDRCHECK_PINS="$root/pins.toml"
rm -rf "$out"
mkdir -p "$out/.run"
(cd lint && go build -o "$out/.run/xdrlint" ./cmd/xdrlint) || { echo "$name: cannot build xdrlint with $toolchain" >&2; exit 2; }

cfg="$out/.run/xdrlint.yml"
{ echo "targetversion: $commit"
  [ -f "$expected/$commit.suppressions.yml" ] && echo "suppressions: $expected/$commit.suppressions.yml"
  true
} >"$cfg"
ovflag=()
if [ -n "$overlay" ]; then
  mkdir -p "$out/.run/overlay"
  ovsup="$overlay/lint/expected/stellar-etl/$commit.suppressions.yml"
  { [ -f "$ovsup" ] && echo "suppressions: $ovsup"; true; } >"$out/.run/overlay/xdrlint.yml"
  ovflag=(-overlay "$out/.run/overlay")
fi
# The pending list marks its rows `pending` in the report (awaiting an upstream report, not unexpected).
pendflag=()
[ -f "$expected/$commit.pending.json" ] && pendflag=(-pending "$expected/$commit.pending.json")
rc=0
# Exit 1 says that an unsuppressed error not on the pending list was reported; the judgement below checks that it
# agrees with the report, accounts for each unsuppressed error and states whether the run is clean (no unsuppressed
# error at all, pending ones included).
(cd "$tree" && "$out/.run/xdrlint" -profile default -config "$cfg" "${ovflag[@]}" "${pendflag[@]}" \
    -report "$out/$commit.json" -sarif "$out/$commit.sarif" ./...) >"$out/$commit.txt" 2>"$out/$commit.err" || rc=$?
if [ "$rc" -gt 1 ]; then
  echo "$name: xdrlint exit $rc" >&2
  sed 's/^/  /' "$out/$commit.err" >&2
  exit 1
fi

"$py" -I - "$root" "$commit" "$expected" "$out" "$overlay" "$toolchain" "$rc" <<'PY'
import collections, hashlib, json, os, re, sys
import yaml

root, commit, expected_dir, out, overlay, toolchain = sys.argv[1:7]
rc = int(sys.argv[7])
require_clean = os.environ.get("XDRCHECK_LINT_REQUIRE_CLEAN") == "1"
OVERLAY_BASE = 5000  # overlay records are numbered above F-5000 (findings/README.md)
problems = []

def suppressions(path, private):
    if not os.path.isfile(path):
        return []
    entries = yaml.safe_load(open(path)) or []
    home = os.path.join(overlay if private else root, "findings")
    for i, e in enumerate(entries):
        where = f"{'overlay ' if private else ''}{os.path.basename(path)} entry {i + 1}"
        for k in ("rule", "file", "reason", "finding", "reviewer", "date", "commit"):
            if not str(e.get(k) or "").strip():
                problems.append(f"{where}: no {k}")
        fid = str(e.get("finding") or "")
        m = re.fullmatch(r"F-([0-9]{4})", fid)
        if fid and not (m and (int(m.group(1)) > OVERLAY_BASE) == private and os.path.isfile(os.path.join(home, fid, "finding.json"))):
            problems.append(f"{where}: finding {fid} is not a {'overlay' if private else 'public'}-range record")
        if e.get("commit") and e["commit"] != commit:
            problems.append(f"{where}: reviewed against {e['commit']}, not {commit}")
        if not e.get("line") and not str(e.get("anchor") or "").strip() and not str(e.get("message") or "").strip():
            problems.append(f"{where}: names no line, anchor or message; a function-wide entry would accept a new report "
                            f"anywhere in {e.get('function') or 'the file'}")
    return entries

public = suppressions(os.path.join(expected_dir, commit + ".suppressions.yml"), False)
private = suppressions(os.path.join(overlay, "lint/expected/stellar-etl", commit + ".suppressions.yml"), True) if overlay else []
exp_path = os.path.join(expected_dir, commit + ".expect.json")
if not os.path.isfile(exp_path):
    problems.append(f"no frozen expected list {os.path.relpath(exp_path, root)}; a new commit is reviewed from empty")
# Both lists are multisets: an expected entry stands for `count` reports (default 1), a pending entry for one.
expect = collections.Counter()
for e in (json.load(open(exp_path))["reports"] if os.path.isfile(exp_path) else []):
    expect[(e["rule"], e["file"], e["function"], e["suppressed"])] += max(int(e.get("count") or 1), 1)
pend_path = os.path.join(expected_dir, commit + ".pending.json")
def norm(msg):
    """framework.NormaliseMessage: the message without the line numbers it names."""
    msg = re.sub(r"\b([A-Za-z0-9_.\-]+\.go):[0-9]+(?::[0-9]+)?", r"\1", msg)
    msg = re.sub(r"\blines [0-9]+(?:[-–][0-9]+)?", "lines", msg)
    msg = re.sub(r"\bline [0-9]+", "line", msg)
    return " ".join(msg.split())

def pending_key(p):
    if "site2" in p:
        return (p["rule"], "site2", p["site2"])
    if "site" in p:
        return (p["rule"], "site", p["site"])
    if "message" in p:
        return (p["rule"], p["file"], p.get("function", ""), norm(p["message"]))
    return (p["rule"], p["file"], p["line"])
pending = collections.Counter(pending_key(p) for p in (json.load(open(pend_path))["pending"] if os.path.isfile(pend_path) else []))

rows = [r for r in json.load(open(os.path.join(out, commit + ".json")))["rows"] if r["tool"] == "lint"]
left, pending_left, unexpected, resolved = expect.copy(), pending.copy(), collections.Counter(), []
unsup = {"errors": 0, "warnings": 0, "pending": 0, "pending_errors": 0}
marked = 0  # unsuppressed errors xdrlint itself marked pending (-pending); they do not set its exit status
for r in rows:
    l = r["lint"]
    k = (l["rule"], l["location"]["file"], l["location"].get("function", ""), l["suppressed"])
    t = (l["rule"], l["location"]["file"], l["location"]["line"])
    fn, msg = l["location"].get("function", ""), norm(l.get("message", ""))
    for alt in ((l["rule"], "site", hashlib.sha256(f"xdrlint.site/v1:{t[0]}:{t[1]}:{max(t[2], 1)}".encode()).hexdigest()),
                (l["rule"], t[1], fn, msg),
                (l["rule"], "site2", hashlib.sha256(f"xdrlint.site/v2:{t[0]}:{t[1]}:{fn}:{msg}".encode()).hexdigest())):
        if pending_left[t] > 0:
            break
        if pending_left[alt] > 0:
            t = alt
    shown = f"{k[0]} {k[1]}" + (f" in {k[2]}" if k[2] else "") + f" (line {t[2]})" + (" (suppressed)" if k[3] else "")
    error = l.get("severity", "error") == "error"
    if not l["suppressed"]:
        unsup["errors"] += error
        unsup["warnings"] += l.get("severity") == "warning"
        marked += error and r.get("expectation") == "pending"
    if pending_left[t] > 0 and not overlay and not l["suppressed"]:
        pending_left[t] -= 1
        unsup["pending"] += 1
        unsup["pending_errors"] += error
    elif pending_left[t] > 0 and overlay and l["suppressed"] and int((r.get("finding") or "F-0000")[2:]) > OVERLAY_BASE:
        pending_left[t] -= 1
        resolved.append(k)
    elif left[k] > 0:
        left[k] -= 1
        if not l["suppressed"]:
            problems.append(f"unsuppressed report accounted for only by the expected list: {shown}; "
                            "a report is suppressed with a reviewed reason or awaiting an upstream report")
    else:
        unexpected[shown] += 1
for k in resolved:
    if left[k] > 0:
        left[k] -= 1
problems += [f"unexpected report: {u}" + (f" ×{n}" if n > 1 else "") for u, n in sorted(unexpected.items())]
problems += [f"missing report: {k[0]} {k[1]} in {k[2]}" + (" (suppressed)" if k[3] else "") + (f" ×{n}" if n > 1 else "")
             for k, n in sorted((+left).items())]
for t in sorted(+pending_left):
    problems.append(f"pending entry {t[0]} {t[1]}:{str(t[2])[:12]} " + ("is not resolved by an overlay suppression with an overlay-range finding"
                    if overlay else "matches no unsuppressed report (the site moved or the report went away)"))
if rc != (1 if unsup["errors"] - marked else 0):
    problems.append(f"xdrlint exit {rc}, but its report has {unsup['errors']} unsuppressed error(s), {marked} of them marked pending")
# Clean: xdrlint exits 0 with the shipped profile after the suppressions, the pending list not excusing anything.
# -pending keeps the exit at 0 for pending errors, so clean is read from the report: no unsuppressed error at all.
clean = rc == 0 and unsup["errors"] == 0
if clean:
    clean_statement = "clean: xdrlint exits 0 with the shipped profile after the suppressions"
else:
    n = unsup["errors"]
    why = (f"{n} unsuppressed error{'' if n == 1 else 's'}, "
           + (("all " if n > 1 else "") + "awaiting an upstream report" if unsup["pending_errors"] == n
              else f"{unsup['pending_errors']} of them awaiting an upstream report"))
    clean_statement = (f"not lint-clean: {why} with the shipped profile after the suppressions (xdrlint exits 0 only because "
                       "the pending list marks them pending)" if rc == 0 else
                       f"not lint-clean: xdrlint exits {rc} with the shipped profile ({why})")
    if require_clean:
        problems.append(f"{clean_statement} (XDRCHECK_LINT_REQUIRE_CLEAN=1)")

n_pending = 0 if overlay else sum(pending.values())
verdict = "PASS" if not problems else "FAIL"
first = (f"lint-stellar-etl: stellar-etl {commit[:8]} ({toolchain}): {len(public) + len(private)} suppressions and "
         f"{n_pending} awaiting an upstream report, covering {len(rows)} reports — every report accounted for: {verdict}; {clean_statement}")
md = [first, "", "Profile `default`; frozen lists in `lint/expected/stellar-etl/`.",
      "Findings under embargo, if any, are not represented in this report; the private acceptance run covers them.",
      "A report awaiting an upstream report is one this run found and a maintainer has not yet approved for reporting; "
      "its record and its suppression are kept privately until then.", "",
      "| Rule | File | Function | Finding | Reason |", "|---|---|---|---|---|"]
md += [f"| {e['rule']} | `{e['file']}` | {e.get('function', '')}{' line ' + str(e['line']) if e.get('line') else ''} | {e.get('finding', '')} | {e.get('reason', '')} |" for e in public + private]
if problems:
    md += ["", "## Problems", ""] + [f"- {p}" for p in problems]
summary = {"name": "lint-stellar-etl", "commit": commit, "toolchain": toolchain, "overlay": bool(overlay),
           "reports": len(rows), "pending": n_pending, "first_line": first, "problems": problems,
           "suppressions": [{k: e.get(k) for k in ("rule", "file", "function", "finding", "reason", "line", "anchor")} for e in public + private],
           "exit": rc, "clean": clean, "clean_statement": clean_statement, "unsuppressed": unsup}
open(os.path.join(out, "..", "lint-stellar-etl.md"), "w").write("\n".join(md) + "\n")
with open(os.path.join(out, "..", "lint-stellar-etl.summary.json"), "w") as f:
    json.dump(summary, f, indent=2)
    f.write("\n")
print(first)
for p in problems:
    print("  " + p, file=sys.stderr)
sys.exit(1 if problems else 0)
PY

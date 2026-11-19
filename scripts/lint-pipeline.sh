#!/usr/bin/env bash
# lint-current: xdrlint on wallet-backend, compared with frozen expected lists.
#
# Usage: scripts/lint-pipeline.sh current|before-after|selftest [report dir]
#
#   current       the commit pinned in pins.toml ([pipelines.wallet_backend] current): `make lint-wallet-backend`
#   before-after  every commit of the before/after table in lint/expected/wallet-backend/plan.json:
#                 `make lint-before-after`
#   selftest      shows that the check can fail (`make lint-selftest`): on a copy of the pinned commit's tree
#                 and frozen lists it runs `current` unchanged (must pass), with one violation added to the
#                 source (must fail on the unexpected report), with one suppression that matches nothing added
#                 (must fail on its XDR000 report), with a second report added inside a suppressed function (must
#                 fail on that report), with a suppression widened to its whole function (must fail on the
#                 policy) and with one pending entry that matches nothing added (must fail on the stale entry)
#
# Each commit is linted with the shipped profile (`-profile wallet-backend`) and the commit's frozen suppression
# file lint/expected/wallet-backend/<commit>.suppressions.yml. Every report must then be accounted for by one of:
#   - <commit>.expect.json: the expected reports, as (rule, file, function, suppressed) with a count (default 1).
#     The comparison is by count, so a second report of a listed key is unexpected;
#   - <commit>.pending.json: reports awaiting an upstream report, as (rule, file, line) and nothing else, one entry per
#     report, or as (rule, site) where site is the hex SHA-256 of "xdrlint.site/v1:<rule>:<file>:<line>" for a site
#     the public tree must not name yet;
#     report. A report on this list is a defect our run found that is not yet reported upstream; its finding
#     record and its suppression (site and reason) stay in the private overlay until a maintainer approves it, so the
#     public tree names the site and no more. A pending report must be unsuppressed in a public run.
# Clean, the claim made for the pinned commit, means that xdrlint exits 0 with the shipped profile after the
# suppressions. A suppression is a reviewed accepted site or one with an upstream item, never a linter false
# positive (that is fixed in the rule). The pending list is passed to xdrlint (-pending), which marks those rows
# `pending` and leaves them out of its exit status; they are still unsuppressed errors, so the run can pass its
# accounting but is not clean. Clean is therefore read from the report (no unsuppressed error, pending included),
# not from the exit status alone; the first line and <name>.summary.json ("clean", "clean_statement") say which.
# With XDRCHECK_LINT_REQUIRE_CLEAN=1 a pinned commit that is not clean fails the run.
# The run fails when:
#   - a report is accounted for by neither list, or an expected report is missing: an extra finding, a changed
#     site, or a stale suppression (a suppression that matches nothing is itself an XDR000 report);
#   - a pending entry matches no unsuppressed report (the site moved or the report went away);
#   - xdrlint's exit status disagrees with its report (exit 1 if and only if an unsuppressed error), or it did
#     not complete (exit 2, for example when no go-stellar-sdk package is loaded);
#   - at the pinned commit, an unsuppressed report is accounted for by the expected list instead of being
#     suppressed or pending;
#   - a suppression has no reason, no reviewer or date, was reviewed against another commit, names no line or
#     anchor (a function-wide entry would accept a new report anywhere in the function), or names no finding
#     record: a public suppression a public-range ID (F-0001…) under findings/, an overlay suppression an
#     overlay-range ID (above F-5000) under the overlay's findings/;
#   - the pinned commit has no frozen list (moving the pin means a new list, reviewed from empty), or more
#     suppressions plus pending entries than the ceiling recorded for it in plan.json;
#   - (before-after) a row of the table does not show the recorded counts: a rule that no longer fires at its
#     pre-fix commit, or that fires at its fixed one.
# It writes one xcc.report/v1 report and one SARIF log per commit, plus <name>.md and <name>.summary.json,
# whose first line states the counts of suppressions and of reports awaiting an upstream report, and
# <name>.verdict.json: the same outcome (per commit: report counts per rule and severity, pending counts, clean)
# with no site in it, which CI uploads when it withholds a report that names a site pending finding review.
#
# Sources come from the cache that `make fetch` fills (scripts/fetch.d/lint-wallet-backend.sh); the run itself
# uses no network (GOPROXY=off), so it also runs under scripts/offline-run.sh (`OFFLINE=1`).
#
# Private overlay: with XDRCHECK_OVERLAY=DIR (a directory outside this working tree) the run also loads
# DIR/lint/xdrlint.yml (profile additions) and DIR/lint/expected/wallet-backend/<commit>.suppressions.yml; the
# expected reports of DIR/lint/expected/wallet-backend/<commit>.expect.json are added to the public list, every
# pending entry must then be resolved by an overlay suppression, and
# DIR/lint/expected/wallet-backend/suppression-ceiling.json ({"<commit>": n}) replaces the public ceiling. Its
# reports are written under DIR/reports/, never into this tree, and carry header.mode.overlay = true. Public runs
# never read an overlay.
set -euo pipefail
cd "$(dirname "$0")/.."
root=$PWD
mode="${1:-}"
case "$mode" in
  current) name=lint-wallet-backend ;;
  before-after) name=lint-before-after ;;
  selftest) name=lint-selftest ;;
  *) echo "usage: $0 current|before-after|selftest [report dir]" >&2; exit 2 ;;
esac
# XDRCHECK_LINT_EXPECTED and XDRCHECK_CACHE point the run at copies (selftest only).
expected="${XDRCHECK_LINT_EXPECTED:-$root/lint/expected/wallet-backend}"
plan="$expected/plan.json"
cache="${XDRCHECK_CACHE:-$HOME/.cache/xdrcheck}/lint/wallet-backend"

if [ "$mode" = selftest ]; then
  [ -z "${XDRCHECK_OVERLAY:-}" ] || { echo "$name: runs without an overlay" >&2; exit 2; }
  out="${2:-reports}/$name"
  case "$out" in /*) ;; *) out="$root/$out" ;; esac
  current="$(python3 -I -c 'import sys, tomllib; print(tomllib.load(open(sys.argv[1], "rb"))["pipelines"]["wallet_backend"]["current"])' "$root/pins.toml")"
  [ -f "$cache/$current/.complete" ] || { echo "$name: no source tree for $current in $cache; run make fetch" >&2; exit 2; }
  rm -rf "$out"
  mkdir -p "$out/cache/lint/wallet-backend"
  # case <label> <want: pass|fail> <text the failing run must print>
  run_case() {
    local label=$1 want=$2 text=$3 rc=0
    XDRCHECK_CACHE="$out/cache" XDRCHECK_LINT_EXPECTED="$out/expected" "$root/scripts/lint-pipeline.sh" current "$out/$label" >"$out/$label.log" 2>&1 || rc=$?
    # The case's reports are deliberately wrong; only its log is kept, so no report of it reaches the findings check.
    rm -rf "$out/$label"
    if [ "$want" = pass ] && [ "$rc" -eq 0 ]; then echo "$name: $label: passes, as it must"; return 0; fi
    if [ "$want" = fail ] && [ "$rc" -ne 0 ] && grep -qF -- "$text" "$out/$label.log"; then
      echo "$name: $label: fails, as it must: $(grep -F -m1 -- "$text" "$out/$label.log" | sed 's/^ *//')"
      return 0
    fi
    echo "$name: $label: exit $rc, want $want${text:+ with \"$text\"}" >&2
    sed 's/^/  /' "$out/$label.log" >&2
    return 1
  }
  # Widen every suppression to its whole function: drop the keys that pin it to a site (line, anchor, message).
  widen() { sed -i -E '/^  (line|anchor|message): /d' "$1"; }
  fresh() {
    rm -rf "$out/cache/lint/wallet-backend/$current" "$out/expected"
    cp -R "$cache/$current" "$out/cache/lint/wallet-backend/$current"
    cp -R "$root/lint/expected/wallet-backend" "$out/expected"
  }
  status=0
  fresh
  run_case unchanged pass "" || status=1

  fresh
  # An operation source used as a participant key without being reduced to its base account (XDR102).
  cat >"$out/cache/lint/wallet-backend/$current/internal/indexer/processors/xdrlint_selftest.go" <<'GO'
package processors

import "github.com/stellar/go-stellar-sdk/xdr"

func selftestParticipants(op xdr.Operation, participants map[string]struct{}) {
	if op.SourceAccount != nil {
		participants[op.SourceAccount.Address()] = struct{}{}
	}
}
GO
  run_case extra-finding fail "unexpected report: XDR102 internal/indexer/processors/xdrlint_selftest.go" || status=1

  fresh
  cat >>"$out/expected/$current.suppressions.yml" <<'YML'
- rule: XDR201
  file: internal/services/sep41/processor.go
  function: processor.processEvent
  line: 207
  reason: "A suppression whose site does not report this rule: stale."
  finding: F-0001
  commit: COMMIT
  reviewer: kit maintainer
  date: 2026-11-12
YML
  sed -i "s/^  commit: COMMIT$/  commit: $current/" "$out/expected/$current.suppressions.yml"
  run_case stale-suppression fail "unexpected report: XDR000" || status=1

  fresh
  # A second authorization-tree participant inside the suppressed function, on a line of its own (the no-op case
  # arm, so no other line moves): the reviewed suppression names its line, so this report is not accepted with it.
  f="$out/cache/lint/wallet-backend/$current/internal/indexer/processors/contract_deploy.go"
  [ "$(sed -n 100p "$f")" = $'\t\t// no-op' ] || { echo "$name: contract_deploy.go:100 is not the no-op arm the selftest edits" >&2; exit 2; }
  sed -i '100s/.*/\t\tfor _, a := range invokeHostOp.Auth { if s, err := a.Credentials.MustAddress().Address.String(); err == nil { stateChanges = append(stateChanges, builder.WithAccount(s).Build()) } }/' "$f"
  run_case same-function fail "unexpected report: XDR301 internal/indexer/processors/contract_deploy.go in ContractDeployProcessor.ProcessOperation (line 100)" || status=1
  # The same edit with the suppression widened to the whole function: the second report is now suppressed, and the
  # expected list, compared by count, still turns it away.
  widen "$out/expected/$current.suppressions.yml"
  run_case same-function-counted fail "unexpected report: XDR301 internal/indexer/processors/contract_deploy.go in ContractDeployProcessor.ProcessOperation (line 100) (suppressed)" || status=1

  fresh
  # The reviewed suppression widened to its whole function.
  widen "$out/expected/$current.suppressions.yml"
  run_case function-wide-suppression fail "names no line, anchor or message" || status=1

  fresh
  python3 -I -c 'import json, sys
p = sys.argv[1]; d = json.load(open(p))
d["pending"].append({"rule": "XDR201", "file": "internal/services/sep41/processor.go", "line": 1})
open(p, "w").write(json.dumps(d, indent=2) + "\n")' "$out/expected/$current.pending.json"
  run_case stale-pending fail "pending entry XDR201 internal/services/sep41/processor.go:1 matches no unsuppressed report" || status=1
  rm -rf "$out/cache" "$out/expected"
  exit "$status"
fi

overlay="${XDRCHECK_OVERLAY:-}"
if [ -n "$overlay" ]; then
  overlay="$(cd "$overlay" && pwd)"
  case "$overlay/" in "$root"/*) echo "$name: XDRCHECK_OVERLAY $overlay is inside the working tree; the overlay must live outside it" >&2; exit 2 ;; esac
  out="$overlay/reports/$name"
else
  out="${2:-reports}/$name"
  case "$out" in /*) ;; *) out="$root/$out" ;; esac
fi

# The interpreter: $PY when set (make passes its own), else .venv/bin/python, else python3.
py=${PY:-}
if [ -z "$py" ]; then
  py=python3
  [ -x "$root/.venv/bin/python" ] && py="$root/.venv/bin/python"
fi
"$py" -I -c 'import yaml' 2>/dev/null || { echo "$name: $py has no yaml module; set PY or run make fetch (it creates .venv)" >&2; exit 2; }

export GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOPROXY=off GOWORK=off XDRCHECK_PINS="$root/pins.toml"
# Rebuild so a stale binary never judges the run.
(cd lint && go build -o bin/ ./cmd/xdrlint) || { echo "$name: cannot build lint/bin/xdrlint" >&2; exit 2; }
xdrlint="$root/lint/bin/xdrlint"

current="$("$py" -I -c 'import sys, tomllib; print(tomllib.load(open(sys.argv[1], "rb"))["pipelines"]["wallet_backend"]["current"])' "$root/pins.toml")"
if [ "$mode" = current ]; then
  commits=("$current")
else
  mapfile -t commits < <("$py" -I -c 'import json, sys; print("\n".join(json.load(open(sys.argv[1]))["commits"]))' "$plan")
fi
mapfile -t patterns < <("$py" -I -c 'import json, sys; print("\n".join(json.load(open(sys.argv[1]))["packages"]))' "$plan")

rm -rf "$out"
mkdir -p "$out/.run"
: >"$out/.run/runs.txt"
status=0
for c in "${commits[@]}"; do
  tree="$cache/$c"
  if [ ! -f "$tree/.complete" ]; then
    echo "$name: no source tree for $c in $cache; run make fetch" >&2
    exit 2
  fi
  if [ ! -f "$expected/$c.expect.json" ]; then
    echo "$name: $c has no frozen expected list ($expected/$c.expect.json); a new commit is reviewed from empty" >&2
    status=1
    continue
  fi
  cfg="$out/.run/$c.xdrlint.yml"
  { echo "targetversion: $c"
    [ -f "$expected/$c.suppressions.yml" ] && echo "suppressions: $expected/$c.suppressions.yml"
    true
  } >"$cfg"
  ovflag=()
  if [ -n "$overlay" ]; then
    ovdir="$out/.run/overlay-$c"
    mkdir -p "$ovdir"
    ovexp="$overlay/lint/expected/wallet-backend"
    { [ -f "$overlay/lint/xdrlint.yml" ] && cat "$overlay/lint/xdrlint.yml"
      [ -f "$ovexp/$c.suppressions.yml" ] && echo "suppressions: $ovexp/$c.suppressions.yml"
      true
    } >"$ovdir/xdrlint.yml"
    ovflag=(-overlay "$ovdir")
  fi
  present=()
  for p in "${patterns[@]}"; do [ -d "$tree/${p%/...}" ] && present+=("$p"); done
  # The pending list marks its rows `pending` in the report (awaiting an upstream report, not unexpected).
  pendflag=()
  [ -f "$expected/$c.pending.json" ] && pendflag=(-pending "$expected/$c.pending.json")
  rc=0
  # Exit 1 says that an unsuppressed error not on the pending list was reported. The judgement below checks that it
  # agrees with the report, accounts for each unsuppressed error (pending or unexpected), and states whether the
  # pinned commit runs clean (no unsuppressed error at all, pending ones included).
  (cd "$tree" && "$xdrlint" -profile wallet-backend -config "$cfg" "${ovflag[@]}" "${pendflag[@]}" \
      -report "$out/$c.json" -sarif "$out/$c.sarif" "${present[@]}") >"$out/$c.txt" 2>"$out/$c.err" || rc=$?
  if [ "$rc" -gt 1 ]; then
    echo "$name: $c: xdrlint exit $rc" >&2
    sed 's/^/  /' "$out/$c.err" >&2
    status=1
  fi
  echo "$c $rc" >>"$out/.run/runs.txt"
done

# The comparison, the policy checks, the before/after table and the summary.
"$py" -I - "$root" "$mode" "$name" "$out" "$current" "$overlay" "$expected" <<'PY' || status=1
import collections, hashlib, json, os, re, sys
import yaml

root, mode, name, out, current, overlay, expected_dir = sys.argv[1:8]
require_clean = os.environ.get("XDRCHECK_LINT_REQUIRE_CLEAN") == "1"
plan = json.load(open(os.path.join(expected_dir, "plan.json")))
order = plan["commits"] + ([current] if current not in plan["commits"] else [])
ov_expected = os.path.join(overlay, "lint/expected/wallet-backend") if overlay else ""
OVERLAY_BASE = 5000  # overlay records are numbered above F-5000 (see findings/README.md)
problems = []

def load_json(path, key):
    return json.load(open(path))[key] if os.path.isfile(path) else []

def load_entries(c, path, private):
    """Suppression entries of one file, with their policy checked."""
    if not os.path.isfile(path):
        return []
    entries = []
    for i, e in enumerate(yaml.safe_load(open(path)) or []):
        where = f"{'overlay ' if private else ''}{os.path.basename(path)} entry {i + 1}"
        for k in ("rule", "file", "reason", "finding", "reviewer", "date", "commit"):
            if not str(e.get(k) or "").strip():
                problems.append(f"{c[:8]}: {where}: no {k}")
        fid = str(e.get("finding") or "")
        m = re.fullmatch(r"F-([0-9]{4})", fid)
        home = os.path.join(overlay if private else root, "findings")
        if fid and not (m and (int(m.group(1)) > OVERLAY_BASE) == private and os.path.isfile(os.path.join(home, fid, "finding.json"))):
            problems.append(f"{c[:8]}: {where}: finding {fid} is not a {'overlay' if private else 'public'}-range record under "
                            f"{'the overlay' if private else 'findings'}/{fid}/finding.json")
        if e.get("commit") and e["commit"] != c:
            problems.append(f"{c[:8]}: {where}: reviewed against {e['commit']}, not this commit")
        if not e.get("line") and not str(e.get("anchor") or "").strip() and not str(e.get("message") or "").strip():
            problems.append(f"{c[:8]}: {where}: names no line, anchor or message; a function-wide entry would accept a new report "
                            f"anywhere in {e.get('function') or 'the file'}")
        entries.append(e)
    return entries

def norm(msg):
    """framework.NormaliseMessage: the message without the line numbers it names."""
    msg = re.sub(r"\b([A-Za-z0-9_.\-]+\.go):[0-9]+(?::[0-9]+)?", r"\1", msg)
    msg = re.sub(r"\blines [0-9]+(?:[-–][0-9]+)?", "lines", msg)
    msg = re.sub(r"\bline [0-9]+", "line", msg)
    return " ".join(msg.split())

def key(r):
    l = r["lint"]
    return (l["rule"], l["location"]["file"], l["location"].get("function", ""), l["suppressed"])

def show(k, line=None):
    s = f"{k[0]} {k[1]}" + (f" in {k[2]}" if k[2] else "") + (f" (line {line})" if line else "")
    return s + (" (suppressed)" if k[3] else "")

per_commit = {}
for line in open(os.path.join(out, ".run/runs.txt")):
    c, rc = line.split()
    rc = int(rc)
    public = load_entries(c, os.path.join(expected_dir, c + ".suppressions.yml"), False)
    private = load_entries(c, os.path.join(ov_expected, c + ".suppressions.yml"), True) if overlay else []
    rp = os.path.join(out, c + ".json")
    rows = [r for r in json.load(open(rp))["rows"] if r["tool"] == "lint"] if os.path.isfile(rp) else []
    if not os.path.isfile(rp):
        problems.append(f"{c[:8]}: no report written")
    # Both lists are multisets: an expected entry stands for `count` reports (default 1) and a pending entry for
    # one, so a second report of an accounted-for key is unexpected however it is suppressed.
    expect = collections.Counter()
    for e in load_json(os.path.join(expected_dir, c + ".expect.json"), "reports") + \
            (load_json(os.path.join(ov_expected, c + ".expect.json"), "reports") if overlay else []):
        k = (e["rule"], e["file"], e["function"], e["suppressed"])
        if e.get("message"):
            k += (norm(e["message"]),)
        expect[k] += max(int(e.get("count") or 1), 1)
    def pending_key(p):
        if "site2" in p:
            return (p["rule"], "site2", p["site2"])
        if "site" in p:
            return (p["rule"], "site", p["site"])
        if "message" in p:
            return (p["rule"], p["file"], p.get("function", ""), norm(p["message"]))
        return (p["rule"], p["file"], p["line"])
    pending = collections.Counter(pending_key(p) for p in load_json(os.path.join(expected_dir, c + ".pending.json"), "pending"))

    left, pending_left, unexpected = expect.copy(), pending.copy(), collections.Counter()
    by_list = []  # unsuppressed reports accounted for only by the expected list
    resolved = []  # (overlay run) pending reports resolved by an overlay suppression
    # "marked": unsuppressed errors xdrlint itself marked pending (-pending); they do not set its exit status.
    unsup = {"errors": 0, "warnings": 0, "other": 0, "pending": 0, "pending_errors": 0, "marked": 0}
    for r in rows:
        k, l = key(r), r["lint"]
        triple = (l["rule"], l["location"]["file"], l["location"]["line"])
        fn, msg = l["location"].get("function", ""), norm(l.get("message", ""))
        for alt in ((l["rule"], "site", hashlib.sha256(f"xdrlint.site/v1:{triple[0]}:{triple[1]}:{max(triple[2], 1)}".encode()).hexdigest()),
                    (l["rule"], triple[1], fn, msg),
                    (l["rule"], "site2", hashlib.sha256(f"xdrlint.site/v2:{triple[0]}:{triple[1]}:{fn}:{msg}".encode()).hexdigest())):
            if pending_left[triple] > 0:
                break
            if pending_left[alt] > 0:
                triple = alt
        if not l["suppressed"]:
            sev = l.get("severity", "error")
            unsup["errors" if sev == "error" else "warnings" if sev == "warning" else "other"] += 1
            unsup["marked"] += sev == "error" and r.get("expectation") == "pending"
        if pending_left[triple] > 0 and not overlay and not l["suppressed"]:
            pending_left[triple] -= 1  # awaiting an upstream report; its record and suppression are private
            unsup["pending"] += 1
            unsup["pending_errors"] += l.get("severity", "error") == "error"
        elif pending_left[triple] > 0 and overlay and l["suppressed"] and int((r.get("finding") or "F-0000")[2:]) > OVERLAY_BASE:
            pending_left[triple] -= 1
            resolved.append(k)
        elif left[k + (msg,)] > 0 or left[k] > 0:
            left[k + (msg,) if left[k + (msg,)] > 0 else k] -= 1
            if not l["suppressed"]:
                by_list.append(show(k, l["location"]["line"]))
        else:
            unexpected[show(k, l["location"]["line"])] += 1
    for k in resolved:  # an overlay expected list may list them too; they are accounted for either way
        if left[k] > 0:
            left[k] -= 1
    for u, n in sorted(unexpected.items()):
        problems.append(f"{c[:8]}: unexpected report: {u}" + (f" ×{n}" if n > 1 else ""))
    for k, n in sorted((+left).items()):
        problems.append(f"{c[:8]}: missing report: {show(k)}" + (f" ×{n}" if n > 1 else ""))
    for t in sorted(+pending_left):
        if overlay:
            problems.append(f"{c[:8]}: pending entry {t[0]} {t[1]}:{t[2][:12]} is not resolved by an overlay suppression with an overlay-range finding")
        else:
            problems.append(f"{c[:8]}: pending entry {t[0]} {t[1]}:{str(t[2])[:12]}{' in ' + t[2] if len(t) == 4 else ''} matches no unsuppressed report (the site moved or the report went away)")
    if rc > 1:
        problems.append(f"{c[:8]}: xdrlint exit {rc} (see {c}.err)")
    elif rc != (1 if unsup["errors"] - unsup["marked"] else 0):
        # The run honours xdrlint's exit status: it must agree with the reports it wrote (an error the pending list
        # names is marked pending and does not set the exit status).
        problems.append(f"{c[:8]}: xdrlint exit {rc}, but its report has {unsup['errors']} unsuppressed error(s), "
                        f"{unsup['marked']} of them marked pending")
    # Clean (the pinned commit's claim): xdrlint exits 0 with the shipped profile after the suppressions, the pending
    # list not excusing anything. -pending keeps the exit at 0 for pending errors, so clean is read from the report:
    # no unsuppressed error at all.
    clean = rc == 0 and unsup["errors"] == 0
    if c == current:
        # At the pinned commit an unsuppressed report is awaiting an upstream report or wrong: accepting one by listing
        # it would let the run pass without a reviewed suppression.
        for s in by_list:
            problems.append(f"{c[:8]}: unsuppressed report accounted for only by the expected list: {s}; "
                            "at the pinned commit a report is suppressed with a reviewed reason or awaiting an upstream report")
        if require_clean and not clean:
            problems.append(f"{c[:8]}: not clean (XDRCHECK_LINT_REQUIRE_CLEAN=1): xdrlint exits {rc} with "
                            f"{unsup['errors']} unsuppressed error(s), {unsup['pending_errors']} of them awaiting an upstream report")
    per_commit[c] = {"rc": rc, "public": public, "private": private, "rows": rows, "pending": pending,
                     "clean": clean, "unsuppressed": unsup, "report": os.path.isfile(rp)}

    if c == current:
        ceilings = plan.get("suppression_ceiling", {})
        ov_ceiling = os.path.join(ov_expected, "suppression-ceiling.json") if overlay else ""
        if ov_ceiling and os.path.isfile(ov_ceiling):
            ceilings = json.load(open(ov_ceiling))
        ceiling = ceilings.get(c)
        # Public run: public suppressions plus pending entries; private run: public plus overlay suppressions.
        used = len(public) + (len(private) if overlay else len(pending))
        if ceiling is None:
            problems.append(f"{c[:8]}: no suppression ceiling is recorded for the pinned commit")
        elif used > ceiling:
            problems.append(f"{c[:8]}: {used} suppressions and pending entries, above the recorded ceiling {ceiling}")

def count(c, row):
    return sum(1 for r in per_commit[c]["rows"]
               if r["lint"]["rule"] == row["rule"] and r["lint"]["location"]["file"] == row["file"]
               and (not row.get("function") or r["lint"]["location"].get("function") == row["function"]))

table = []
if mode == "before-after":
    for row in plan["rows"]:
        obs, ok = {}, True
        for side in ("before", "after"):
            c = row[side]["commit"]
            if c not in per_commit:
                problems.append(f"row {row['id']}: {side} commit {c[:8]} was not run")
                ok = False
                continue
            obs[side] = count(c, row)
            if obs[side] != row[side]["reports"]:
                problems.append(f"row {row['id']}: {row['rule']} {row['file']} at {side} {c[:8]}: {obs[side]} reports, recorded {row[side]['reports']}")
                ok = False
        table.append((row, obs, ok))

def suppression_lines(entries):
    lines = []
    for e in entries:
        at = e.get("function") or ""
        if e.get("line"):
            at = (at + " " if at else "") + f"line {e['line']}"
        if e.get("anchor"):
            at = (at + " " if at else "") + f"`{e['anchor']}`"
        lines.append(f"| {e['rule']} | `{e['file']}` | {at} | {e.get('finding', '')} | {e.get('reason', '')} |")
    return lines

verdict = "PASS" if not problems else "FAIL"
n_pending = lambda v: 0 if overlay else sum(v["pending"].values())
n_sup = lambda v: len(v["public"]) + len(v["private"])

def plural(n, word):
    return f"{n} {word}{'' if n == 1 else 's'}"

def clean_statement(v):
    """Whether xdrlint runs clean (exit 0 with the shipped profile after the suppressions), and why not."""
    if v["rc"] > 1:
        return f"not lint-clean: xdrlint did not complete (exit {v['rc']})"
    if v["clean"]:
        return "clean: xdrlint exits 0 with the shipped profile after the suppressions"
    u = v["unsuppressed"]
    why = plural(u["errors"], "unsuppressed error")
    if u["pending_errors"] == u["errors"]:
        why += ", all awaiting an upstream report" if u["errors"] > 1 else ", awaiting an upstream report"
    else:
        why += f", {u['pending_errors']} of them awaiting an upstream report"
    if v["rc"] == 0:
        return (f"not lint-clean: {why} with the shipped profile after the suppressions "
                "(xdrlint exits 0 only because the pending list marks them pending)")
    return f"not lint-clean: xdrlint exits {v['rc']} with the shipped profile ({why})"

if mode == "current" and current in per_commit:
    v = per_commit[current]
    first = (f"{name}: wallet-backend {current[:8]}: {n_sup(v)} suppressions and {n_pending(v)} awaiting an upstream report, "
             f"covering {len(v['rows'])} reports — every report accounted for: {verdict}; {clean_statement(v)}")
else:
    first = (f"{name}: {len(per_commit)} wallet-backend commits: {sum(n_sup(v) for v in per_commit.values())} suppressions, "
             f"{sum(n_pending(v) for v in per_commit.values())} awaiting an upstream report, {len(table)} before/after rows — {verdict}")
md = [first, "", "Profile `lint/profiles/wallet-backend.yml`; frozen lists in `lint/expected/wallet-backend/`.",
      "Findings under embargo, if any, are not represented in this report; the private acceptance run covers them.",
      "A report awaiting an upstream report is one this run found and a maintainer has not yet approved for reporting; "
      "its record and its suppression are kept privately until then."]
summary = {"name": name, "mode": mode, "overlay": bool(overlay), "commits": []}
if current in per_commit:
    # The pinned commit's claim, apart from the accounting verdict: clean only when xdrlint exits 0.
    summary["clean"] = per_commit[current]["clean"]
    summary["clean_statement"] = clean_statement(per_commit[current])
for c in order:
    if c not in per_commit:
        continue
    v = per_commit[c]
    entries = v["public"] + v["private"]
    summary["commits"].append({"commit": c, "exit": v["rc"], "reports": len(v["rows"]), "pending": n_pending(v),
                               "suppressions": [{k: e.get(k) for k in ("rule", "file", "function", "anchor", "finding", "reason", "line")} for e in entries],
                               "pinned": c == current, "clean": v["clean"], "clean_statement": clean_statement(v),
                               "unsuppressed": {k: v["unsuppressed"][k] for k in ("errors", "warnings", "pending", "pending_errors")}})
    md += ["", f"## {c}", "", f"{len(v['rows'])} reports, {len(entries)} suppressions, {n_pending(v)} awaiting an upstream report.", ""]
    if c == current:
        md += [f"At the pinned commit: {clean_statement(v)}.", ""]
    if entries:
        md += ["| Rule | File | Function / anchor | Finding | Reason |", "|---|---|---|---|---|"] + suppression_lines(entries)
if table:
    md += ["", "## Before and after", "", "| Row | Change | Rule | File | Before | Reports | After | Reports | Observed |", "|---|---|---|---|---|---|---|---|---|"]
    for row, obs, ok in table:
        md.append(f"| {row['id']} | {row['change']} | {row['rule']} | `{row['file']}`{' ' + row['function'] if row.get('function') else ''} | {row['before']['commit'][:8]} | "
                  f"{obs.get('before', '?')} | {row['after']['commit'][:8]} | {obs.get('after', '?')} | {'as recorded' if ok else 'DIFFERS'} |")
    summary["before_after"] = [{"id": r["id"], "rule": r["rule"], "file": r["file"], "before": r["before"]["commit"],
                                "after": r["after"]["commit"], "observed": o, "recorded": {"before": r["before"]["reports"], "after": r["after"]["reports"]},
                                "ok": ok} for r, o, ok in table]
if problems:
    md += ["", "## Problems", ""] + [f"- {p}" for p in problems]
summary["first_line"] = first
summary["problems"] = problems
with open(os.path.join(out, "..", name + ".md"), "w") as f:
    f.write("\n".join(md) + "\n")
with open(os.path.join(out, "..", name + ".summary.json"), "w") as f:
    json.dump(summary, f, indent=2)
    f.write("\n")

def rule_counts(rows):
    """Reports per (rule, severity): suppressed, pending finding review, and other unsuppressed. No site."""
    n = collections.defaultdict(lambda: {"suppressed": 0, "pending": 0, "unsuppressed": 0})
    for r in rows:
        l = r["lint"]
        k = (l["rule"], l.get("severity", "error"))
        n[k]["suppressed" if l["suppressed"] else "pending" if r.get("expectation") == "pending" else "unsuppressed"] += 1
    return [{"rule": k[0], "severity": k[1], **n[k]} for k in sorted(n)]

# The verdict: the summary's counts and clean flag with no site in it (no file, line, function, message or reason),
# so it can be uploaded while a report of this run is withheld (scripts/ci/withhold-pending.py) and the acceptance
# report (lint-current) still reads the run's outcome. Problems are counted here; their text is in the summary and the log.
verdict_doc = {"schema": "xdrlint.verdict/v1", "name": name, "mode": mode, "overlay": bool(overlay),
               "accounting": verdict, "problems": len(problems), "commits": []}
if current in per_commit:
    verdict_doc["clean"] = per_commit[current]["clean"]
    verdict_doc["clean_statement"] = clean_statement(per_commit[current])
for c in order:
    if c not in per_commit:
        continue
    v = per_commit[c]
    u = v["unsuppressed"]
    verdict_doc["commits"].append({"commit": c, "pinned": c == current, "report": v["report"], "exit": v["rc"],
                                   "reports": len(v["rows"]), "suppressions": n_sup(v), "pending": n_pending(v),
                                   "clean": v["clean"], "clean_statement": clean_statement(v),
                                   "unsuppressed": {k: u[k] for k in ("errors", "warnings", "pending", "pending_errors")},
                                   "rules": rule_counts(v["rows"])})
with open(os.path.join(out, "..", name + ".verdict.json"), "w") as f:
    json.dump(verdict_doc, f, indent=2)
    f.write("\n")
print(first)
for p in problems:
    print("  " + p, file=sys.stderr)
sys.exit(1 if problems else 0)
PY
exit "$status"

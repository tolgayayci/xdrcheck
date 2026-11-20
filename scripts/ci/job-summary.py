#!/usr/bin/env python3
"""Technical summaries for the GitHub Actions job summary, read from what a job's make target wrote.

    scripts/ci/job-summary.py job JOB_ID [--log FILE] [--reports DIR] [--summary FILE]
    scripts/ci/job-summary.py run [--reports DIR] [--summary FILE]

`job` reads the reports a CI job wrote under DIR (default reports/), and FILE given with --log (the job's make
output, for the checks whose result is printed rather than written: tests, coverage, the findings check and the
mainnet tier), and appends a short markdown section to the --summary file (default stdout). It also writes a
one-line brief to DIR/ci-summary/JOB_ID.txt, which the job's reports artifact carries to the run summary. Every
number comes from those files; nothing is computed beyond sums and counts of what they state. A report that is
missing is said to be missing.

`run` prints one table of the jobs named in the JOB_RESULTS environment variable ("id=result id=result ...", the
needs.<id>.result of each job) with each job's brief from DIR/ci-summary/.

It never fails the job over a summary: any error is printed as a line of the summary and the exit status is 0.
"""
import glob
import json
import os
import re
import sys

KINDS = {
    "corpus": "corpus",
    "replay": "replay:replay-regression", "replay-acceptance": "replay:replay-regression",
    "replay-full": "replay:replay-full", "replay-etl-known": "replay:replay-etl-known",
    "harness-selftest": "selftest", "memory": "memory",
    "conformance": "conformance:conformance", "conformance-public": "conformance:conformance-public",
    "conformance-js": "sdk_regression",
    "lint": "lint", "guide": "guide", "coverage": "coverage",
    "findings": "findings", "findings-acceptance": "findings",
    "mainnet": "mainnet",
    "unit-rust": "tests", "unit-go": "tests", "unit-lint": "tests", "cli": "tests",
    "unit-drivers-a": "tests", "unit-drivers-b": "tests", "unit-drivers-c": "tests", "unit-drivers-d": "tests",
    "unit-drivers-e": "tests",
}
# The job ids kept for stable needs graphs; the summary shows each job by its technical name.
LABELS = {"replay-acceptance": "replay", "findings-acceptance": "findings-check-strict"}


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def lines_of(path):
    if not path or not os.path.isfile(path):
        return []
    cwd = os.getcwd().rstrip("/") + "/"
    with open(path, encoding="utf-8", errors="replace") as f:
        return [ln.rstrip("\n").replace(cwd, "") for ln in f]


def classes(by_result):
    return ", ".join(f"{k} {v}" for k, v in sorted((by_result or {}).items()))


def report_summary(path):
    s = load(path).get("summary") or {}
    return s


# ---- one function per kind: (markdown lines, brief) ----

def corpus(reports, log):
    md, brief = [], []
    for name in ("corpus-verify.json", "corpus-verify-ag4.json"):
        p = os.path.join(reports, name)
        if not os.path.isfile(p):
            md.append(f"- `{name}`: not written")
            continue
        s = report_summary(p)
        brief.append(f"{name[:-5]}: {s.get('rows')} rows, {s.get('failures')} failures")
        md += [f"**`{name}`**: {s.get('rows')} rows, {s.get('failures')} failures, {s.get('unexpected')} unexpected, "
               f"{s.get('failures_without_finding')} failures without a finding ID", "",
               "| result | rows |", "|---|---|"]
        md += [f"| `{k}` | {v} |" for k, v in sorted((s.get("by_result") or {}).items())]
        md.append("")
    return md, "; ".join(brief) or "no report"


def replay(reports, log, sub):
    paths = sorted(glob.glob(os.path.join(reports, sub, "*", "report.json")))
    if not paths:
        return [f"No replay report under `{sub}/`."], "no report"
    md = [f"Replay runs under `{sub}/`, one per target commit and input:", "",
          "| run | target | input | rows | failures | unexpected | without finding ID | result classes |",
          "|---|---|---|---|---|---|---|---|"]
    tot = {"rows": 0, "failures": 0, "unexpected": 0}
    for p in paths:
        d = load(p)
        s = d.get("summary") or {}
        vals = ((d.get("header") or {}).get("pins") or {}).get("values") or {}
        for k in tot:
            tot[k] += s.get(k) or 0
        md.append(f"| `{os.path.basename(os.path.dirname(p))}` | `{vals.get('target', '-')}` | {vals.get('input', '-')} "
                  f"| {s.get('rows')} | {s.get('failures')} | {s.get('unexpected')} | "
                  f"{s.get('failures_without_finding')} | {classes(s.get('by_result'))} |")
    return md, f"{len(paths)} runs, {tot['rows']} rows, {tot['failures']} failures, {tot['unexpected']} unexpected"


def selftest(reports, log):
    p = os.path.join(reports, "selftest", "summary.json")
    if not os.path.isfile(p):
        return ["No `selftest/summary.json`."], "no report"
    bugs = load(p).get("bugs") or []
    md = ["Seeded-bug indexers and the result classes they landed in:", "",
          "| seeded bug | status | rows | results |", "|---|---|---|---|"]
    md += [f"| `{b.get('bug')}` | {b.get('status')} | {b.get('rows')} | {', '.join(b.get('results') or [])} |" for b in bugs]
    ok = sum(1 for b in bugs if b.get("status") == "ok")
    return md, f"{ok} of {len(bugs)} seeded bugs in their documented class"


def memory(reports, log):
    p = os.path.join(reports, "memory", "memory.json")
    if not os.path.isfile(p):
        return ["No `memory/memory.json`."], "no report"
    tests = load(p).get("tests") or []
    md = ["| test | what | ok |", "|---|---|---|"]
    md += [f"| {t.get('name')} | {t.get('what')} | {t.get('ok')} |" for t in tests]
    return md, f"{sum(1 for t in tests if t.get('ok'))} of {len(tests)} memory tests hold"


def sdk_regression_lines(reports, sub="conformance"):
    p = os.path.join(reports, sub, "sdk-regression.json")
    if not os.path.isfile(p):
        return [], None
    d = load(p)
    rows = d.get("rows") or []
    held = sum(1 for r in rows if r.get("pass"))
    cols = ", ".join(d.get("columns") or [])
    line = f"js-stellar-sdk assertions on {cols}: {held} of {len(rows)} rows hold"
    return [f"**{line}**", ""], line


def sdk_regression(reports, log):
    md, brief = sdk_regression_lines(reports)
    return (md or ["No `conformance/sdk-regression.json`."]), (brief or "no report")


def conformance(reports, log, sub):
    md, brief = [], []
    m = os.path.join(reports, sub, "matrix.json")
    if os.path.isfile(m):
        s = load(m).get("summary") or {}
        md += ["Cells of the conformance matrix by class:", "", "| class | cells |", "|---|---|"]
        md += [f"| {k} | {v} |" for k, v in sorted(s.items())]
        md.append("")
        brief.append(classes(s))
    else:
        md.append(f"No `{sub}/matrix.json`.")
    head = [ln for ln in lines_of(os.path.join(reports, sub, "SUMMARY.md")) if ln.startswith("Corpus ")]
    if head:
        md += [head[0], ""]
    cross = lines_of(os.path.join(reports, sub, "cross-sdk.md"))
    table = [ln for ln in cross if ln.startswith("|")]
    if table:
        md += ["<details><summary>Cross-SDK divergence matrix (cross-sdk.md)</summary>", "", *table, "", "</details>", ""]
    c_md, c_brief = sdk_regression_lines(reports, sub)
    md += c_md
    if c_brief:
        brief.append(c_brief)
    return md, "; ".join(brief) or "no report"


def lint(reports, log):
    md, brief = [], []
    fx = os.path.join(reports, "lint-fixtures.jsonl")
    if os.path.isfile(fx):
        res = {"pass": 0, "fail": 0, "skip": 0}
        for ln in lines_of(fx):
            try:
                ev = json.loads(ln)
            except ValueError:
                continue
            if ev.get("Test") and ev.get("Action") in res:
                res[ev["Action"]] += 1
        line = f"linter tests (fixtures included): {res['pass']} passed, {res['fail']} failed, {res['skip']} skipped"
        md += [f"- {line}"]
        brief.append(line)
    for t in sorted(glob.glob(os.path.join(reports, "lint-*.tally.json"))):
        name = os.path.basename(t)[: -len(".tally.json")]
        head = lines_of(os.path.join(reports, name + ".md"))[:1]
        md.append(f"- {head[0]}" if head else f"- {name}: report withheld from the upload; counted from its tally")
    if not md:
        return ["No linter report."], "no report"
    brief.append(f"{len(md) - (1 if os.path.isfile(fx) else 0)} linter runs")
    return md, "; ".join(brief)


def guide(reports, log):
    p = os.path.join(reports, "guide-table.json")
    if not os.path.isfile(p):
        return ["No `guide-table.json`."], "no report"
    s = report_summary(p)
    line = f"guide field table against the manifest: {s.get('rows')} rows, {s.get('failures')} failures"
    return [f"**{line}** ({classes(s.get('by_result'))})"], line


def coverage(reports, log):
    keep = [ln for ln in lines_of(log) if ln.startswith("coverage: ") or "mainnet-coverage.json: " in ln]
    if not keep:
        return ["No coverage line in the job's output."], "no output"
    return [f"- {ln}" for ln in keep], keep[0][len("coverage: "):] if keep[0].startswith("coverage: ") else keep[0]


FINDINGS = re.compile(r"^findings check \((\w+)\): (\d+) report\(s\), (\d+) rows, (\d+) failure rows \((\d+) linked to a "
                      r"record, (\d+) pending finding review, (\d+) without a finding ID\); (\d+) record\(s\)(?: \((.*)\))?$")


def findings(reports, log):
    lines = lines_of(log)
    head = [m for m in map(FINDINGS.match, lines) if m]
    if not head:
        return ["No findings check line in the job's output."], "no output"
    m = head[-1]
    mode = {"acceptance": "strict", "development": "development"}.get(m.group(1), m.group(1))
    md = [f"Findings check, {mode} mode:", "", "| reports | rows | failure rows | linked to a record | awaiting finding review "
          "| without a finding ID | records |", "|---|---|---|---|---|---|---|",
          f"| {m.group(2)} | {m.group(3)} | {m.group(4)} | {m.group(5)} | {m.group(6)} | {m.group(7)} | {m.group(8)}"
          f"{' (' + m.group(9) + ')' if m.group(9) else ''} |", ""]
    fails = [ln for ln in lines if ln.startswith("FAIL ")]
    md += [f"- {ln}" for ln in fails]
    pending = [ln for ln in lines if re.match(r"^\d+ failure rows have no linked issue$", ln)]
    md += ["", *(f"**{ln}**" for ln in pending)] if pending else []
    brief = f"{m.group(4)} failure rows, {m.group(5)} linked, {m.group(6)} awaiting review, {m.group(7)} without ID"
    return md, brief


def mainnet(reports, log):
    md, brief = [], "no output"
    head = [ln for ln in lines_of(log) if ln.startswith("mainnet check: ")]
    if head:
        md.append(f"**{head[-1]}**")
        brief = head[-1][len("mainnet check: "):]
    tsv = lines_of(os.path.join(reports, "mainnet-check.tsv"))[1:]
    if tsv:
        ok = sum(1 for ln in tsv if ln.endswith("\tpass"))
        md.append(f"- `mainnet-check.tsv`: {len(tsv)} transactions, {ok} pass, {len(tsv) - ok} fail")
    return md or ["No mainnet check output."], brief


def tests(reports, log):
    lines = lines_of(log)
    if not lines:
        return ["No test output."], "no output"
    passed = failed = 0
    for ln in lines:
        for p, f in re.findall(r"(\d+) passed; (\d+) failed", ln):
            passed, failed = passed + int(p), failed + int(f)
    units = sum(1 for ln in lines if re.match(r"^PASS +\d+s ", ln))
    units_failed = sum(1 for ln in lines if re.match(r"^FAIL +\d+s ", ln))
    go_ok = sum(1 for ln in lines if re.match(r"^ok\s+\S+", ln))
    go_fail = sum(1 for ln in lines if re.match(r"^FAIL\s+\S+\s", ln) and not re.match(r"^FAIL +\d+s ", ln))
    md, brief = [], []
    if passed or failed:
        md.append(f"- Rust tests: {passed} passed, {failed} failed")
        brief.append(f"{passed} tests passed, {failed} failed")
    if units or units_failed:
        md.append(f"- test units (binaries or driver directories): {units} passed, {units_failed} failed")
        brief.append(f"{units} units passed, {units_failed} failed")
    if go_ok or go_fail:
        md.append(f"- Go packages: {go_ok} ok, {go_fail} failed")
        brief.append(f"{go_ok} Go packages ok, {go_fail} failed")
    final = [ln for ln in lines if re.match(r"^(cargo-test-parallel|test-drivers|check_cli_reference): ", ln)]
    md += [f"- {ln}" for ln in final[-2:]]
    if not brief and final:
        brief.append(final[-1])
    return md or ["No test result line in the job's output."], "; ".join(brief) or "no result line"


def job(job_id, reports, log):
    kind = KINDS.get(job_id)
    if not kind:
        return [], ""
    name, _, sub = kind.partition(":")
    fn = globals()[name]
    return fn(reports, log, sub) if sub else fn(reports, log)


def run_table(reports):
    pairs = [p.split("=", 1) for p in os.environ.get("JOB_RESULTS", "").split() if "=" in p]
    md = ["## Run summary", "", "| job | result | key numbers |", "|---|---|---|"]
    for jid, result in pairs:
        brief = lines_of(os.path.join(reports, "ci-summary", jid + ".txt"))
        md.append(f"| `{LABELS.get(jid, jid)}` | {result or '-'} | {(brief[0] if brief else '-').replace('|', '/')} |")
    md += ["", "Each job's own summary has the details; its reports are in the run's artifacts."]
    return md


def main(argv):
    args = {"--reports": "reports", "--log": None, "--summary": None}
    pos = []
    it = iter(argv)
    for a in it:
        if a in args:
            args[a] = next(it, None)
        else:
            pos.append(a)
    if not pos or pos[0] not in ("job", "run") or (pos[0] == "job" and len(pos) != 2):
        print(__doc__, file=sys.stderr)
        return 2
    reports = args["--reports"]
    try:
        if pos[0] == "run":
            md = run_table(reports)
        else:
            body, brief = job(pos[1], reports, args["--log"])
            md = [f"## {LABELS.get(pos[1], pos[1])}", "", *body, ""]
            if brief:
                os.makedirs(os.path.join(reports, "ci-summary"), exist_ok=True)
                with open(os.path.join(reports, "ci-summary", pos[1] + ".txt"), "w", encoding="utf-8") as f:
                    f.write(brief + "\n")
            for ln in body:
                m = re.match(r"^\*\*(\d+) failure rows have no linked issue\*\*$", ln)
                if m:
                    print(f"::warning title=Findings awaiting review::{m.group(1)} failure rows have no linked issue")
    except Exception as e:  # a summary never fails the job
        md = [f"## {pos[1] if len(pos) > 1 else 'run'}", "", f"The summary could not be read: {type(e).__name__}: {e}"]
    text = "\n".join(md) + "\n"
    if args["--summary"]:
        with open(args["--summary"], "a", encoding="utf-8") as f:
            f.write(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

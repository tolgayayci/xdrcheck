package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tolgayayci/xdrcheck/go/internal/findings"
	"github.com/tolgayayci/xdrcheck/go/internal/pins"
	"github.com/tolgayayci/xdrcheck/go/internal/report"
)

func runReport(args ...string) cmdRun {
	var out, errb bytes.Buffer
	code := reportMain(args, &out, &errb)
	return cmdRun{code, out.String(), errb.String()}
}

// Redaction keeps classes, qualifiers, verdicts and entry IDs; drops evidence, notes, messages and details;
// and leaves nothing the repository's public-tree scan forbids and no machine-local path.
func TestReportRedact(t *testing.T) {
	home, _ := os.UserHomeDir()
	elsewhere := filepath.Join(string(filepath.Separator), "home", "someone", "build", "out.log")
	adr := "ADR" + " 0001"
	note := "wallet-backend-replay" + "-2026-11-12"
	handle := "tol" + "ga"
	module := "github.com/tolgayayci/xdrcheck/go"

	halt := wbRow("replay:cap-0040/signed-payload-signer-added:testnet:x", true, strp("F-0003"))
	halt.Evidence = json.RawMessage(`{"log":"` + home + `/x/adapter.log","value":"GABC stored value","field":"signer_account_id"}`)
	halt.Notes = []string{"log tail: panic at " + elsewhere}
	halt.KnownDivergence = &report.DivergenceMatch{Reference: "https://github.com/stellar/wallet-backend/pull/729", Status: "fixed", InRange: true}
	priv := wbRow("replay:cap-0040/x:testnet:y", false, nil)
	priv.Target.Name = "acme/" + handle + "-indexer"
	priv.Target.Version = "built per " + adr + " see " + note
	lint := report.Row{RowID: "lint:" + module + ":XDR201:internal/x.go:walk", Tool: "lint", Expectation: "expected", Failure: true,
		Target: report.Target{Name: "stellar/wallet-backend", Version: "e967ce8b7362b79c277e700e789181d76fbb5967", Kind: "pipeline"},
		Lint: &report.LintResult{Rule: "XDR201", Severity: "error", Location: report.Location{File: "internal/x.go", Line: 3, Function: "walk"},
			Message: "recursion at " + elsewhere, Suppressed: true, SuppressionReason: "private reason"}}
	src := writeReport(t, filepath.Join(t.TempDir(), "report.json"), "xcc replay", func(h *report.Header) {
		h.Run = &report.Run{Host: "build-host-7", ID: "run-1", Toolchains: map[string]string{"go": "go1.26.11 at " + home + "/sdk"}}
		h.Pins.Values = map[string]string{"adapter": elsewhere + " 1.0"}
	}, halt, priv, lint)
	before, _ := os.ReadFile(src)
	if !strings.Contains(string(before), "GABC stored value") {
		t.Fatal("fixture lacks evidence")
	}

	out := filepath.Join(t.TempDir(), "redacted.json")
	r := runReport("redact", src, "--out", out)
	if r.code != 0 {
		t.Fatalf("redact: exit %d %s", r.code, r.stderr)
	}
	data, _ := os.ReadFile(out)
	text := string(data)
	for _, gone := range []string{home, elsewhere, "GABC stored value", "signer_account_id", "log tail", "private reason", "recursion at",
		"build-host-7", adr, note, "acme/" + handle} {
		if strings.Contains(text, gone) {
			t.Errorf("redacted report still contains %q", gone)
		}
	}
	for _, kept := range []string{"cap-0040/signed-payload-signer-added", `"class":"mishandled"`, `"qualifier":"halt"`, `"finding":"F-0003"`,
		"XDR201", "pull/729", module} {
		if !strings.Contains(text, kept) {
			t.Errorf("redacted report lost %q", kept)
		}
	}
	rep, err := report.ReadAll(out)
	if err != nil || len(rep.Rows) != 3 || rep.Summary.Failures != 2 || rep.Header.Run.Host != "" {
		t.Fatalf("redacted report: %v %+v", err, rep)
	}
	for _, row := range rep.Rows {
		if row.Evidence != nil || row.Notes != nil {
			t.Errorf("%s keeps evidence or notes", row.RowID)
		}
	}
	// Nothing is left for the scan's own patterns to find.
	rd, note2, err := newRedactor()
	if err != nil || note2 != "" || len(rd.banned) < 5 {
		t.Fatalf("patterns from the public-tree scan: %v %q %d", err, note2, len(rd.banned))
	}
	if again := rd.scrub(text); again != text {
		t.Errorf("a second pass still changes the redacted report")
	}
	if r := runReport("redact"); r.code != 2 {
		t.Errorf("no report: exit %d", r.code)
	}
}

func TestPublicPatternTranslation(t *testing.T) {
	cases := map[string]string{
		`(?<![\w-])widgets/`:      `widgets/`,
		`a(?<=[(\]])b`:            `ab`,
		`(?i)plain\(x\)`:          `(?i)plain\(x\)`,
		`\bX(?<!(y|z))[ -]?0\d\b`: `\bX[ -]?0\d\b`,
	}
	for in, want := range cases {
		if got := dropLookbehind(in); got != want {
			t.Errorf("dropLookbehind(%q) = %q, want %q", in, got, want)
		}
	}
	p := filepath.Join(t.TempDir(), "scan.py")
	os.WriteFile(p, []byte("BANNED = [\n    (re.compile(r\"(?<![\\w-])widgets/\"), \"x\"),\n    (re.compile(r\"(?i)gizmo\"), \"y\"),\n]\n"+
		"HANDLE = re.compile(r\"(?i)gizmo\")\nHANDLE_OK = re.compile(r\"example\\.org/gizmo\")\n"), 0o644)
	banned, allow, err := loadPublicPatterns(p)
	if err != nil || len(banned) != 3 || len(allow) != 1 {
		t.Fatalf("%v %d %d", err, len(banned), len(allow))
	}
	rd := &redactor{banned: banned, allow: allow}
	if got := rd.scrub("see example.org/gizmo and a Gizmo in widgets/x"); got != "see example.org/gizmo and a [redacted] in [redacted]x" {
		t.Errorf("scrub: %q", got)
	}
}

// The hashed list of private names is read with the tokenizer of check_public.py; the names here are made up.
func TestPrivateTermsRedact(t *testing.T) {
	salt := "test-salt"
	digest := func(s string) string {
		sum := sha256.Sum256([]byte(salt + ":" + s))
		return hex.EncodeToString(sum[:])
	}
	p := filepath.Join(t.TempDir(), "terms.sha256")
	os.WriteFile(p, []byte("# comment\nsalt "+salt+"\n"+digest("zq-plantedname")+"\n"+digest("zq plantword")+"\n"), 0o644)
	pt, err := loadPrivateTerms(p)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"a zq-plantedname here":         "a [redacted] here",
		"path/to/ZQ-PlantedName/x":      "path/to/[redacted]/x",
		"x.zq_plantedname.y":            "[redacted]",
		"see Zq Plantword docs":         "see [redacted] [redacted] docs",
		"zqplanted-name and zq-planted": "zqplanted-name and zq-planted",
	}
	for in, want := range cases {
		if got := pt.redact(in); got != want {
			t.Errorf("redact(%q) = %q, want %q", in, got, want)
		}
	}
	// The repository's own list loads, and the redactor uses it.
	rd, note, err := newRedactor()
	if err != nil || note != "" || rd.terms == nil || len(rd.terms.hashes) < 2 {
		t.Fatalf("repository list: %v %q", err, note)
	}
}

func TestReportDiff(t *testing.T) {
	d := t.TempDir()
	a := writeReport(t, filepath.Join(d, "a.json"), "xcc replay", nil,
		wbRow("same", false, nil), wbRow("breaks", false, nil), wbRow("heals", true, nil), wbRow("gone", false, nil))
	flipped := wbRow("same", false, nil)
	breaks := wbRow("breaks", true, nil)
	heals := wbRow("heals", false, nil)
	changed := wbRow("changes", true, nil)
	b := writeReport(t, filepath.Join(d, "b.json"), "xcc replay", func(h *report.Header) { h.Run = &report.Run{Host: "elsewhere"} },
		flipped, breaks, heals, changed)
	r := runReport("diff", a, b)
	for _, want := range []string{"newly fail: 1", "breaks: pass → mishandled·halt", "newly pass: 1", "heals: mishandled·halt → pass", "only in " + a + ": 1", "gone", "changes"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("diff output lacks %q:\n%s", want, r.stdout)
		}
	}
	if r.code != 1 {
		t.Errorf("diff with differences: exit %d", r.code)
	}
	if r := runReport("diff", a, a); r.code != 0 || !strings.Contains(r.stdout, "0 differences") {
		t.Errorf("identical: exit %d\n%s", r.code, r.stdout)
	}
	c := writeReport(t, filepath.Join(d, "c.json"), "xcc conform", nil, jsRow())
	if r := runReport("diff", a, c); r.code != 2 {
		t.Errorf("different tools: exit %d", r.code)
	}
	// A changed result with the same failure flag.
	x := wbRow("v", true, nil)
	y := wbRow("v", true, nil)
	y.Replay.Qualifier = "crash"
	if r := runReport("diff", writeReport(t, filepath.Join(d, "x.json"), "xcc replay", nil, x), writeReport(t, filepath.Join(d, "y.json"), "xcc replay", nil, y)); r.code != 1 ||
		!strings.Contains(r.stdout, "changed result: 1") {
		t.Errorf("changed result: exit %d\n%s", r.code, r.stdout)
	}
}

func corpusRow(id, check string, ok bool) report.Row {
	return report.Row{RowID: "corpus:" + id + ":" + check, Tool: "corpus", Entry: id,
		Target: report.Target{Name: "xdrcheck-corpus", Version: "0.1.0", Kind: "oracle"}, Failure: !ok, Expectation: "expected",
		Corpus: &report.CorpusResult{Check: check, OK: ok}}
}

// requireRuns declares the fake repository's required run set (findings/required-runs.json) as the make targets
// given; the set is expanded against pins.toml and the linter's before/after plan, copied from the repository.
func requireRuns(t *testing.T, root string, targets ...string) {
	t.Helper()
	copyFile(t, filepath.Join(repoAbs, "lint/expected/wallet-backend/plan.json"), filepath.Join(root, "lint/expected/wallet-backend/plan.json"))
	data, _ := json.Marshal(map[string][]string{"targets": targets})
	if err := os.WriteFile(filepath.Join(root, findings.RequiredRunsFile), data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestReportAcceptance(t *testing.T) {
	root := fakeRepo(t)
	requireRuns(t, root, "verify-conformance", "verify-conformance-public")
	os.MkdirAll(filepath.Join(root, "guide"), 0o755)
	os.WriteFile(filepath.Join(root, "guide", "claims.yaml"), []byte("claims:\n- claim_id: C-001\n  reviewer_status: confirmed\n- claim_id: C-002\n  reviewer_status: unreviewed\n"), 0o644)
	reports := filepath.Join(root, "reports")
	copyFile(t, filepath.Join(repoAbs, "corpus", "mirrors.json"), filepath.Join(root, "corpus", "mirrors.json"))
	writeReport(t, filepath.Join(reports, "corpus-verify.json"), "xcc-corpus verify", nil,
		corpusRow("cap-0040/signed-payload-signer-added", "roundtrip", true), corpusRow("cap-0040/signed-payload-signer-added", "ag1", true),
		corpusRow("mirrors.json", "ag4", true), corpusRow("floor:ag4", "ag4", true))
	assertKnown := func(h *report.Header) { h.Mode.Suite = "assert-known" }
	const pre, fixed = "2a0a84ea12523b6c92e278c0c84b443041240095", "2c873353c1f0f3c9b145e25a7d009023ad104a1c"
	writeReport(t, filepath.Join(reports, "replay-regression", pre, "report.json"), "xcc replay", assertKnown, wbRow("halt", true, strp("F-0001")))
	pass := wbRow("pass", false, nil)
	pass.Target.Version = fixed
	writeReport(t, filepath.Join(reports, "replay-regression", fixed, "report.json"), "xcc replay", assertKnown, pass)
	putRecord(t, filepath.Join(root, "findings"), exampleRecord(t, "F-0001", "draft"))

	r := runReport("acceptance", "reports")
	if r.code != 0 {
		t.Fatalf("acceptance: exit %d %s", r.code, r.stderr)
	}
	md, err := os.ReadFile(filepath.Join(reports, "acceptance.md"))
	if err != nil || string(md) != r.stdout {
		t.Fatalf("acceptance.md: %v", err)
	}
	for _, want := range []string{
		"| roundtrip | met |", "| golden-agreement | met |", "| replay-regression/wallet-backend-729 | met |", "`reports/replay-regression/" + pre + "/report.json`",
		"| replay-regression/wallet-backend-731 | missing |", "| replay-regression/wallet-backend-716 | missing |", "| lint-fixtures | not recorded |", "| lint-current | missing |", "| guide-table | not recorded |",
		"| guide-review | not met | 1 of 2 claims reviewed (1 unreviewed, 0 disputed); publication waits on the review", "| sdk-regression | missing |",
		"| findings-linked | missing | the check needs these runs' reports: conformance/report.json (make verify-conformance), conformance-public/report.json (make verify-conformance-public)",
		EmbargoSentence,
	} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("acceptance report lacks %q:\n%s", want, r.stdout)
		}
	}
	// With the conformance runs findings-linked is the findings check's verdict: not met while the record is a draft, met
	// once it is terminal.
	writeReport(t, filepath.Join(reports, "conformance", "report.json"), "xcc conform", nil, passCell("js@17.2.0"))
	writeReport(t, filepath.Join(reports, "conformance-public", "report.json"), "xcc conform", nil, passCell("js@17.2.0"))
	r = runReport("acceptance", "reports", "--out", filepath.Join(t.TempDir(), "a.md"))
	if want := "| findings-linked | not met | 1 of 1 records not yet filed: F-0001 draft; " + waitingFindings + " |"; !strings.Contains(r.stdout, want) {
		t.Errorf("draft record: lacks %q:\n%s", want, r.stdout)
	}
	rec := exampleRecord(t, "F-0001", "not-a-defect")
	rec.Resolution = &findings.Resolution{Reason: "the expectation was wrong: the input is valid", Reviewer: "independent-reviewer", Date: "2026-11-13"}
	putRecord(t, filepath.Join(root, "findings"), rec)
	if r := runReport("acceptance", "reports", "--out", filepath.Join(t.TempDir(), "a.md")); !strings.Contains(r.stdout, "| findings-linked | met |") {
		t.Errorf("terminal record:\n%s", r.stdout)
	}
	// A report made with the overlay is refused.
	writeReport(t, filepath.Join(reports, "private.json"), "xcc replay", func(h *report.Header) { h.Mode.Overlay = true }, pass)
	if r := runReport("acceptance", "reports"); r.code != 2 || !strings.Contains(r.stderr, "overlay") {
		t.Errorf("overlay report: exit %d %s", r.code, r.stderr)
	}
}

// passCell is a conforming cell on a JavaScript column.
func passCell(column string) report.Row {
	r := jsRow()
	r.Entry, r.Variant, r.KnownDivergence, r.Failure = "cap-0038/other", "", nil, false
	r.Target.Column, r.Target.Version = column, strings.TrimPrefix(column, "js@")
	r.RowID = "conform:cap-0038/other::" + column + ":L1"
	r.Conform.Outcome, r.Conform.Reason, r.Conform.Verdict, r.Conform.Check = "ok", "", "conform", "conform"
	return r
}

// pendingCell is an undeclared divergence the producing tool marked pending finding review.
func pendingCell(entry, column string) report.Row {
	r := passCell(column)
	r.Entry, r.RowID = entry, "conform:"+entry+"::"+column+":L1"
	r.Failure, r.Expectation = true, report.ExpectationPending
	r.Conform.Outcome, r.Conform.Reason, r.Conform.Verdict, r.Conform.Check = "reject", "ordering", "reject_valid", "undeclared"
	return r
}

func rowLine(md, check string) string {
	for _, l := range strings.Split(md, "\n") {
		if strings.HasPrefix(l, "| "+check+" |") {
			return l
		}
	}
	return ""
}

// Each check is read from its own verdict artefact: the fixture tests' `go test -json` output (lint-fixtures), the lint
// summary at the pinned current commit (lint-current), the guide table's report (guide-table), sdk-regression.json (sdk-regression) and the
// acceptance-mode findings check (findings-linked). Rows pending finding review keep findings-linked `not met`, and lint-current too when the
// summary does not say they are only warnings (TestReportAcceptanceLintClean); the text names the outside action.
func TestReportAcceptanceVerdicts(t *testing.T) {
	root := fakeRepo(t)
	requireRuns(t, root, "verify-conformance", "verify-conformance-public")
	p, err := pins.Load(filepath.Join(root, "pins.toml"))
	if err != nil {
		t.Fatal(err)
	}
	current := p.Pipelines.WalletBackend.Current
	reports := filepath.Join(root, "reports")
	put := func(rel, text string) {
		os.MkdirAll(filepath.Dir(filepath.Join(reports, rel)), 0o755)
		if err := os.WriteFile(filepath.Join(reports, rel), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	os.MkdirAll(filepath.Join(root, "findings", "pending"), 0o755)
	os.WriteFile(filepath.Join(root, "findings", "pending", "conformance.json"),
		[]byte(`{"since":"`+time.Now().UTC().Format("2006-01-02")+`","pending":[{"entry":"cap-0038/pending-entry","column":"js@17.2.0","level":"L1"}]}`), 0o644)
	put("lint-fixtures.jsonl", `{"Action":"run","Package":"x","Test":"TestA"}`+"\n"+`{"Action":"pass","Package":"x","Test":"TestA"}`+"\n"+
		`{"Action":"pass","Package":"x","Test":"TestB"}`+"\n"+`{"Action":"pass","Package":"x"}`+"\n")
	summary := func(pending int, problems string) string {
		return fmt.Sprintf(`{"name":"lint-wallet-backend","mode":"current","overlay":false,"commits":[{"commit":%q,"reports":9,"pending":%d}],"problems":[%s]}`,
			current, pending, problems)
	}
	put("lint-wallet-backend.summary.json", summary(3, ""))
	guideRow := func(ok bool) report.Row {
		r := corpusRow("cap-0040/signed-payload-signer-added", "guide-table", ok)
		r.Target.Name = "xdrcheck-corpus guide-table"
		return r
	}
	writeReport(t, filepath.Join(reports, "guide-table.json"), "xdrcheck-corpus guide-table", nil, guideRow(true))
	put("conformance/sdk-regression.json", `{"schema":"xcc.conform.sdk-regression/v1","passed":true,"rows":[{"id":"a1","check":"sdk-regression/js-1766","entry":"e","column":"js@17.2.0","level":"L1","pass":true}]}`)
	conf := filepath.Join(reports, "conformance", "report.json")
	writeReport(t, conf, "xcc conform", nil, pendingCell("cap-0038/pending-entry", "js@17.2.0"), passCell("js@17.2.1"))
	writeReport(t, filepath.Join(reports, "conformance-public", "report.json"), "xcc conform", nil, passCell("js@17.2.0"))

	r := runReport("acceptance", "reports")
	if r.code != 0 {
		t.Fatalf("acceptance: exit %d %s", r.code, r.stderr)
	}
	want := map[string]string{
		"lint-fixtures":   "| lint-fixtures | met | the linter's tests, seeded-violation fixtures included: all 2 passed | `reports/lint-fixtures.jsonl` (make lint-fixtures) |",
		"lint-current":    fmt.Sprintf("| lint-current | not met | wallet-backend %.8s: 9 reports, every one expected or suppressed except 3 rows pending finding review; %s |", current, waitingFindings),
		"guide-table":     "| guide-table | met | the generated field table agrees with the manifest: all 1 rows passed | `reports/guide-table.json` |",
		"sdk-regression":  "| sdk-regression | met | all 1 assertion rows of `xdrcheck conform sdk-regression` hold on js@17.2.0, js@17.2.1, js@17.3.0; cells pending finding review elsewhere in the matrix, per run: `reports/conformance/report.json`: 1 |",
		"findings-linked": "| findings-linked | not met | 1 row pending finding review; " + waitingFindings + " |",
	}
	for check, w := range want {
		if l := rowLine(r.stdout, check); !strings.HasPrefix(l, w) {
			t.Errorf("%s:\n got %s\nwant %s", check, l, w)
		}
	}

	// Real failures: a failed fixture test, a problem in the clean run, a failing guide-table row, a failed sdk-regression
	// assertion, an undeclared cell and an orphaned record.
	put("lint-fixtures.jsonl", `{"Action":"pass","Package":"x","Test":"TestA"}`+"\n"+`{"Action":"fail","Package":"x","Test":"TestB"}`+"\n"+`{"Action":"fail","Package":"x"}`+"\n")
	put("lint-wallet-backend.summary.json", summary(0, `"e967ce8b: unexpected report XDR102 a.go"`))
	writeReport(t, filepath.Join(reports, "guide-table.json"), "xdrcheck-corpus guide-table", nil, guideRow(false))
	put("conformance/sdk-regression.json", `{"schema":"xcc.conform.sdk-regression/v1","passed":false,"rows":[{"id":"a1","check":"sdk-regression/js-1766","entry":"e","column":"js@17.2.0","level":"L1","pass":false}]}`)
	undeclared := pendingCell("cap-0038/new-divergence", "js@17.2.1")
	undeclared.Expectation = "unexpected"
	writeReport(t, conf, "xcc conform", nil, pendingCell("cap-0038/pending-entry", "js@17.2.0"), undeclared)
	putRecord(t, filepath.Join(root, "findings"), exampleRecord(t, "F-0007", "draft"))
	r = runReport("acceptance", "reports")
	want = map[string]string{
		"lint-fixtures":   "| lint-fixtures | not met | 2 tests or packages failed (x, x TestB); 1 passed |",
		"lint-current":    fmt.Sprintf("| lint-current | not met | 1 problem at %.8s: e967ce8b: unexpected report XDR102 a.go |", current),
		"guide-table":     "| guide-table | not met | the generated field table agrees with the manifest: 1 of 1 rows failed |",
		"sdk-regression":  "| sdk-regression | not met | 1 assertion row of 1 failed: a1 e js@17.2.0 L1; cells pending finding review elsewhere",
		"findings-linked": "| findings-linked | not met | 1 failure row without a finding; 1 orphaned record that no report row refers to: F-0007 (draft); 1 row pending finding review; 1 of 1 records not yet filed: F-0007 draft; " + waitingFindings + " |",
	}
	for check, w := range want {
		if l := rowLine(r.stdout, check); !strings.HasPrefix(l, w) {
			t.Errorf("%s:\n got %s\nwant %s", check, l, w)
		}
	}
	// The table's findings-linked is the findings check's own result: the same orphan, pending row and unlinked row.
	fc := runFindings("check", "--mode", "acceptance", "reports")
	for _, both := range []string{"(orphans): 1\n  F-0007 (draft)", "1 pending finding review", "1 without a finding ID"} {
		if !strings.Contains(fc.stdout, both) {
			t.Errorf("findings check lacks %q:\n%s", both, fc.stdout)
		}
	}

	// The clean run at another commit than the pinned current one does not count; nor does a missing public run.
	put("lint-wallet-backend.summary.json", strings.Replace(summary(0, ""), current, strings.Repeat("0", 40), 1))
	os.RemoveAll(filepath.Join(reports, "conformance-public"))
	r = runReport("acceptance", "reports")
	if l := rowLine(r.stdout, "lint-current"); !strings.HasPrefix(l, "| lint-current | missing | lint-wallet-backend.summary.json has no run at the pinned current commit") {
		t.Errorf("lint-current at another commit: %s", l)
	}
	if l := rowLine(r.stdout, "findings-linked"); !strings.HasPrefix(l, "| findings-linked | missing | the check needs these runs' reports: conformance-public/report.json (make verify-conformance-public)") {
		t.Errorf("findings-linked without the public run: %s", l)
	}
}

// The checker's private-only records are named apart from its orphans, as the findings check names them.
func TestFindingsStatusPrivateOnly(t *testing.T) {
	res := &findings.Result{Mode: findings.Acceptance, PendingRows: 3, Orphans: []string{"F-0032 (candidate)"}, PrivateOnly: []string{"F-0028"},
		NonTerminal: []string{"F-0032 candidate"}, Records: 2}
	status, text := findingsStatus(res)
	if status != statusNotMet || !strings.HasPrefix(text, "1 orphaned record that no report row refers to: F-0032 (candidate); 3 rows pending") ||
		!strings.HasSuffix(text, "private overlay: F-0028") {
		t.Errorf("%s: %s", status, text)
	}
}

// Every check that reads a run of the required set is `missing` while that run has no report, and the row names
// the run's make target: here the full-corpus replay (findings-linked only) and the corpus verification's AG-4 report.
func TestReportAcceptanceRequiredRuns(t *testing.T) {
	root := fakeRepo(t)
	requireRuns(t, root, "verify-corpus", "replay-full")
	reports := filepath.Join(root, "reports")
	writeReport(t, filepath.Join(reports, "corpus-verify.json"), "xcc-corpus verify", nil,
		corpusRow("cap-0040/signed-payload-signer-added", "roundtrip", true), corpusRow("cap-0040/signed-payload-signer-added", "ag1", true))
	r := runReport("acceptance", "reports", "--out", filepath.Join(t.TempDir(), "a.md"))
	if r.code != 0 {
		t.Fatalf("acceptance: exit %d %s", r.code, r.stderr)
	}
	for check, w := range map[string]string{
		"roundtrip":        "| roundtrip | met |",
		"golden-agreement": "| golden-agreement | missing | the check needs these runs' reports: corpus-verify-ag4.json (make verify-corpus) |",
		"findings-linked": "| findings-linked | missing | the check needs these runs' reports: corpus-verify-ag4.json (make verify-corpus), " +
			"replay-full/wallet-backend-sep54-s3/report.json (make replay-full), replay-full/wallet-backend-rpc/report.json (make replay-full) |",
	} {
		if l := rowLine(r.stdout, check); !strings.HasPrefix(l, w) {
			t.Errorf("%s:\n got %s\nwant %s", check, l, w)
		}
	}
}

// --full-ci names the make targets only the full CI runs. A check met on this run whose only absent reports are
// those targets' is `proven in full CI` and names them; a check that fails on this run stays `not met`, and a run
// of another target that is absent still makes the row `missing`. findings-linked is never deferred.
func TestReportAcceptanceFullCI(t *testing.T) {
	root := fakeRepo(t)
	requireRuns(t, root, "verify-conformance")
	reports := filepath.Join(root, "reports")
	put := func(body string) {
		if err := os.MkdirAll(filepath.Join(reports, "conformance"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(reports, "conformance", "sdk-regression.json"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	put(`{"schema":"xcc.conform.sdk-regression/v1","passed":true,"rows":[{"id":"a1","check":"sdk-regression/js-1766","entry":"e","column":"js@17.2.0","level":"L1","pass":true}]}`)
	row := func(check string, args ...string) string {
		r := runReport(append([]string{"acceptance", "reports", "--out", filepath.Join(t.TempDir(), "a.md")}, args...)...)
		if r.code != 0 {
			t.Fatalf("acceptance %v: exit %d %s", args, r.code, r.stderr)
		}
		return rowLine(r.stdout, check)
	}
	for _, c := range []struct {
		args       []string
		check      string
		want, also string
	}{
		{nil, "sdk-regression", "| sdk-regression | missing | the check needs these runs' reports: conformance/report.json (make verify-conformance) |", ""},
		{[]string{"--full-ci", "lint-stellar-etl"}, "sdk-regression", "| sdk-regression | missing |", ""},
		{[]string{"--full-ci", "verify-replay,verify-conformance"}, "sdk-regression", "| sdk-regression | proven in full CI | this run: all 1 assertion rows",
			"; the full CI also makes conformance/report.json (make verify-conformance) |"},
		{[]string{"--full-ci", "verify-conformance"}, "findings-linked", "| findings-linked | missing | the check needs these runs' reports: conformance/report.json (make verify-conformance) |", ""},
	} {
		l := row(c.check, c.args...)
		if !strings.HasPrefix(l, c.want) || !strings.Contains(l, c.also) {
			t.Errorf("%v %s:\n got %s\nwant %s ... %s", c.args, c.check, l, c.want, c.also)
		}
	}
	put(`{"schema":"xcc.conform.sdk-regression/v1","passed":false,"rows":[{"id":"a1","check":"sdk-regression/js-1766","entry":"e","column":"js@17.2.0","level":"L1","pass":false}]}`)
	if l := row("sdk-regression", "--full-ci", "verify-conformance"); !strings.HasPrefix(l, "| sdk-regression | not met |") {
		t.Errorf("a failing assertion under --full-ci: %s", l)
	}
}

// golden-agreement is not met when a whole-corpus AG-4 row fails or is absent, and always states corpus/mirrors.json's
// counts of local-core entries with and without a golden counterpart.
func TestReportAcceptanceAG4(t *testing.T) {
	root := fakeRepo(t)
	copyFile(t, filepath.Join(repoAbs, "corpus", "mirrors.json"), filepath.Join(root, "corpus", "mirrors.json"))
	var c struct {
		Counts struct {
			Local    int `json:"local_core_entries"`
			Mapped   int `json:"mapped"`
			Unmapped int `json:"unmapped"`
		} `json:"counts"`
	}
	data, _ := os.ReadFile(filepath.Join(root, "corpus", "mirrors.json"))
	if err := json.Unmarshal(data, &c); err != nil || c.Counts.Local == 0 {
		t.Fatalf("corpus/mirrors.json: %v %+v", err, c)
	}
	counts := fmt.Sprintf("corpus/mirrors.json: %d of %d local-core entries match a golden transaction (mapped); %d unmapped (", c.Counts.Mapped, c.Counts.Local, c.Counts.Unmapped)
	reports := filepath.Join(root, "reports")
	run := func(floorOK bool, whole bool) string {
		rows := []report.Row{corpusRow("cap-0040/signed-payload-signer-added", "ag1", true)}
		if whole {
			rows = append(rows, corpusRow("mirrors.json", "ag4", true), corpusRow("floor:ag4", "ag4", floorOK))
		}
		writeReport(t, filepath.Join(reports, "corpus-verify.json"), "xcc-corpus verify", nil, rows...)
		r := runReport("acceptance", "reports", "--out", filepath.Join(t.TempDir(), "a.md"))
		if r.code != 0 {
			t.Fatalf("acceptance: exit %d %s", r.code, r.stderr)
		}
		return rowLine(r.stdout, "golden-agreement")
	}
	if l := run(true, true); !strings.HasPrefix(l, "| golden-agreement | met | golden checks (AG-1, AG-3, AG-4): all 3 rows passed; "+counts) {
		t.Errorf("passing: %s", l)
	}
	if l := run(false, true); !strings.HasPrefix(l, "| golden-agreement | not met |") || !strings.Contains(l, "AG-4 whole-corpus rows failed: floor:ag4; "+counts) {
		t.Errorf("failing floor: %s", l)
	}
	if l := run(true, false); !strings.HasPrefix(l, "| golden-agreement | not met |") || !strings.Contains(l, "no AG-4 whole-corpus row mirrors.json, floor:ag4") {
		t.Errorf("no whole-corpus rows: %s", l)
	}
}

// lint-current follows the kit's definition of clean: no unsuppressed error after the suppressions, a pending error
// included. A pending warning leaves the row met with a note; a pending error, a summary that is not clean, and a
// summary that does not say how many pending reports are errors keep it `not met`. A lint report withheld from
// CI's upload is accounted for by its run's site-free verdict, which is also read when the summary is absent.
func TestReportAcceptanceLintClean(t *testing.T) {
	root := fakeRepo(t)
	requireRuns(t, root, "lint-wallet-backend")
	p, err := pins.Load(filepath.Join(root, "pins.toml"))
	if err != nil {
		t.Fatal(err)
	}
	current := p.Pipelines.WalletBackend.Current
	reports := filepath.Join(root, "reports")
	put := func(rel, text string) {
		os.MkdirAll(filepath.Dir(filepath.Join(reports, rel)), 0o755)
		if err := os.WriteFile(filepath.Join(reports, rel), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	commit := func(clean string, pending int, breakdown string) string {
		return fmt.Sprintf(`{"commit":%q,"report":true,"reports":3,"pending":%d,"clean":%s,"clean_statement":"clean: xdrlint exits 0 with the shipped profile after the suppressions"%s}`,
			current, pending, clean, breakdown)
	}
	summary := func(c, problems string) string {
		return `{"name":"lint-wallet-backend","mode":"current","overlay":false,"commits":[` + c + `],"problems":` + problems + `}`
	}
	row := func() string {
		r := runReport("acceptance", "reports", "--out", filepath.Join(t.TempDir(), "a.md"))
		if r.code != 0 {
			t.Fatalf("acceptance: exit %d %s", r.code, r.stderr)
		}
		return rowLine(r.stdout, "lint-current")
	}
	report := filepath.Join(reports, "lint-wallet-backend", current+".json")
	writeReport(t, report, "xdrlint", nil)
	warning := `,"unsuppressed":{"errors":0,"warnings":1,"pending":1,"pending_errors":0}`
	for _, c := range []struct{ name, summary, want string }{
		{"pending warning", summary(commit("true", 1, warning), "[]"),
			fmt.Sprintf("| lint-current | met | wallet-backend %.8s: 3 reports, every one expected or suppressed except 1 warning awaiting finding review (%s; a warning does not make the run unclean, and it counts in findings-linked); clean: xdrlint exits 0", current, waitingFindings)},
		{"pending error", summary(strings.Replace(commit("false", 1, `,"unsuppressed":{"errors":1,"warnings":0,"pending":1,"pending_errors":1}`), "clean: xdrlint exits 0 with the shipped profile after the suppressions", "not lint-clean: 1 unsuppressed error", 1), "[]"),
			fmt.Sprintf("| lint-current | not met | wallet-backend %.8s: not lint-clean: 1 unsuppressed error |", current)},
		{"pending error, clean claimed", summary(commit("true", 1, `,"unsuppressed":{"errors":1,"warnings":0,"pending":1,"pending_errors":1}`), "[]"),
			fmt.Sprintf("| lint-current | not met | wallet-backend %.8s: 3 reports, every one expected or suppressed except 1 row pending finding review", current)},
		{"no breakdown", summary(commit("true", 1, ""), "[]"),
			fmt.Sprintf("| lint-current | not met | wallet-backend %.8s: 3 reports, every one expected or suppressed except 1 row pending finding review", current)},
		{"nothing pending", summary(commit("true", 0, ""), "[]"),
			fmt.Sprintf("| lint-current | met | wallet-backend %.8s: all 3 reports are in the frozen expected list", current)},
	} {
		put("lint-wallet-backend.summary.json", c.summary)
		if l := row(); !strings.HasPrefix(l, c.want) {
			t.Errorf("%s:\n got %s\nwant %s", c.name, l, c.want)
		}
	}

	// CI: the report and the summary are gone; the verdict (problems counted, no site) stands in for both.
	os.Remove(filepath.Join(reports, "lint-wallet-backend.summary.json"))
	os.Remove(report)
	if l := row(); !strings.HasPrefix(l, "| lint-current | missing | the check needs these runs' reports: lint-wallet-backend/"+current+".json") {
		t.Errorf("nothing there: %s", l)
	}
	verdict := func(problems string, wrote bool) {
		put("lint-wallet-backend.verdict.json", strings.Replace(`{"schema":"xdrlint.verdict/v1","name":"lint-wallet-backend","mode":"current","overlay":false,"accounting":"PASS","commits":[`+
			commit("true", 1, warning)+`],"problems":`+problems+`}`, `"report":true`, fmt.Sprintf(`"report":%v`, wrote), 1))
	}
	verdict("0", true)
	if l := row(); !strings.HasPrefix(l, "| lint-current | met | wallet-backend") || !strings.Contains(l, "1 warning awaiting finding review") ||
		!strings.Contains(l, "; 1 lint report not in this directory (withheld from the upload while a row awaits finding review), each run's verdict read instead (lint-wallet-backend.verdict.json: 1) |") ||
		!strings.HasSuffix(l, "| `reports/lint-wallet-backend.verdict.json` (make lint-wallet-backend) |") {
		t.Errorf("verdict standing in: %s", l)
	}
	// A verdict whose run failed its accounting, did not write the report, or had nothing pending at the commit
	// (so nothing to withhold) stands in for nothing.
	verdict("1", true)
	if l := row(); !strings.HasPrefix(l, "| lint-current | missing | the check needs these runs' reports: lint-wallet-backend/"+current+".json (make lint-wallet-backend)") {
		t.Errorf("verdict with a problem: %s", l)
	}
	verdict("0", false)
	if l := row(); !strings.HasPrefix(l, "| lint-current | missing | the check needs these runs' reports: lint-wallet-backend/"+current+".json") {
		t.Errorf("verdict without a report: %s", l)
	}
	put("lint-wallet-backend.verdict.json", `{"schema":"xdrlint.verdict/v1","name":"lint-wallet-backend","mode":"current","overlay":false,"accounting":"PASS","commits":[`+
		commit("true", 0, "")+`],"problems":0}`)
	if l := row(); !strings.HasPrefix(l, "| lint-current | missing | the check needs these runs' reports: lint-wallet-backend/"+current+".json") {
		t.Errorf("verdict with nothing pending: %s", l)
	}
}

// findings-linked counts a required run whose report CI withheld as present when its tally is there.
func TestMissingRunsOrTally(t *testing.T) {
	dir := t.TempDir()
	runs := []findings.RequiredRun{
		{Report: "lint-wallet-backend/abc.json", Make: "lint-wallet-backend", Tool: "lint", Version: "abc"},
		{Report: "lint-stellar-etl/def.json", Make: "lint-stellar-etl", Tool: "lint", Version: "def"},
	}
	if got := missingRunsOrTally(dir, runs); len(got) != 2 {
		t.Fatalf("no reports, no tallies: %v", got)
	}
	tally := `{"schema": "` + findings.TallySchema + `", "make": "lint-wallet-backend", "runs": [{"report": "lint-wallet-backend/abc.json", "sha256": "", "overlay": false, "rows": 1, "failures": 0, "linked": 0, "unlinked": 0, "pending": 0, "dangling": 0, "refs": {}, "pending_hits": null}]}`
	if err := os.WriteFile(filepath.Join(dir, "lint-wallet-backend"+findings.TallySuffix), []byte(tally), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := missingRunsOrTally(dir, runs); len(got) != 1 || !strings.Contains(got[0], "lint-stellar-etl/def.json") {
		t.Errorf("one tally: %v", got)
	}
}

// --pending-ok's note: on stdout always; in a GitHub Actions run also a warning annotation and a job summary line.
func TestNotePendingOnly(t *testing.T) {
	summary := filepath.Join(t.TempDir(), "summary.md")
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_STEP_SUMMARY", summary)
	var out bytes.Buffer
	notePendingOnly(30, &out)
	want := "findings-linked not met: 30 rows await finding review; this blocks a release tag, not main"
	if !strings.Contains(out.String(), want+"\n") || !strings.Contains(out.String(), "::warning title=findings-linked not met::"+want) {
		t.Errorf("stdout: %q", out.String())
	}
	if data, err := os.ReadFile(summary); err != nil || !strings.Contains(string(data), want) {
		t.Errorf("summary: %q %v", data, err)
	}
	t.Setenv("GITHUB_ACTIONS", "")
	out.Reset()
	notePendingOnly(1, &out)
	if strings.Contains(out.String(), "::warning") || !strings.Contains(out.String(), "1 row awaits finding review") {
		t.Errorf("outside Actions: %q", out.String())
	}
}

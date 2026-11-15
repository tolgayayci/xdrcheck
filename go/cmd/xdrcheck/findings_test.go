package main

// Tests of `xdrcheck findings`, the make targets that run it, and `xdrcheck replay --findings`. Records and reports are
// fixtures written by the tests; the repository's own findings/ holds no records.

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/tolgayayci/xdrcheck/go/internal/findings"
	"github.com/tolgayayci/xdrcheck/go/internal/report"
)

const repoRootRel = "../../.."

// repoAbs is the repository root, resolved before any test changes directory.
var repoAbs = func() string { a, _ := filepath.Abs(repoRootRel); return a }()

// fakeRepo makes a directory that looks like the repository to `xdrcheck findings` (pins.toml, the record schema,
// an empty findings/) and changes into it.
func fakeRepo(t *testing.T) string {
	t.Helper()
	root := repoAbs
	d := t.TempDir()
	copyFile(t, filepath.Join(root, "pins.toml"), filepath.Join(d, "pins.toml"))
	copyFile(t, findingSchemaPath(filepath.Join(root, "corpus")), findingSchemaPath(filepath.Join(d, "corpus")))
	copySets(t, root, d)
	os.MkdirAll(filepath.Join(d, "findings"), 0o755)
	t.Chdir(d)
	return d
}

// exampleRecord is the schema's example draft, renumbered and moved to state.
func exampleRecord(t *testing.T, id, state string) *findings.Record {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoAbs, "corpus/schema/examples/finding-record/valid-01.json"))
	if err != nil {
		t.Fatal(err)
	}
	var r findings.Record
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	r.ID, r.State = id, state
	r.IssueDraft.DryRunCommand = strings.ReplaceAll(r.IssueDraft.DryRunCommand, "F-0009", id)
	if state == "candidate" {
		r.IssueDraft, r.Reproduction, r.UpstreamSearch, r.Evidence = nil, nil, nil, nil
	}
	return &r
}

func putRecord(t *testing.T, findingsDir string, r *findings.Record) {
	t.Helper()
	b, err := findings.Encode(r)
	if err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Join(findingsDir, r.ID), 0o755)
	if err := os.WriteFile(filepath.Join(findingsDir, r.ID, findings.RecordFile), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func strp(s string) *string { return &s }

// wbRow is a wallet-backend replay row: a mishandled·halt failure, or a pass.
func wbRow(id string, failure bool, finding *string) report.Row {
	r := report.Row{RowID: id, Tool: "replay", Entry: "cap-0040/signed-payload-signer-added", Variant: "testnet",
		Target:  report.Target{Name: "stellar/wallet-backend", Version: "2a0a84ea12523b6c92e278c0c84b443041240095", Kind: "pipeline"},
		Failure: failure, Expectation: "expected", Finding: finding, Caps: []int{40},
		Replay: &report.ReplayResult{Unit: "single", Class: "pass"}}
	if failure {
		r.Replay.Class, r.Replay.Qualifier = "mishandled", "halt"
	}
	return r
}

// jsRow is a conformance failure on js@17.2.0 that matched the fixed upstream divergence.
func jsRow() report.Row {
	return report.Row{RowID: "conform:cap-0038/pool-issuers-order-by-bytes-not-strkey:testnet:js@17.2.0:L1", Tool: "conform",
		Entry: "cap-0038/pool-issuers-order-by-bytes-not-strkey", Variant: "testnet",
		Target:  report.Target{Name: "@stellar/stellar-sdk", Version: "17.2.0", Kind: "sdk", Column: "js@17.2.0"},
		Failure: true, Expectation: "expected", Caps: []int{38},
		KnownDivergence: &report.DivergenceMatch{Reference: "https://github.com/stellar/js-stellar-sdk/pull/1766", Status: "fixed", InRange: true, FixedIn: "17.2.1"},
		Conform:         &report.ConformResult{Level: "L1", Reference: "network", Outcome: "reject", Reason: "ordering", Verdict: "reject_valid", Check: "known"}}
}

func writeReport(t *testing.T, path, tool string, h func(*report.Header), rows ...report.Row) string {
	t.Helper()
	os.MkdirAll(filepath.Dir(path), 0o755)
	hdr := report.Header{Tool: report.Tool{Name: tool, Version: "0.1.0"},
		Corpus: report.CorpusRef{Version: "test", ManifestSHA256: strings.Repeat("0", 64)},
		Pins:   report.PinsRef{FileSHA256: strings.Repeat("0", 64)}, Mode: report.Mode{Suite: "test"}}
	if h != nil {
		h(&hdr)
	}
	w, err := report.Create(path, hdr)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if err := w.Write(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

type cmdRun struct {
	code           int
	stdout, stderr string
}

func runFindings(args ...string) cmdRun {
	var out, errb bytes.Buffer
	code := findingsMain(args, &out, &errb)
	return cmdRun{code, out.String(), errb.String()}
}

func TestFindingsCheck(t *testing.T) {
	root := fakeRepo(t)
	reports := filepath.Join(root, "reports")
	writeReport(t, filepath.Join(reports, "replay", "report.json"), "xcc replay", nil, wbRow("r-pass", false, nil), wbRow("r-fail", true, nil))
	for _, mode := range []string{"development", "acceptance"} {
		r := runFindings("check", "--mode", mode, reports)
		if r.code != 1 || !strings.Contains(r.stdout, "failure rows without a finding ID: 1") || !strings.Contains(r.stdout, "r-fail") {
			t.Errorf("%s, unlinked failure row: exit %d\n%s%s", mode, r.code, r.stdout, r.stderr)
		}
	}
	// Linked to a draft: development passes, acceptance fails on the draft.
	writeReport(t, filepath.Join(reports, "replay", "report.json"), "xcc replay", nil, wbRow("r-pass", false, nil), wbRow("r-fail", true, strp("F-0001")))
	putRecord(t, filepath.Join(root, "findings"), exampleRecord(t, "F-0001", "draft"))
	r := runFindings("check", "--mode", "development", reports)
	if r.code != 0 || !strings.HasPrefix(r.stdout, findings.DevelopmentBanner) {
		t.Errorf("development with a draft: exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	r = runFindings("check", "--mode", "acceptance", reports)
	if r.code != 1 || !strings.Contains(r.stdout, "F-0001 draft") || strings.Contains(r.stdout, findings.DevelopmentBanner) {
		t.Errorf("acceptance with a draft: exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	// Tool errors: an overlay report without --overlay, a bad mode, no reports.
	writeReport(t, filepath.Join(reports, "private.json"), "xcc replay", func(h *report.Header) { h.Mode.Overlay = true }, wbRow("p", false, nil))
	if r := runFindings("check", "--mode", "development", reports); r.code != 2 || !strings.Contains(r.stderr, "overlay") {
		t.Errorf("overlay report: exit %d %s", r.code, r.stderr)
	}
	if r := runFindings("check", "--mode", "strict", reports); r.code != 2 {
		t.Errorf("bad mode: exit %d", r.code)
	}
	if r := runFindings("check", "--mode", "development", t.TempDir()); r.code != 2 {
		t.Errorf("no reports: exit %d", r.code)
	}
}

// installFakeGh puts a gh first on PATH that records any invocation; the tests then assert it never ran.
func installFakeGh(t *testing.T) string {
	t.Helper()
	bin := t.TempDir()
	marker := filepath.Join(t.TempDir(), "gh-was-run")
	script := "#!/bin/sh\necho \"$@\" > " + marker + "\nexit 0\n"
	if err := os.WriteFile(filepath.Join(bin, "gh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return marker
}

func TestFindingsNewIssueList(t *testing.T) {
	root := fakeRepo(t)
	marker := installFakeGh(t)
	rep := writeReport(t, filepath.Join(root, "reports", "conformance", "report.json"), "xcc conform", nil, jsRow(), wbRow("r-halt", true, nil))

	r := runFindings("new", "--from", rep, "--row", jsRow().RowID)
	if r.code != 0 || !strings.Contains(r.stdout, "F-0001: candidate written to findings/F-0001/finding.json") {
		t.Fatalf("new: exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	if r := runFindings("new", "--from", rep, "--row", jsRow().RowID); r.code != 2 || !strings.Contains(r.stderr, "already accounted for by F-0001") {
		t.Errorf("second new for the same row: exit %d %s", r.code, r.stderr)
	}
	// A halt with no public upstream item may be security-relevant: only in an overlay outside the tree.
	if r := runFindings("new", "--from", rep, "--row", "r-halt"); r.code != 2 || !strings.Contains(r.stderr, "overlay") {
		t.Errorf("possibly security-relevant row without an overlay: exit %d %s", r.code, r.stderr)
	}
	inside := filepath.Join(root, "private")
	os.MkdirAll(inside, 0o755)
	if r := runFindings("new", "--from", rep, "--row", "r-halt", "--overlay", inside); r.code != 2 || !strings.Contains(r.stderr, "outside") {
		t.Errorf("overlay inside the tree: exit %d %s", r.code, r.stderr)
	}
	overlay := t.TempDir()
	if r := runFindings("new", "--from", rep, "--row", "r-halt", "--overlay", overlay); r.code != 0 {
		t.Errorf("new in the overlay: exit %d %s", r.code, r.stderr)
	}
	// Overlay records are numbered in their own range: the public sequence stays F-0001, F-0002, …
	if _, err := os.Stat(filepath.Join(overlay, "findings", "F-5001", "finding.json")); err != nil {
		t.Errorf("overlay record: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "findings", "F-5001")); err == nil {
		t.Error("the embargoed candidate reached the public tree")
	}

	// issue: writes the body, records the command, prints it, and runs nothing.
	r = runFindings("issue", "F-0001")
	want := "gh issue create --repo stellar/js-stellar-sdk --title "
	if r.code != 0 || !strings.Contains(r.stdout, want) || !strings.Contains(r.stdout, "--body-file findings/F-0001/issue-js-stellar-sdk.md") ||
		!strings.Contains(r.stdout, "NOT RUN") {
		t.Fatalf("issue: exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("findings issue executed gh")
	}
	body, err := os.ReadFile(filepath.Join(root, "findings", "F-0001", "issue-js-stellar-sdk.md"))
	if err != nil || !strings.Contains(string(body), "## Reproduce") || !strings.Contains(string(body), "cap-0038/pool-issuers-order-by-bytes-not-strkey") {
		t.Errorf("body: %v\n%s", err, body)
	}
	var rec findings.Record
	b, _ := os.ReadFile(filepath.Join(root, "findings", "F-0001", "finding.json"))
	json.Unmarshal(b, &rec)
	if rec.IssueDraft == nil || !strings.Contains(r.stdout, rec.IssueDraft.DryRunCommand) || rec.State != "candidate" {
		t.Errorf("record after issue: %+v", rec.IssueDraft)
	}
	// The embargoed record's draft goes to the overlay and its command is a private-channel note.
	r = runFindings("issue", "F-5001", "--overlay", overlay)
	if r.code != 0 || strings.Contains(r.stdout, "gh issue") || !strings.Contains(r.stdout, "private report") {
		t.Errorf("embargoed issue: exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	if _, err := os.Stat(filepath.Join(overlay, "findings", "F-5001", "issue-wallet-backend.md")); err != nil {
		t.Errorf("embargoed body: %v", err)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("findings issue executed gh")
	}

	r = runFindings("list")
	if r.code != 0 || !strings.Contains(r.stdout, "F-0001") || strings.Contains(r.stdout, "F-5001") || !strings.Contains(r.stdout, "1 record(s)") {
		t.Errorf("list: exit %d\n%s", r.code, r.stdout)
	}
	r = runFindings("list", "--overlay", overlay, "--state", "candidate", "--target", "wallet-backend")
	if r.code != 0 || !strings.Contains(r.stdout, "F-5001") || strings.Contains(r.stdout, "F-0001 ") || !strings.Contains(r.stdout, "embargoed (overlay)") {
		t.Errorf("list --target: exit %d\n%s", r.code, r.stdout)
	}
	if r := runFindings("check", "--mode", "development", filepath.Join(root, "reports")); r.code != 1 || !strings.Contains(r.stdout, "without a finding ID: 2") {
		t.Errorf("rows still name no finding until the manifest does: exit %d\n%s", r.code, r.stdout)
	}
}

// A conformance row's upstream repository comes from its column's package ecosystem: the Rust crate and the
// Python XDR package are both named "stellar-xdr". A column only an overlay defines needs that overlay.
func TestFindingsNewSameNamePackages(t *testing.T) {
	root := fakeRepo(t)
	overlay := t.TempDir()
	os.MkdirAll(filepath.Join(overlay, "drivers"), 0o755)
	if err := os.WriteFile(filepath.Join(overlay, "drivers", "sets.toml"), []byte(`[columns."python-xdr@0.1.0"]
sdk = "python-xdr"
kind = "sdk"
ecosystem = "pypi"
package = "stellar-xdr"
target = "stellar-xdr (PyPI)"
version = "0.1.0"
role = "extra"
dir = "drivers/python-xdr/0.1.0"
run = ["bin/xdrcheck-driver"]
`), 0o644); err != nil {
		t.Fatal(err)
	}
	xdrRow := func(column, version string) report.Row {
		r := jsRow()
		r.RowID = "conform:cap-0038/pool-issuers-order-by-bytes-not-strkey:testnet:" + column + ":L1"
		r.Target = report.Target{Name: "stellar-xdr", Version: version, Kind: "sdk", Column: column}
		r.KnownDivergence = nil
		return r
	}
	py, rs := xdrRow("python-xdr@0.1.0", "0.1.0"), xdrRow("rust@30.0.0:limits-default", "30.0.0")
	rep := writeReport(t, filepath.Join(root, "reports", "conformance", "report.json"), "xcc conform", nil, py, rs)

	if r := runFindings("new", "--from", rep, "--row", py.RowID); r.code != 2 || !strings.Contains(r.stderr, "--overlay") {
		t.Errorf("overlay column without the overlay: exit %d %s", r.code, r.stderr)
	}
	record := func(dir, id string) findings.Record {
		t.Helper()
		var rec findings.Record
		b, err := os.ReadFile(filepath.Join(dir, "findings", id, "finding.json"))
		if err != nil {
			t.Fatal(err)
		}
		json.Unmarshal(b, &rec)
		return rec
	}
	if r := runFindings("new", "--from", rep, "--row", py.RowID, "--overlay", overlay); r.code != 0 {
		t.Fatalf("python column: exit %d %s", r.code, r.stderr)
	}
	if rec := record(overlay, "F-5001"); rec.Target.Project != "lightsail-network/py-stellar-xdr" || rec.Target.Ecosystem != "pypi" ||
		rec.Target.Package != "stellar-xdr" || rec.Component != "xdr-library" {
		t.Errorf("python column record: %+v %s", rec.Target, rec.Component)
	}
	if r := runFindings("new", "--from", rep, "--row", rs.RowID); r.code != 0 {
		t.Fatalf("rust column: exit %d %s", r.code, r.stderr)
	}
	if rec := record(root, "F-0001"); rec.Target.Project != "stellar/rs-stellar-xdr" || rec.Target.Ecosystem != "crates" || rec.Component != "xdr-library" {
		t.Errorf("rust column record: %+v %s", rec.Target, rec.Component)
	}
}

// ---- the make targets ----

func buildXdrcheck(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("make"); err != nil {
		t.Skip("make is not installed")
	}
	bin := filepath.Join(t.TempDir(), "xdrcheck")
	out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

// runMake runs a target of the repository's Makefile in dir (a fakeRepo, so that the records under the
// repository's own findings/ do not take part).
func runMake(t *testing.T, bin, dir, target, reports string, env ...string) (int, string) {
	t.Helper()
	// OFFLINE= on the command line: under `make test OFFLINE=1` the outer make passes OFFLINE=1 down in MAKEFLAGS,
	// and this make would wrap its steps in <dir>/scripts/offline-run.sh, which the fake repository lacks.
	cmd := exec.Command("make", "--no-print-directory", "-C", dir, "-f", filepath.Join(repoAbs, "Makefile"), target, "XDRCHECK="+bin, "REPORTS="+reports, "OFFLINE=")
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), string(out)
	} else if err != nil {
		t.Fatal(err)
	}
	return 0, string(out)
}

// `make verify-findings` fails on a failure row with no finding ID and passes when every failure is accounted
// for; `make verify-findings-acceptance` fails on a draft that the development mode accepts.
func TestMakeVerifyFindings(t *testing.T) {
	bin := buildXdrcheck(t)
	dir := fakeRepo(t)
	unlinked := t.TempDir()
	writeReport(t, filepath.Join(unlinked, "replay-regression", "2a0a84ea", "report.json"), "xcc replay", nil, wbRow("r-pass", false, nil), wbRow("r-fail", true, nil))
	code, out := runMake(t, bin, dir, "verify-findings", unlinked)
	if code == 0 || !strings.Contains(out, "failure rows without a finding ID: 1") {
		t.Errorf("verify-findings with an unlinked failure row: exit %d\n%s", code, out)
	}
	clean := t.TempDir()
	selftest := wbRow("r-seeded", true, nil)
	selftest.Target.Kind = "selftest"
	writeReport(t, filepath.Join(clean, "selftest", "report.json"), "xcc replay", nil, wbRow("r-pass", false, nil), selftest)
	code, out = runMake(t, bin, dir, "verify-findings", clean)
	if code != 0 || !strings.Contains(out, findings.DevelopmentBanner) {
		t.Errorf("verify-findings with nothing to link: exit %d\n%s", code, out)
	}

	// A draft record in an overlay outside the tree.
	overlay := t.TempDir()
	putRecord(t, filepath.Join(overlay, "findings"), exampleRecord(t, "F-5001", "draft"))
	linked := t.TempDir()
	writeReport(t, filepath.Join(linked, "replay-regression", "2a0a84ea", "report.json"), "xcc replay", nil, wbRow("r-fail", true, strp("F-5001")))
	code, out = runMake(t, bin, dir, "verify-findings", linked, "XDRCHECK_OVERLAY="+overlay)
	if code != 0 {
		t.Errorf("verify-findings with a linked draft: exit %d\n%s", code, out)
	}
	code, out = runMake(t, bin, dir, "verify-findings-acceptance", linked, "XDRCHECK_OVERLAY="+overlay)
	if code == 0 || !strings.Contains(out, "F-5001 draft") {
		t.Errorf("verify-findings-acceptance with a draft: exit %d\n%s", code, out)
	}
	putRecord(t, filepath.Join(overlay, "findings"), func() *findings.Record {
		r := exampleRecord(t, "F-5001", "duplicate-of")
		r.Upstream = &findings.Upstream{URL: "https://github.com/StellarCN/py-stellar-base/issues/1",
			EvidenceAdded: &findings.EvidenceAdded{Kind: "not-needed", Reason: "the existing report has the same reproduction"}}
		return r
	}())
	code, out = runMake(t, bin, dir, "verify-findings-acceptance", linked, "XDRCHECK_OVERLAY="+overlay)
	if code != 0 {
		t.Errorf("verify-findings-acceptance, every record terminal: exit %d\n%s", code, out)
	}
}

// `make verify-findings` accepts a failure row that a committed pending list names; `make
// verify-findings-acceptance` fails on it and says how many rows wait for an approved finding.
func TestMakeVerifyFindingsPending(t *testing.T) {
	bin := buildXdrcheck(t)
	dir := fakeRepo(t)
	reports := t.TempDir()
	writeReport(t, filepath.Join(reports, "replay-regression", "report.json"), "xcc replay", nil, wbRow("r-fail", true, nil))
	os.MkdirAll(filepath.Join(dir, "findings", "pending"), 0o755)
	list := `{"pending": [{"tool": "replay", "entry": "cap-0040/signed-payload-signer-added", "variant": "testnet", "commit": "2a0a84ea12523b6c92e278c0c84b443041240095"}]}`
	if err := os.WriteFile(filepath.Join(dir, "findings", "pending", "replay.json"), []byte(list), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, out := runMake(t, bin, dir, "verify-findings", reports); code != 0 || !strings.Contains(out, "1 pending finding review") {
		t.Errorf("verify-findings with a pending row: exit %d\n%s", code, out)
	}
	if code, out := runMake(t, bin, dir, "verify-findings-acceptance", reports); code == 0 || !strings.Contains(out, "FAIL pending finding review: rows that need an approved finding: 1") {
		t.Errorf("verify-findings-acceptance with a pending row: exit %d\n%s", code, out)
	}
}

// ---- xdrcheck replay --findings ----

// The development-mode check on the run's own report: the pre-fix halt fails it while no record accounts for
// it, and passes once the manifest's divergence names a finding that has a record.
func TestReplayFindingsFlag(t *testing.T) {
	const prefix = "2a0a84ea12523b6c92e278c0c84b443041240095"
	const entry = "cap-0040/signed-payload-signer-added"

	// A copy of the corpus whose divergence names no finding, whatever the repository's manifest links.
	dir := filepath.Join(t.TempDir(), "corpus")
	if err := copyTree(corpusDir, dir); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(dir, "manifest", "cap-0040", "signed-payload-signer-added.json")
	b, _ := os.ReadFile(f)
	const ref = `"reference": "https://github.com/stellar/wallet-backend/pull/729",`
	if !strings.Contains(string(b), ref) {
		t.Fatal("the divergence reference was not found")
	}
	unlinked := regexp.MustCompile(`(`+regexp.QuoteMeta(ref)+`)\n\s*"finding": "F-[0-9]{4}",`).ReplaceAllString(string(b), "$1")
	os.WriteFile(f, []byte(unlinked), 0o644)

	empty := t.TempDir()
	r := runReplay(t, dir, "", replayArgs(dir, prefix, "--assert-known", "--input", "rpc", "--entries", entry, "--findings", empty)...)
	if r.code != 1 || !strings.Contains(r.stderr, "failure rows without a finding ID") {
		t.Errorf("pre-fix run, no records: exit %d\n%s", r.code, r.stderr)
	}
	r = runReplay(t, corpusDir, "", replayArgs(corpusDir, head, "--assert-known", "--input", "rpc", "--entries", entry, "--findings", empty)...)
	if r.code != 0 {
		t.Errorf("current commit, nothing fails: exit %d\n%s", r.code, r.stderr)
	}

	os.WriteFile(f, []byte(strings.Replace(unlinked, ref, ref+"\n        \"finding\": \"F-0003\",", 1)), 0o644)
	recs := t.TempDir()
	r = runReplay(t, dir, "", replayArgs(dir, prefix, "--assert-known", "--input", "rpc", "--entries", entry, "--findings", recs)...)
	if r.code != 1 || !strings.Contains(r.stderr, "names F-0003, which has no record") {
		t.Errorf("finding without a record: exit %d\n%s", r.code, r.stderr)
	}
	putRecord(t, recs, exampleRecord(t, "F-0003", "candidate"))
	r = runReplay(t, dir, "", replayArgs(dir, prefix, "--assert-known", "--input", "rpc", "--entries", entry, "--findings", recs)...)
	if r.code != 0 || !strings.Contains(r.stderr, "findings check (development): passed") {
		t.Errorf("finding with a record: exit %d\n%s", r.code, r.stderr)
	}
}

func TestSameEcosystemCratesAlias(t *testing.T) {
	if !sameEcosystem("crates.io", "crates") || !sameEcosystem("npm", "npm") || sameEcosystem("crates.io", "pypi") {
		t.Fatal("sameEcosystem: crates.io must match crates, and only its own ecosystem")
	}
}

package findings

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/tolgayayci/xdrcheck/go/internal/report"
)

func conformRow(verdict string, kd *report.DivergenceMatch) report.Row {
	return report.Row{RowID: "conform:cap-0038/pool-issuers-order-by-bytes-not-strkey:testnet:js@17.2.0:L1", Tool: "conform",
		Entry: "cap-0038/pool-issuers-order-by-bytes-not-strkey", Variant: "testnet",
		Target:  report.Target{Name: "@stellar/stellar-sdk", Version: "17.2.0", Kind: "sdk", Column: "js@17.2.0"},
		Failure: report.ConformFailure(verdict), Expectation: "expected", KnownDivergence: kd, Caps: []int{38},
		Conform: &report.ConformResult{Level: "L1", Outcome: "reject", Reason: "ordering", Verdict: verdict}}
}

func TestCandidate(t *testing.T) {
	s := loadSchema(t)
	o := NewOptions{Today: "2026-11-12", Report: "reports/conformance/report.json"}

	// Fixed upstream: public, not security-relevant, linked to the upstream item.
	kd := &report.DivergenceMatch{Reference: "https://github.com/stellar/js-stellar-sdk/pull/1766", Status: "fixed", InRange: true, FixedIn: "17.2.1"}
	row := conformRow("reject_valid", kd)
	rec, err := Candidate("F-0001", &row, o)
	if err != nil {
		t.Fatal(err)
	}
	if errs := s.Validate(asDoc(t, rec)); len(errs) > 0 {
		t.Fatalf("candidate does not validate: %v", errs)
	}
	if rec.Target.Project != "stellar/js-stellar-sdk" || rec.Target.Package != "@stellar/stellar-sdk" || rec.Target.Ecosystem != "npm" ||
		rec.Class != "rejects_valid" || rec.Severity != "medium" || rec.SecurityRelevant || rec.State != "candidate" ||
		rec.Target.FixedIn != "17.2.1" || rec.Entries[0].Scope != "L1" || rec.Evidence.ReportRows[0] != row.RowID {
		t.Errorf("%+v", rec)
	}

	// A halt with no public upstream item is provisionally critical and security-relevant; in the overlay it is
	// embargoed.
	halt := replayRow("replay:x", true, nil, "pipeline")
	rec, err = Candidate("F-0002", &halt, o)
	if err != nil || rec.Severity != "critical" || !rec.SecurityRelevant || rec.Component != "pipeline" || rec.Target.Project != "stellar/wallet-backend" {
		t.Fatalf("%v %+v", err, rec)
	}
	o.Overlay = true
	rec, err = Candidate("F-0002", &halt, o)
	if err != nil || rec.Visibility != "embargoed" || rec.Embargo == nil || rec.Embargo.Trigger != "severity-undetermined" {
		t.Fatalf("%v %+v", err, rec)
	}
	if errs := s.Validate(asDoc(t, rec)); len(errs) > 0 {
		t.Errorf("embargoed candidate does not validate: %v", errs)
	}

	// Sibling: shares the defect group.
	o.Overlay = false
	sib := example(t)
	row = conformRow("reject_valid", kd)
	o.SiblingOf = sib
	rec, _ = Candidate("F-0003", &row, o)
	if rec.DefectGroup != sib.DefectGroup || len(rec.Siblings) != 1 || rec.Siblings[0] != "F-0009" {
		t.Errorf("sibling: %+v", rec)
	}

	// Not findings: passes, selftest rows, corpus rows; unknown upstream.
	pass := conformRow("conform", nil)
	self := replayRow("r", true, nil, "selftest")
	odd := replayRow("r", true, nil, "pipeline")
	odd.Target.Name = "some-indexer"
	for _, r := range []report.Row{pass, self, odd} {
		if _, err := Candidate("F-0004", &r, NewOptions{Today: "2026-11-12"}); err == nil {
			t.Errorf("%s (%s): a candidate was made", r.RowID, r.Target.Name)
		}
	}
}

// One package name in two ecosystems resolves by the row's ecosystem and is refused without one.
func TestUpstreamOfSameName(t *testing.T) {
	for _, c := range []struct{ name, eco, repo, wantEco string }{
		{"stellar-xdr", "crates", "stellar/rs-stellar-xdr", "crates"},
		{"stellar-xdr", RecordEcosystem("crates.io"), "stellar/rs-stellar-xdr", "crates"},
		{"stellar-xdr", "pypi", "lightsail-network/py-stellar-xdr", "pypi"},
		{"@stellar/stellar-sdk", "", "stellar/js-stellar-sdk", "npm"},
		{"github.com/stellar/go-stellar-sdk", "go", "stellar/go-stellar-sdk", "go"},
	} {
		repo, eco, err := UpstreamOf(c.name, c.eco)
		if err != nil || repo != c.repo || eco != c.wantEco {
			t.Errorf("UpstreamOf(%q, %q) = %q, %q, %v; want %q, %q", c.name, c.eco, repo, eco, err, c.repo, c.wantEco)
		}
	}
	if _, _, err := UpstreamOf("stellar-xdr", ""); err == nil || !strings.Contains(err.Error(), "more than one ecosystem") {
		t.Errorf("ambiguous name without an ecosystem: %v", err)
	}
	if _, _, err := UpstreamOf("stellar-xdr", "npm"); err == nil {
		t.Error("stellar-xdr in npm resolved")
	}
}

// The rendered command for the schema's example draft is the command the example records, and an issue body
// follows the template.
func TestRenderIssue(t *testing.T) {
	rec := example(t)
	want := rec.IssueDraft.DryRunCommand
	d, err := RenderIssue(rec, "findings/F-0009")
	if err != nil {
		t.Fatal(err)
	}
	if d.Command != want || d.Kind != "new-issue" || d.File != "issue-py-stellar-base.md" {
		t.Errorf("command\n got %s\nwant %s (%s %s)", d.Command, want, d.Kind, d.File)
	}
	for _, h := range []string{"Title: ", "Affected: `stellar-sdk@17.0.0, 17.0.1`", "## Summary", "## Reproduce", "## Why this is expected",
		"## Same defect elsewhere", "## Suggested fix", "## Corpus", "cap-0027/api-muxed-account-id-encoding.id-2-pow-64",
		"https://github.com/stellar/js-stellar-sdk/pull/1780"} {
		if !strings.Contains(d.Body, h) {
			t.Errorf("body lacks %q:\n%s", h, d.Body)
		}
	}

	rec.UpstreamSearch = &UpstreamSearch{Date: "2026-11-12", Queries: []string{"muxed"}, Result: "existing-open", Existing: "https://github.com/stellar/go-stellar-sdk/issues/5981"}
	rec.IssueDraft = nil
	d, _ = RenderIssue(rec, "findings/F-0009")
	if d.Kind != "comment-on-existing" || d.Command != "gh issue comment 5981 --repo stellar/go-stellar-sdk --body-file findings/F-0009/issue-py-stellar-base.md" {
		t.Errorf("comment: %s %s", d.Kind, d.Command)
	}

	rec.UpstreamSearch = nil
	rec.Title = `Quote "this" and $HOME`
	d, _ = RenderIssue(rec, "findings/F-0009")
	if !strings.Contains(d.Command, `--title "Quote \"this\" and \$HOME"`) {
		t.Errorf("quoting: %s", d.Command)
	}

	rec.Visibility, rec.SecurityRelevant = "embargoed", true
	rec.Embargo = &Embargo{Trigger: "production-halt-or-crash", Policy: "SECURITY.md at abc", Channel: "the project's bug bounty programme"}
	d, _ = RenderIssue(rec, "findings/F-0009")
	if d.Kind != "private-report" || !strings.Contains(d.Command, "bug bounty") {
		t.Errorf("embargoed: %s\n%s", d.Kind, d.Command)
	}
	for _, line := range strings.Split(d.Command, "\n") {
		if !strings.HasPrefix(line, "#") {
			t.Errorf("embargoed: a line that is not a comment: %s", line)
		}
	}
}

// The package never starts a process or opens a connection: no file imports os/exec, net/http, net or syscall.
func TestNoExecNoNetwork(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(af, func(n ast.Node) bool {
			if imp, ok := n.(*ast.ImportSpec); ok {
				p, _ := strconv.Unquote(imp.Path.Value)
				switch p {
				case "os/exec", "net", "net/http", "syscall":
					t.Errorf("%s imports %s", f, p)
				}
			}
			return true
		})
	}
}

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/tolgayayci/xdrcheck/lint/internal/fixture"
	"github.com/tolgayayci/xdrcheck/lint/internal/framework"
)

var (
	buildOnce sync.Once
	binPath   string
	buildErr  error
)

// xdrlintBin builds the command once per test run.
func xdrlintBin(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "xdrlint-test-")
		if err != nil {
			buildErr = err
			return
		}
		binPath = filepath.Join(dir, "xdrlint")
		out, err := exec.Command("go", "build", "-o", binPath, ".").CombinedOutput()
		if err != nil {
			buildErr = errors.New(string(out))
		}
	})
	if buildErr != nil {
		t.Fatalf("building xdrlint: %v", buildErr)
	}
	return binPath
}

type result struct {
	code           int
	stdout, stderr string
}

// run runs a command in the lint module root with the configuration
// environment cleared.
func runCmd(t *testing.T, name string, args ...string) result {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = fixture.ModuleRoot(t)
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "XDRLINT_") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		code = exit.ExitCode()
	} else if err != nil {
		t.Fatalf("%s %v: %v", name, args, err)
	}
	return result{code, stdout.String(), stderr.String()}
}

const xdr000Fixture = "./testdata/xdr0xx/xdr000"

func TestTextOutput(t *testing.T) {
	r := runCmd(t, xdrlintBin(t), xdr000Fixture)
	if r.code != 1 {
		t.Fatalf("exit %d, want 1 (unsuppressed XDR000 errors)\n%s%s", r.code, r.stdout, r.stderr)
	}
	want := "testdata/xdr0xx/xdr000/bad.go:12:2: XDR000 (error): suppression of XDR201 has no reason"
	if !strings.Contains(r.stdout, want) {
		t.Errorf("output lacks %q:\n%s", want, r.stdout)
	}
	// Each diagnostic carries its fix and its rule page; the summary says
	// what failed and how to accept a checked report.
	for _, want := range []string{
		"\tfix: " + framework.XDR000.Fix + "\n",
		"\tdocs: lint/docs/XDR000.md\n",
	} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("output lacks %q:\n%s", want, r.stdout)
		}
	}
	for _, want := range []string{
		"xdrlint: 6 problems (6 errors).",
		"The run fails (exit 1): 6 reports are at or above -fail-on error.",
		"//xdrlint:ignore XDR",
		"suppressions: FILE   in .xdrlint.yml",
	} {
		if !strings.Contains(r.stderr, want) {
			t.Errorf("summary lacks %q:\n%s", want, r.stderr)
		}
	}
	if strings.Contains(r.stderr, "pending") {
		t.Errorf("summary mentions the pending list without -pending:\n%s", r.stderr)
	}
	// One configurable base for the page links, a template when it names {rule}.
	for base, want := range map[string]string{
		"https://example.org/lint/":      "\tdocs: https://example.org/lint/XDR000.md\n",
		"https://example.org/r/{rule}#x": "\tdocs: https://example.org/r/XDR000#x\n",
	} {
		if r := runCmd(t, xdrlintBin(t), "-docs-base", base, xdr000Fixture); !strings.Contains(r.stdout, want) {
			t.Errorf("-docs-base %s: output lacks %q:\n%s", base, want, r.stdout)
		}
	}
	// The pattern ./testdata/... reaches the fixtures (the go command alone would match nothing).
	if r := runCmd(t, xdrlintBin(t), "./testdata/..."); r.code != 1 || !strings.Contains(r.stdout, "testdata/xdr0xx/xdr000/bad.go") {
		t.Errorf("./testdata/...: exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
}

// Every rule built into the command has the one-line fix its diagnostics print.
func TestEveryRuleHasAFix(t *testing.T) {
	for _, r := range framework.Default.Rules() {
		if strings.TrimSpace(r.Fix) == "" || strings.Contains(r.Fix, "\n") {
			t.Errorf("%s: fix %q, want one non-empty line", r.ID, r.Fix)
		}
	}
}

func TestJSONOutput(t *testing.T) {
	r := runCmd(t, xdrlintBin(t), "-json", xdr000Fixture)
	if r.code != 1 {
		t.Fatalf("exit %d\n%s", r.code, r.stderr)
	}
	var tree map[string]map[string][]struct {
		Posn, Message, Rule, Severity, File, Function, Guide, Fix, Docs string
		Suppressed                                                      bool
	}
	if err := json.Unmarshal([]byte(r.stdout), &tree); err != nil {
		t.Fatalf("-json output: %v\n%s", err, r.stdout)
	}
	diags := tree["github.com/tolgayayci/xdrcheck/lint/testdata/xdr0xx/xdr000"]["xdrlint"]
	if len(diags) != 6 {
		t.Fatalf("%d diagnostics, want 6: %+v", len(diags), diags)
	}
	for _, d := range diags {
		if d.Rule != "XDR000" || d.Severity != "error" || d.Function != "describe" || d.Guide == "" ||
			!strings.HasPrefix(d.Message, "XDR000 (error): ") || d.File == "" || !strings.Contains(d.Posn, "bad.go:") ||
			d.Fix != framework.XDR000.Fix || d.Docs != "lint/docs/XDR000.md" {
			t.Errorf("diagnostic %+v", d)
		}
	}
}

func TestReportAndExpect(t *testing.T) {
	bin := xdrlintBin(t)
	dir := t.TempDir()
	report := filepath.Join(dir, "report.json")
	r := runCmd(t, bin, "-profile", "fixtures", "-report", report, "./testdata/...")
	if r.code != 1 {
		t.Fatalf("exit %d\n%s", r.code, r.stderr)
	}
	fixture.ValidateReport(t, report)

	var rep framework.XDRCheckReport
	data, _ := os.ReadFile(report)
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Schema != "xcc.report/v1" || rep.Header.Tool.Name != "xdrlint" || rep.Header.Mode.Suite != "fixtures" || len(rep.Rows) == 0 {
		t.Fatalf("report header %+v, %d rows", rep.Header, len(rep.Rows))
	}
	for _, row := range rep.Rows {
		if row.Target.Kind != "fixture" || row.Target.Profile != "fixtures" || !strings.HasPrefix(row.Lint.Location.File, "testdata/") {
			t.Errorf("row %+v", row)
		}
	}

	// The report itself is a valid expected list: no difference, exit 0.
	if r := runCmd(t, bin, "-profile", "fixtures", "-expect", report, "./testdata/..."); r.code != 0 {
		t.Errorf("-expect with the same reports: exit %d\n%s", r.code, r.stderr)
	}

	entries, err := framework.LoadExpect(report)
	if err != nil {
		t.Fatal(err)
	}
	writeExpect := func(name string, es []framework.ExpectEntry) string {
		p := filepath.Join(dir, name)
		b, _ := json.Marshal(framework.ExpectFile{Schema: framework.ExpectSchema, Reports: es})
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	// One report more than expected. The comparison is of sets of
	// (rule, file, function, suppressed), so every entry with that key goes.
	var fewer []framework.ExpectEntry
	for _, e := range entries {
		if e != entries[0] {
			fewer = append(fewer, e)
		}
	}
	short := writeExpect("short.json", fewer)
	r = runCmd(t, bin, "-profile", "fixtures", "-expect", short, "./testdata/...")
	if r.code != 1 || !strings.Contains(r.stderr, "unexpected report: "+entries[0].String()) {
		t.Errorf("extra report: exit %d\n%s", r.code, r.stderr)
	}

	// One expected report missing.
	ghost := framework.ExpectEntry{Rule: "XDR201", File: "testdata/xdr0xx/xdr000/bad.go", Function: "describe", Suppressed: true}
	long := writeExpect("long.json", append(entries, ghost))
	r = runCmd(t, bin, "-profile", "fixtures", "-expect", long, "./testdata/...")
	if r.code != 1 || !strings.Contains(r.stderr, "missing report: "+ghost.String()) {
		t.Errorf("missing report: exit %d\n%s", r.code, r.stderr)
	}
}

// TestSARIF: -sarif writes a SARIF 2.1.0 log with every rule of the build
// (linked to its page) and one result per finding, suppressed ones carrying a
// SARIF suppression.
func TestSARIF(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.sarif")
	if err := os.WriteFile(filepath.Join(dir, "supp.yml"), []byte(`- rule: XDR102
  file: testdata/xdr1xx/xdr102/bad.go
  function: operationParticipants
  reason: accepted for this test
  finding: F-0001
`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "cfg.yml")
	if err := os.WriteFile(cfg, []byte("suppressions: supp.yml\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := runCmd(t, xdrlintBin(t), "-config", cfg, "-sarif", path, xdr000Fixture, "./testdata/xdr1xx/xdr102")
	if r.code != 1 {
		t.Fatalf("exit %d, want 1\n%s", r.code, r.stderr)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatal(err)
	}
	if log.Version != "2.1.0" || len(log.Runs) != 1 {
		t.Fatalf("version %q, %d runs", log.Version, len(log.Runs))
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "xdrlint" || len(run.Tool.Driver.Rules) != len(framework.Default.Rules()) {
		t.Fatalf("driver %+v", run.Tool.Driver)
	}
	for i, rule := range run.Tool.Driver.Rules {
		if !strings.HasSuffix(rule.HelpURI, "/lint/docs/"+rule.ID+".md") || rule.ShortDescription.Text == "" {
			t.Errorf("rule %d: %+v", i, rule)
		}
	}
	var suppressed, xdr000 int
	for _, res := range run.Results {
		if run.Tool.Driver.Rules[res.RuleIndex].ID != res.RuleID {
			t.Errorf("result %s: ruleIndex %d", res.RuleID, res.RuleIndex)
		}
		loc := res.Locations[0].PhysicalLocation
		if loc.ArtifactLocation.URIBaseID != "SRCROOT" || !strings.HasPrefix(loc.ArtifactLocation.URI, "testdata/") || loc.Region.StartLine < 1 {
			t.Errorf("result %s: location %+v", res.RuleID, loc)
		}
		if len(res.Suppressions) > 0 {
			suppressed++
			if res.Suppressions[0].Kind != "external" || res.Suppressions[0].Justification != "accepted for this test" || res.Properties["finding"] != "F-0001" {
				t.Errorf("result %s: suppression %+v", res.RuleID, res.Suppressions[0])
			}
		}
		if res.RuleID == "XDR000" {
			xdr000++
			if res.Level != "error" {
				t.Errorf("XDR000 level %q", res.Level)
			}
		}
	}
	if suppressed == 0 || xdr000 == 0 {
		t.Errorf("%d results: %d suppressed, %d XDR000; want both", len(run.Results), suppressed, xdr000)
	}
}

func TestVetTool(t *testing.T) {
	bin := xdrlintBin(t)
	r := runCmd(t, "go", "vet", "-vettool="+bin, "./testdata/xdr0xx/xdr000")
	if r.code == 0 {
		t.Fatalf("go vet passed; want XDR000 reports\n%s", r.stderr)
	}
	for _, want := range []string{
		"bad.go:12:2: XDR000 (error): suppression of XDR201 has no reason",
		"bad.go:26:2: XDR000 (error): XDR000 cannot be suppressed",
	} {
		if !strings.Contains(r.stderr, want) {
			t.Errorf("go vet output lacks %q:\n%s", want, r.stderr)
		}
	}
}

func TestSuppressionFile(t *testing.T) {
	dir := t.TempDir()
	supp := filepath.Join(dir, "supp.yml")
	if err := os.WriteFile(supp, []byte(`- rule: XDR201
  file: testdata/xdr0xx/xdr000/bad.go
  function: describe
- rule: XDR999
  file: testdata/xdr0xx/xdr000/bad.go
  function: describe
  reason: not a rule
`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "cfg.yml")
	if err := os.WriteFile(cfg, []byte("suppressions: supp.yml\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := runCmd(t, xdrlintBin(t), "-config", cfg, xdr000Fixture)
	for _, want := range []string{"supp.yml:1:1: XDR000 (error): suppression entry has no reason", "supp.yml:4:1: XDR000 (error): suppression entry names unknown rule XDR999"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("output lacks %q:\n%s%s", want, r.stdout, r.stderr)
		}
	}
}

// TestConfigNames: a configured sink in a loaded package that does not
// exist there stops the run; one in a package that is not loaded does not.
func TestConfigNames(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	const pkg = "github.com/tolgayayci/xdrcheck/lint/testdata/xdr1xx/xdr102"
	bad := write("bad.yml", "sinksaccountkey: ["+pkg+".AddressByte]\n")
	r := runCmd(t, xdrlintBin(t), "-config", bad, "./testdata/xdr1xx/xdr102")
	if r.code != 2 || !strings.Contains(r.stderr, "sinksaccountkey: "+pkg+".AddressByte: package "+pkg+" has no AddressByte") {
		t.Errorf("misspelt sink: exit %d\n%s", r.code, r.stderr)
	}
	elsewhere := write("elsewhere.yml", "sinksaccountkey: [example.com/not/loaded.AddressBytea]\n")
	if r := runCmd(t, xdrlintBin(t), "-config", elsewhere, xdr000Fixture); r.code == 2 {
		t.Errorf("sink in a package that is not loaded: exit 2\n%s", r.stderr)
	}
	reserved := write("reserved.yml", "rules: [XDR101, XDR208]\n")
	if r := runCmd(t, xdrlintBin(t), "-config", reserved, xdr000Fixture); r.code != 2 || !strings.Contains(r.stderr, `unknown rule "XDR208"`) {
		t.Errorf("unknown rule: exit %d\n%s", r.code, r.stderr)
	}
}

// TestNoSourcePackage: packages that load none of go-stellar-sdk's xdr
// package give the rules nothing to follow; the run warns and exits 2
// instead of reporting a clean run.
func TestNoSourcePackage(t *testing.T) {
	r := runCmd(t, xdrlintBin(t), "./testdata/xdr0xx/hygiene")
	if r.code != 2 || !strings.Contains(r.stderr, "no recognised source package is loaded") {
		t.Errorf("exit %d, want 2 with a warning\n%s%s", r.code, r.stdout, r.stderr)
	}
	if r.stdout != "" {
		t.Errorf("reports printed for a run that analysed nothing:\n%s", r.stdout)
	}
}

func TestUsageErrors(t *testing.T) {
	bin := xdrlintBin(t)
	for _, args := range [][]string{
		{"-profile", "no-such-profile", xdr000Fixture},
		{"-fail-on", "never", xdr000Fixture},
		{"-expect", "no-such-file.json", xdr000Fixture},
		{},
	} {
		if r := runCmd(t, bin, args...); r.code != 2 {
			t.Errorf("%v: exit %d, want 2\n%s", args, r.code, r.stderr)
		}
	}
}

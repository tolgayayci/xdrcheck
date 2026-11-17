package framework_test

import (
	"encoding/json"
	"go/ast"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tolgayayci/xdrcheck/lint/internal/fixture"
	"github.com/tolgayayci/xdrcheck/lint/internal/framework"
)

// demoRegistry returns a registry with one demonstration rule, XDR990,
// reporting every call of a function named sink.
func demoRegistry(t *testing.T) (*framework.Registry, *framework.Spec) {
	t.Helper()
	reg := framework.NewRegistry()
	spec := framework.Spec{
		Name: "demo",
		Doc:  "demo reports calls of sink()",
		Rules: []framework.Rule{{
			ID: "XDR990", Family: "XDR9xx", Title: "demo sink called", Severity: framework.SeverityError, Assumption: framework.AssumeSuppression,
			Guide: "demo", Corpus: "demo/entry", Checklist: "HC-990",
		}},
		Run: func(p *framework.Pass) (any, error) {
			for _, f := range p.Files {
				ast.Inspect(f, func(n ast.Node) bool {
					if call, ok := n.(*ast.CallExpr); ok {
						if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "sink" {
							p.Reportf("XDR990", call, "demo sink called")
						}
					}
					return true
				})
			}
			return nil, nil
		},
	}
	reg.Register(spec)
	reg.SetConfig(&framework.Config{})
	return reg, &spec
}

func TestSuppressionPlacement(t *testing.T) {
	reg, _ := demoRegistry(t)
	fixture.Run(t, reg.Analyzers()[0], "xdr0xx/suppress")
}

func TestDirectiveHygiene(t *testing.T) {
	reg, _ := demoRegistry(t)
	fixture.Run(t, reg.Directive(), "xdr0xx/hygiene")
}

// TestShippedXDR000 runs the XDR000 analyzer of the real build (the
// Default registry) over its fixture, which imports go-stellar-sdk v0.9.0.
func TestShippedXDR000(t *testing.T) {
	framework.SetConfig(&framework.Config{})
	t.Cleanup(func() { framework.SetConfig(nil) })
	fixture.Run(t, framework.Default.Directive(), "xdr0xx/xdr000")
}

func TestDisabledRuleIsSilent(t *testing.T) {
	reg, _ := demoRegistry(t)
	reg.SetConfig(&framework.Config{Rules: []string{"XDR000"}})
	res := fixture.Run(&quiet{T: t}, reg.Analyzers()[0], "xdr0xx/suppress")
	for _, r := range res {
		if len(r.Diagnostics) != 0 {
			t.Errorf("disabled rule reported %d diagnostics", len(r.Diagnostics))
		}
	}
}

// quiet swallows analysistest's expectation errors (the fixture expects
// reports that a disabled rule must not produce).
type quiet struct{ *testing.T }

func (q *quiet) Errorf(string, ...any) {}

func TestSeverityOverride(t *testing.T) {
	reg, _ := demoRegistry(t)
	reg.SetConfig(&framework.Config{Severity: map[string]framework.Severity{"XDR990": framework.SeverityInfo}})
	res := fixture.Run(&quiet{T: t}, reg.Analyzers()[0], "xdr0xx/suppress")
	n := 0
	for _, r := range res {
		for _, d := range r.Diagnostics {
			n++
			if !strings.HasPrefix(d.Message, "XDR990 (info): ") || d.Category != "XDR990" {
				t.Errorf("diagnostic %q (category %q): want the info prefix", d.Message, d.Category)
			}
		}
		fr := r.Result.(*framework.Result)
		sup := 0
		for _, f := range fr.Findings {
			if f.Suppressed {
				sup++
				if f.Suppression.Kind != "inline" || f.Suppression.Reason == "" {
					t.Errorf("suppressed finding without an inline reason: %+v", f)
				}
			}
			if f.File != "testdata/xdr0xx/suppress/suppress.go" {
				t.Errorf("finding file %q, want module-relative", f.File)
			}
		}
		if sup != 7 {
			t.Errorf("%d suppressed findings, want 7 (trailing, above, two-line, doc ×2, several, first of two)", sup)
		}
	}
	if n != 5 {
		t.Errorf("%d diagnostics, want 5", n)
	}
}

func TestEnclosingFunction(t *testing.T) {
	src := `package p
type T struct{}
func (t *T) M() { _ = 1 }
func F() { func() { _ = 2 }() }
var v = 3
`
	fset := token.NewFileSet()
	f := parseFile(t, fset, src)
	cases := map[string]string{"_ = 1": "T.M", "_ = 2": "F", "v = 3": ""}
	for needle, want := range cases {
		pos := f.FileStart + token.Pos(strings.Index(src, needle))
		if got := framework.EnclosingFunction(fset, []*ast.File{f}, pos); got != want {
			t.Errorf("EnclosingFunction(%q) = %q, want %q", needle, got, want)
		}
	}
}

func TestSplitMessage(t *testing.T) {
	id, sev, text, ok := framework.SplitMessage("XDR201 (warning): unbounded recursion")
	if !ok || id != "XDR201" || sev != framework.SeverityWarning || text != "unbounded recursion" {
		t.Errorf("SplitMessage = %q %q %q %v", id, sev, text, ok)
	}
	if _, _, _, ok := framework.SplitMessage("plain message"); ok {
		t.Error("SplitMessage accepted a message without a rule")
	}
}

func TestRegisterRejects(t *testing.T) {
	bad := []framework.Rule{
		{ID: "XDR1", Family: framework.FamilyUnvalidated, Title: "t", Severity: framework.SeverityError},
		{ID: "XDR101", Family: framework.FamilyCaps, Title: "t", Severity: framework.SeverityError},
		{ID: "XDR101", Family: framework.FamilyUnvalidated, Title: "t", Severity: "fatal"},
		{ID: "XDR000", Family: framework.FamilyHygiene, Title: "t", Severity: framework.SeverityError},
	}
	for _, r := range bad {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("Register accepted %+v", r)
				}
			}()
			framework.NewRegistry().Register(framework.Spec{Name: "x", Rules: []framework.Rule{r}, Run: func(*framework.Pass) (any, error) { return nil, nil }})
		}()
	}
	reg, spec := demoRegistry(t)
	reg.Analyzers()
	func() {
		defer func() {
			if recover() == nil {
				t.Error("Register after Analyzers did not panic")
			}
		}()
		s := *spec
		s.Rules = []framework.Rule{{ID: "XDR991", Family: "XDR9xx", Title: "t", Severity: framework.SeverityInfo, Assumption: framework.AssumeSuppression}}
		reg.Register(s)
	}()
	if r := reg.Rule("XDR990"); r == nil || r.Corpus != "demo/entry" || r.Guide != "demo" {
		t.Errorf("Rule(XDR990) = %+v", r)
	}
}

func write(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestConfigLayers(t *testing.T) {
	reg, _ := demoRegistry(t)
	dir := t.TempDir()
	write(t, dir, "supp.yml", `
- rule: XDR990
  file: internal/x.go
  function: walk
  reason: reviewed
  finding: F-0001
- rule: XDR990
  file: internal/x.go
  function: f
- rule: XDR990
  file: internal/x.go
  reason: no function or anchor
- rule: XDR990
  file: internal/x.go
  anchor: "participants.Add("
  reason: anchored
  colour: red
- rule: XDR201
  file: internal/x.go
  function: walk
  reason: a reserved rule the registry does not provide
- rule: XDR999
  file: internal/x.go
  function: walk
  reason: not a rule
`)
	cfg := write(t, dir, "cfg.yml", `
rules: [XDR990, XDR201, XDR000]
severity: {XDR990: warning}
sinksparticipant: [example.com/p.Set.Add]
overflowpolicy: halt-ledger
suppressions: supp.yml
`)
	c, err := framework.Load(framework.LoadOptions{Profile: "default", ConfigFile: cfg})
	if err != nil {
		t.Fatal(err)
	}
	// XDR201 is reserved, but this registry does not provide it: enabling it
	// would check nothing, so the configuration is rejected.
	if err := c.Validate(reg); err == nil || !strings.Contains(err.Error(), `rule "XDR201" is reserved but not provided by this build`) {
		t.Errorf("reserved, unregistered XDR201: %v", err)
	}
	if err := c.Validate(framework.Default); err == nil {
		t.Error("XDR990 accepted by a registry that does not have it")
	}
	provided := *c
	provided.Rules = []string{"XDR990", "XDR000"}
	if err := provided.Validate(reg); err != nil {
		t.Fatal(err)
	}
	if strings.Join(c.Rules, ",") != "XDR990,XDR201,XDR000" {
		t.Errorf("rules = %v: a later layer replaces the list", c.Rules)
	}
	if c.Severity["XDR990"] != framework.SeverityWarning || c.OverflowPolicy != framework.PolicyHaltLedger || len(c.SinksParticipant) != 1 {
		t.Errorf("config = %+v", c)
	}
	if len(c.Layers) != 2 || c.Layers[0] != "profiles/default.yml" {
		t.Errorf("layers = %v", c.Layers)
	}
	if len(c.SuppressionFiles) != 1 || len(c.SuppressionFiles[0].Entries) != 6 {
		t.Fatalf("suppression files = %+v", c.SuppressionFiles)
	}
	var problems []string
	for _, s := range c.SuppressionFiles[0].Entries {
		problems = append(problems, s.Problem)
	}
	want := []string{"", "has no reason", "names none of a function, an anchor, a line and a message", `unknown key "colour"`, "", ""}
	if strings.Join(problems, "|") != strings.Join(want, "|") {
		t.Errorf("problems = %q, want %q", problems, want)
	}

	// Malformed, unprovided and unknown entries are XDR000; so is an
	// entry that matched nothing.
	first := c.SuppressionFiles[0].Entries[0].Key()
	fs := reg.SuppressionFindings(c, map[string]bool{first: true})
	if len(fs) != 5 {
		t.Fatalf("%d suppression findings, want 5: %+v", len(fs), fs)
	}
	fs = reg.SuppressionFindings(c, map[string]bool{})
	if len(fs) != 6 || fs[0].Rule != "XDR000" || fs[0].Position.Line != 2 || !strings.Contains(fs[0].Message, "matches nothing") {
		t.Errorf("unused entry not reported: %+v", fs)
	}
	// A rule that is switched off is not checked.
	off := *c
	off.Rules = []string{"XDR000"}
	if fs := reg.SuppressionFindings(&off, map[string]bool{}); len(fs) != 5 {
		t.Errorf("%d findings with XDR990 off, want 5 (the stale XDR990 entry is not checked)", len(fs))
	}
}

func TestConfigErrors(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"unknown-key.yml":  "rulez: [XDR101]\n",
		"bad-rule.yml":     "rules: [XDR777]\n",
		"bad-severity.yml": "severity: {XDR101: fatal}\n",
		"bad-policy.yml":   "overflowpolicy: carry-on\n",
		"bad-regex.yml":    "participantnameregex: \"(\"\n",
		"bad-kind.yml":     "targetkind: indexer\n",
		"missing-supp.yml": "suppressions: nowhere.yml\n",
		"not-a-list.yml":   "suppressions: map.yml\n",
		"map.yml":          "rule: XDR101\n",
	} {
		write(t, dir, name, content)
	}
	for _, name := range []string{"unknown-key.yml", "bad-rule.yml", "bad-severity.yml", "bad-policy.yml", "bad-regex.yml", "bad-kind.yml", "missing-supp.yml", "not-a-list.yml"} {
		c, err := framework.Load(framework.LoadOptions{ConfigFile: filepath.Join(dir, name)})
		if err == nil {
			err = c.Validate(framework.Default)
		}
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := framework.Load(framework.LoadOptions{Profile: "no-such-profile"}); err == nil {
		t.Error("unknown profile accepted")
	}
}

func TestDiscovery(t *testing.T) {
	root := t.TempDir()
	write(t, root, "go.mod", "module example.com/m\n")
	write(t, root, ".xdrlint.yml", "rules: [XDR000]\n")
	sub := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	c, err := framework.Load(framework.LoadOptions{DiscoverFrom: sub})
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Rules) != 1 || c.Rules[0] != "XDR000" {
		t.Errorf("discovered config not loaded: %+v", c)
	}
	if got := framework.ModuleRelPath(filepath.Join(sub, "x.go")); got != "a/b/x.go" {
		t.Errorf("ModuleRelPath = %q", got)
	}
}

func sampleFindings() []framework.Finding {
	pos := func(line int) token.Position {
		return token.Position{Filename: "/abs/internal/x.go", Line: line, Column: 2}
	}
	return []framework.Finding{
		{Rule: "XDR201", Severity: framework.SeverityWarning, Message: "unbounded recursion", Position: pos(10), File: "internal/x.go", Function: "walk",
			Suppressed: true, Suppression: &framework.SuppressionRef{Kind: "file", Reason: "reviewed", Finding: "F-0014", Source: "supp.yml:2"}},
		{Rule: "XDR102", Severity: framework.SeverityError, Message: "muxed address as identity", Position: pos(20), File: "internal/x.go", Function: "T.M"},
		{Rule: "XDR102", Severity: framework.SeverityError, Message: "again", Position: pos(22), File: "internal/x.go", Function: "T.M"},
		{Rule: "XDR207", Severity: framework.SeverityInfo, Message: "no floor", Position: pos(30), File: "internal/x.go", Function: "walk"},
		{Rule: "XDR000", Severity: framework.SeverityError, Message: "suppression has no reason", Position: token.Position{Filename: "supp.yml", Line: 7, Column: 1}, File: "supp.yml"},
	}
}

func TestBuildReport(t *testing.T) {
	rules := map[string]framework.Rule{"XDR201": {ID: "XDR201", Corpus: "cap-0046/scval-nested-vec-99-in-event"}}
	rep := framework.BuildReport(framework.ReportMeta{
		ToolVersion: "0.1.0", TargetName: "stellar/wallet-backend", TargetVersion: "e967ce8b7362b79c277e700e789181d76fbb5967",
		TargetKind: "pipeline", Profile: "wallet-backend", Suite: "wallet-backend", Rules: rules,
	}, sampleFindings())
	if rep.Summary.Rows != 5 || rep.Summary.Failures != 4 || rep.Summary.FailuresWithoutFinding != 3 || rep.Summary.Unexpected != 3 {
		t.Errorf("summary = %+v", rep.Summary)
	}
	ids := map[string]bool{}
	for _, r := range rep.Rows {
		if ids[r.RowID] {
			t.Errorf("duplicate row_id %s", r.RowID)
		}
		ids[r.RowID] = true
	}
	r0 := rep.Rows[0]
	if r0.RowID != "lint:stellar/wallet-backend@e967ce8b:XDR201:internal/x.go:walk" || r0.Finding == nil || *r0.Finding != "F-0014" ||
		r0.Expectation != "expected" || r0.Entry != "cap-0046/scval-nested-vec-99-in-event" || !r0.Lint.Suppressed {
		t.Errorf("row 0 = %+v", r0)
	}
	if !ids["lint:stellar/wallet-backend@e967ce8b:XDR102:internal/x.go:T.M#2"] {
		t.Errorf("second XDR102 row has no disambiguated id: %v", ids)
	}
	p := filepath.Join(t.TempDir(), "report.json")
	data, _ := json.MarshalIndent(rep, "", "  ")
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	fixture.ValidateReport(t, p)
}

// A report the pending list names is marked pending (not unexpected), below -fail-on too; a suppressed one and
// one on another line are not.
func TestBuildReportPending(t *testing.T) {
	const commit = "e967ce8b7362b79c277e700e789181d76fbb5967"
	dir := t.TempDir()
	pf := write(t, dir, "p.json", `{"schema":"xdrlint.pending/v1","commit":"`+commit+`","since":"2026-11-13","pending":[
		{"rule":"XDR102","file":"internal/x.go","line":20},{"rule":"XDR207","file":"internal/x.go","line":30},
		{"rule":"XDR201","file":"internal/x.go","line":10}]}`)
	pending, err := framework.LoadPending(pf, commit)
	if err != nil || len(pending) != 3 {
		t.Fatalf("LoadPending = %v, %v", pending, err)
	}
	if _, err := framework.LoadPending(pf, "666a64d426263fa6bd2a0ee61ee8dfb1f4729019"); err == nil {
		t.Error("a list for another commit was accepted")
	}
	rep := framework.BuildReport(framework.ReportMeta{TargetName: "stellar/wallet-backend", TargetVersion: commit, Pending: pending}, sampleFindings())
	want := []string{"expected", framework.ExpectationPending, "unexpected", framework.ExpectationPending, "unexpected"}
	for i, r := range rep.Rows {
		if r.Expectation != want[i] {
			t.Errorf("row %d (%s): %s, want %s", i, r.RowID, r.Expectation, want[i])
		}
	}
	if rep.Summary.Unexpected != 2 {
		t.Errorf("summary = %+v", rep.Summary)
	}
	p := filepath.Join(dir, "report.json")
	data, _ := json.MarshalIndent(rep, "", "  ")
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	fixture.ValidateReport(t, p)
}

func TestExpect(t *testing.T) {
	fs := sampleFindings()
	var exp []framework.ExpectEntry
	for _, f := range fs {
		exp = append(exp, f.Key())
	}
	if m, x := framework.CompareExpect(exp, fs); len(m)+len(x) != 0 {
		t.Errorf("identical sets differ: %v %v", m, x)
	}
	m, x := framework.CompareExpect(exp[1:], fs)
	if len(m) != 0 || len(x) != 1 || x[0].Rule != "XDR201" {
		t.Errorf("extra report not found: %v %v", m, x)
	}
	m, x = framework.CompareExpect(append(exp, framework.ExpectEntry{Rule: "XDR301", File: "a.go", Function: "f"}), fs)
	if len(m) != 1 || len(x) != 0 {
		t.Errorf("missing report not found: %v %v", m, x)
	}
	// Suppressed or not is part of the key.
	flipped := append([]framework.ExpectEntry(nil), exp...)
	flipped[0].Suppressed = false
	if m, x := framework.CompareExpect(flipped, fs); len(m) != 1 || len(x) != 1 {
		t.Errorf("suppression state not compared: %v %v", m, x)
	}

	// The list is a multiset: a second report of an expected key is extra,
	// and a count above what is reported is missing.
	twice := append(fs, fs[0])
	if m, x := framework.CompareExpect(exp, twice); len(m) != 0 || len(x) != 1 || x[0].Rule != fs[0].Rule || x[0].Function != fs[0].Function || x[0].Count != 1 {
		t.Errorf("second report of a listed key not extra: %v %v", m, x)
	}
	counted := append([]framework.ExpectEntry(nil), exp...)
	counted[0].Count = 2
	if m, x := framework.CompareExpect(counted, twice); len(m)+len(x) != 0 {
		t.Errorf("count 2 against two reports: %v %v", m, x)
	}
	if m, x := framework.CompareExpect(counted, fs); len(m) != 1 || m[0].Count != 1 || len(x) != 0 {
		t.Errorf("count 2 against one report: %v %v", m, x)
	}
	if m, x := framework.CompareExpect(append(exp, exp[0]), twice); len(m)+len(x) != 0 {
		t.Errorf("a key listed twice counts twice: %v %v", m, x)
	}
	if rep := framework.BuildReport(framework.ReportMeta{Expect: exp}, twice); rep.Summary.Unexpected != 1 {
		t.Errorf("report with one report beyond the list: %d unexpected rows, want 1", rep.Summary.Unexpected)
	}

	rep := framework.BuildReport(framework.ReportMeta{Expect: exp[1:]}, fs)
	if rep.Rows[0].Expectation != "unexpected" || rep.Rows[1].Expectation != "expected" {
		t.Errorf("expectations with -expect: %s %s", rep.Rows[0].Expectation, rep.Rows[1].Expectation)
	}

	dir := t.TempDir()
	ef, _ := json.Marshal(framework.ExpectFile{Schema: framework.ExpectSchema, Reports: exp})
	p := write(t, dir, "expect.json", string(ef))
	got, err := framework.LoadExpect(p)
	if err != nil || len(got) != len(exp) {
		t.Errorf("LoadExpect = %v, %v", got, err)
	}
	rf, _ := json.Marshal(framework.BuildReport(framework.ReportMeta{}, fs))
	got, err = framework.LoadExpect(write(t, dir, "report.json", string(rf)))
	if err != nil || len(got) != len(fs) {
		t.Errorf("LoadExpect(report) = %v, %v", got, err)
	}
	if _, err := framework.LoadExpect(write(t, dir, "bad.json", `{"schema":"other"}`)); err == nil {
		t.Error("LoadExpect accepted an unknown schema")
	}
}

// A pending entry may give its site as SiteHash(rule, file, line) instead of the file and line.
func TestIsPendingHashedSite(t *testing.T) {
	f := framework.Finding{Rule: "XDR102", File: "internal/x.go", Position: token.Position{Line: 12}}
	hashed := []framework.PendingEntry{{Rule: "XDR102", Site: framework.SiteHash("XDR102", "internal/x.go", 12)}}
	if !framework.IsPending(hashed, f) {
		t.Error("hashed site not matched")
	}
	f.Position.Line = 13
	if framework.IsPending(hashed, f) {
		t.Error("hashed site matched another line")
	}
	if framework.IsPending([]framework.PendingEntry{{Rule: "XDR102", Site: "x"}}, framework.Finding{Rule: "XDR102", File: "", Position: token.Position{}}) {
		t.Error("a site entry matched by its empty file and line")
	}
}

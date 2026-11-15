package findings

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tolgayayci/xdrcheck/go/internal/report"
)

const (
	schemaPath   = "../../../corpus/schema/finding-record.schema.json"
	examplesDir  = "../../../corpus/schema/examples/finding-record"
	reportsExDir = "../../../corpus/schema/examples/report"
)

func loadSchema(t *testing.T) *Schema {
	t.Helper()
	s, err := LoadSchema(schemaPath)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// example returns the draft record of the schema's first valid example.
func example(t *testing.T) *Record {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(examplesDir, "valid-01.json"))
	if err != nil {
		t.Fatal(err)
	}
	var r Record
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	return &r
}

// recordIn returns a valid record with the given ID in the given state.
func recordIn(t *testing.T, id, state string) *Record {
	r := example(t)
	r.ID, r.State = id, state
	r.IssueDraft.DryRunCommand = strings.ReplaceAll(r.IssueDraft.DryRunCommand, "F-0009", id)
	switch state {
	case "candidate":
		r.IssueDraft, r.Reproduction, r.UpstreamSearch, r.Evidence = nil, nil, nil, nil
	case "approved":
		r.Approval = &Approval{By: "user", Date: "2026-11-12", Scope: "this draft, new issue"}
	case "filed":
		r.Approval = &Approval{By: "user", Date: "2026-11-12", Scope: "this draft, new issue"}
		r.Upstream = &Upstream{URL: "https://github.com/StellarCN/py-stellar-base/issues/1", FiledAt: "2026-11-13"}
	case "duplicate-of":
		r.Upstream = &Upstream{URL: "https://github.com/StellarCN/py-stellar-base/issues/1",
			EvidenceAdded: &EvidenceAdded{Kind: "not-needed", Reason: "fixed upstream with the same reproduction"}}
	case "not-a-defect":
		r.Resolution = &Resolution{Reason: "the expectation was wrong: the input is valid", Reviewer: "independent-reviewer", Date: "2026-11-13"}
	}
	r.History = append(r.History, HistoryItem{Date: "2026-11-13", State: state})
	return r
}

func asDoc(t *testing.T, r *Record) any {
	t.Helper()
	b, err := Encode(r)
	if err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := decodeJSON(b, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

// The validator accepts the schema's valid examples and rejects its invalid ones, and the seven deliberately
// wrong inputs: a record cannot skip a step of the lifecycle the schema encodes.
func TestSchemaExamples(t *testing.T) {
	s := loadSchema(t)
	files, _ := filepath.Glob(filepath.Join(examplesDir, "*.json"))
	if len(files) == 0 {
		t.Fatal("no examples")
	}
	for _, f := range files {
		b, _ := os.ReadFile(f)
		errs := s.ValidateBytes(b)
		if strings.HasPrefix(filepath.Base(f), "valid") && len(errs) > 0 {
			t.Errorf("%s: %v", f, errs)
		}
		if strings.HasPrefix(filepath.Base(f), "invalid") && len(errs) == 0 {
			t.Errorf("%s validates", f)
		}
	}
	for _, state := range []string{"candidate", "draft", "approved", "filed", "duplicate-of", "not-a-defect"} {
		if errs := s.Validate(asDoc(t, recordIn(t, "F-0001", state))); len(errs) > 0 {
			t.Errorf("fixture in state %s: %v", state, errs)
		}
	}
	wrong := map[string]func(r *Record){
		"filed without approval":            func(r *Record) { *r = *recordIn(t, "F-0001", "filed"); r.Approval = nil },
		"filed public without a URL":        func(r *Record) { *r = *recordIn(t, "F-0001", "filed"); r.Upstream.URL = "" },
		"duplicate-of without evidence":     func(r *Record) { *r = *recordIn(t, "F-0001", "duplicate-of"); r.Upstream.EvidenceAdded = nil },
		"draft without a reproduction":      func(r *Record) { r.Reproduction = nil },
		"embargoed without embargo":         func(r *Record) { r.Visibility = "embargoed"; r.SecurityRelevant = true },
		"not-a-defect without a resolution": func(r *Record) { *r = *recordIn(t, "F-0001", "not-a-defect"); r.Resolution = nil },
		"draft without issue text":          func(r *Record) { r.IssueDraft = nil },
		"title too short":                   func(r *Record) { r.Title = "short" },
		"bad ID":                            func(r *Record) { r.ID = "F-123" },
		"approval by a person":              func(r *Record) { *r = *recordIn(t, "F-0001", "approved"); r.Approval.By = "someone" },
		"unknown state":                     func(r *Record) { r.State = "wontfix" },
		"embargoed and not security-relevant": func(r *Record) {
			r.Visibility = "embargoed"
			r.Embargo = &Embargo{Trigger: "severity-undetermined", Policy: "p", Channel: "c"}
		},
	}
	for name, mutate := range wrong {
		r := example(t)
		mutate(r)
		if errs := s.Validate(asDoc(t, r)); len(errs) == 0 {
			t.Errorf("%s: validates", name)
		}
	}
	var extra map[string]any
	json.Unmarshal(mustEncode(t, example(t)), &extra)
	extra["owner"] = "someone"
	if errs := s.Validate(extra); len(errs) == 0 {
		t.Error("an unknown property validates")
	}
}

func mustEncode(t *testing.T, r *Record) []byte {
	b, err := Encode(r)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSchemaRejectsUnsupportedKeyword(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.json")
	os.WriteFile(p, []byte(`{"type":"object","patternProperties":{"^x":{"type":"string"}}}`), 0o644)
	if _, err := LoadSchema(p); err == nil || !strings.Contains(err.Error(), "patternProperties") {
		t.Errorf("unsupported keyword: %v", err)
	}
}

// ---- fixtures: records on disk, reports written with the report writer ----

type fixture struct {
	t       *testing.T
	public  string
	overlay string
	reports string
	schema  *Schema
	// privateRow is the checker's PrivateRow test.
	privateRow func(string) bool
}

func newFixture(t *testing.T) *fixture {
	d := t.TempDir()
	f := &fixture{t: t, public: filepath.Join(d, "findings"), overlay: filepath.Join(d, "overlay", "findings"), reports: filepath.Join(d, "reports"), schema: loadSchema(t)}
	os.MkdirAll(f.public, 0o755)
	os.MkdirAll(f.reports, 0o755)
	return f
}

func (f *fixture) record(r *Record, overlay bool) {
	f.t.Helper()
	dir := f.public
	if overlay {
		dir = f.overlay
	}
	os.MkdirAll(filepath.Join(dir, r.ID), 0o755)
	if err := os.WriteFile(filepath.Join(dir, r.ID, RecordFile), mustEncode(f.t, r), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

func str(s string) *string { return &s }

// replayRow is a wallet-backend replay row; failure rows are mishandled·halt.
func replayRow(id string, failure bool, finding *string, kind string) report.Row {
	r := report.Row{RowID: id, Tool: "replay", Entry: "cap-0040/signed-payload-signer-added", Variant: "testnet",
		Target:  report.Target{Name: "stellar/wallet-backend", Version: "2a0a84ea12523b6c92e278c0c84b443041240095", Kind: kind},
		Failure: failure, Expectation: "expected", Finding: finding,
		Replay: &report.ReplayResult{Unit: "single", Class: "pass"}}
	if failure {
		r.Replay.Class, r.Replay.Qualifier = "mishandled", "halt"
	}
	return r
}

func (f *fixture) report(name string, overlay bool, rows ...report.Row) string {
	f.t.Helper()
	p := filepath.Join(f.reports, name)
	os.MkdirAll(filepath.Dir(p), 0o755)
	h := report.Header{Tool: report.Tool{Name: "xcc replay", Version: "0.1.0"},
		Corpus: report.CorpusRef{Version: "test", ManifestSHA256: strings.Repeat("0", 64)},
		Pins:   report.PinsRef{FileSHA256: strings.Repeat("0", 64)}, Mode: report.Mode{Suite: "test", Overlay: overlay}}
	w, err := report.Create(p, h)
	if err != nil {
		f.t.Fatal(err)
	}
	for _, r := range rows {
		if err := w.Write(r); err != nil {
			f.t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		f.t.Fatal(err)
	}
	return p
}

func (f *fixture) check(mode string, withOverlay bool) (*Result, error) {
	ov := ""
	if withOverlay {
		ov = f.overlay
	}
	s, err := Load(f.schema, f.public, ov)
	if err != nil {
		return nil, err
	}
	paths, err := FindReports(f.reports)
	if err != nil {
		return nil, err
	}
	c := NewChecker(s)
	c.AllowOverlay = withOverlay
	c.PrivateRow = f.privateRow
	for _, p := range paths {
		if err := c.AddReport(p); err != nil {
			return nil, err
		}
	}
	return c.Finish(mode, true), nil
}

func (f *fixture) mustCheck(mode string) *Result {
	f.t.Helper()
	r, err := f.check(mode, false)
	if err != nil {
		f.t.Fatal(err)
	}
	return r
}

// A failure row with no finding ID fails both modes; a selftest failure and a pass need none.
func TestCheckUnlinkedFailureRow(t *testing.T) {
	f := newFixture(t)
	f.report("replay/report.json", false,
		replayRow("r-pass", false, nil, "pipeline"),
		replayRow("r-selftest", true, nil, "selftest"),
		replayRow("r-fail", true, nil, "pipeline"))
	for _, mode := range []string{Development, Acceptance} {
		r := f.mustCheck(mode)
		if r.Passed() || r.UnlinkedRows != 1 || r.FailureRows != 2 || !strings.Contains(strings.Join(r.UnlinkedExamples, ""), "r-fail") {
			t.Errorf("%s: passed=%v %+v", mode, r.Passed(), r)
		}
	}
}

// A draft passes the development mode and fails the acceptance mode; a terminal record passes both.
func TestCheckDraftFailsAcceptance(t *testing.T) {
	f := newFixture(t)
	f.record(recordIn(t, "F-0001", "draft"), false)
	f.record(recordIn(t, "F-0002", "filed"), false)
	f.report("a.json", false, replayRow("r1", true, str("F-0001"), "pipeline"), replayRow("r2", true, str("F-0002"), "pipeline"))
	if r := f.mustCheck(Development); !r.Passed() || r.LinkedRows != 2 {
		t.Errorf("development: %+v", r)
	}
	r := f.mustCheck(Acceptance)
	if r.Passed() || len(r.NonTerminal) != 1 || r.NonTerminal[0] != "F-0001 draft" {
		t.Errorf("acceptance with a draft: %+v", r)
	}
	f.record(recordIn(t, "F-0001", "duplicate-of"), false)
	if r := f.mustCheck(Acceptance); !r.Passed() {
		t.Errorf("acceptance, every record terminal: %+v", r)
	}
	var out strings.Builder
	f.mustCheck(Development).Print(&out)
	if !strings.HasPrefix(out.String(), DevelopmentBanner+"\n") {
		t.Errorf("development output lacks the banner:\n%s", out.String())
	}
}

// Dangling IDs, orphaned, invalid and misplaced records fail; a not-a-defect record may be unreferenced.
func TestCheckRecordProblems(t *testing.T) {
	f := newFixture(t)
	f.record(recordIn(t, "F-0001", "candidate"), false)
	f.record(recordIn(t, "F-0002", "candidate"), false)    // orphan
	f.record(recordIn(t, "F-0003", "not-a-defect"), false) // unreferenced, allowed
	bad := recordIn(t, "F-0004", "draft")
	bad.Reproduction = nil
	f.record(bad, false)
	emb := recordIn(t, "F-0005", "candidate")
	emb.Visibility, emb.SecurityRelevant = "embargoed", true
	emb.Embargo = &Embargo{Trigger: "severity-undetermined", Policy: "none in repository", Channel: "bug bounty"}
	f.record(emb, false) // embargoed in the public tree
	f.report("a.json", false, replayRow("r1", true, str("F-0001"), "pipeline"), replayRow("r2", true, str("F-0099"), "pipeline"),
		replayRow("r3", true, str("F-0004"), "pipeline"), replayRow("r4", true, str("F-0005"), "pipeline"))
	r := f.mustCheck(Development)
	if r.Passed() || r.DanglingRows != 1 || len(r.Orphans) != 1 || !strings.HasPrefix(r.Orphans[0], "F-0002") {
		t.Errorf("%+v", r)
	}
	inv := strings.Join(r.Invalid, "\n")
	if !strings.Contains(inv, "F-0004") || !strings.Contains(inv, "reproduction") || !strings.Contains(inv, "F-0005") || !strings.Contains(inv, "overlay") {
		t.Errorf("invalid records: %s", inv)
	}
}

// A record whose rows can come only from runs with the private overlay is not an orphan of a public check.
func TestCheckPrivateOnlyRecord(t *testing.T) {
	f := newFixture(t)
	rec := recordIn(t, "F-0002", "duplicate-of")
	rec.Evidence = &Evidence{ReportRows: []string{"conform:e:-:private@1.0.0:L4"}}
	f.record(rec, false)
	f.report("a.json", false, replayRow("r1", false, nil, "pipeline"))
	if r := f.mustCheck(Acceptance); r.Passed() || len(r.Orphans) != 1 {
		t.Errorf("without a private-row test: %+v", r)
	}
	// A development check only notes an orphan: its run may simply not have been checked.
	if r := f.mustCheck(Development); !r.Passed() || len(r.Orphans) != 1 {
		t.Errorf("development mode fails on an orphan: %+v", r)
	}
	f.privateRow = func(id string) bool { return strings.Contains(id, ":private@1.0.0:") }
	r := f.mustCheck(Acceptance)
	if len(r.Orphans) != 0 || len(r.PrivateOnly) != 1 {
		t.Errorf("with the private-row test: %+v", r)
	}
	rec.Evidence.ReportRows = append(rec.Evidence.ReportRows, "conform:e:-:public@1.0.0:L4")
	f.record(rec, false)
	if r := f.mustCheck(Acceptance); r.Passed() || len(r.Orphans) != 1 {
		t.Errorf("a record with a public row stays an orphan: %+v", r)
	}
}

// A record observed by source reading only, with no report rows, on a target no driver column runs is exempt from
// the orphan rule and listed apart; without the explicit observed value, or on a driven target, it stays an orphan.
func TestCheckSourceReadingOnlyRecord(t *testing.T) {
	f := newFixture(t)
	rec := recordIn(t, "F-0002", "duplicate-of")
	rec.Target.Ecosystem, rec.Target.Package = "nuget", "undriven-sdk"
	rec.Evidence = &Evidence{PreFix: "read from the source at a pinned commit"}
	f.record(rec, false)
	f.report("a.json", false, replayRow("r1", false, nil, "pipeline"))
	noDriver := func(eco, pkg string) bool { return pkg != "driven-sdk" }
	check := func() *Result {
		t.Helper()
		s, err := Load(f.schema, f.public, "")
		if err != nil {
			t.Fatal(err)
		}
		c := NewChecker(s)
		c.NoDriver = noDriver
		if err := c.AddReport(filepath.Join(f.reports, "a.json")); err != nil {
			t.Fatal(err)
		}
		return c.Finish(Acceptance, true)
	}
	if r := check(); r.Passed() || len(r.Orphans) != 1 || len(r.SourceReadingOnly) != 0 {
		t.Errorf("not marked source-reading: %+v", r)
	}
	rec.Evidence.Observed = ObservedSourceReading
	f.record(rec, false)
	r := check()
	if !r.Passed() || len(r.Orphans) != 0 || len(r.SourceReadingOnly) != 1 {
		t.Errorf("source-reading on an undriven target: %+v", r)
	}
	var out strings.Builder
	r.Print(&out)
	if !strings.Contains(out.String(), "exempt from the orphan check): F-0002") {
		t.Errorf("the exemption is not listed:\n%s", out.String())
	}
	rec.Target.Package = "driven-sdk"
	f.record(rec, false)
	if r := check(); r.Passed() || len(r.Orphans) != 1 {
		t.Errorf("source-reading on a driven target: %+v", r)
	}
	rec.Target.Package = "undriven-sdk"
	rec.Evidence.ReportRows = []string{"conform:e:-:x@1.0.0:L4"}
	f.record(rec, false)
	if r := check(); r.Passed() || len(r.Orphans) != 1 {
		t.Errorf("source-reading with report rows: %+v", r)
	}
}

// A record whose evidence.observed is private-run and that lists no report rows is exempt from the orphan rule and
// listed apart; with report rows, or without the value, it stays an orphan.
func TestCheckPrivateRunRecord(t *testing.T) {
	f := newFixture(t)
	rec := recordIn(t, "F-0002", "duplicate-of")
	rec.Evidence = &Evidence{PreFix: "executed in the private acceptance run"}
	f.record(rec, false)
	f.report("a.json", false, replayRow("r1", false, nil, "pipeline"))
	check := func() *Result {
		t.Helper()
		s, err := Load(f.schema, f.public, "")
		if err != nil {
			t.Fatal(err)
		}
		c := NewChecker(s)
		if err := c.AddReport(filepath.Join(f.reports, "a.json")); err != nil {
			t.Fatal(err)
		}
		return c.Finish(Acceptance, true)
	}
	if r := check(); r.Passed() || len(r.Orphans) != 1 || len(r.PrivateRunOnly) != 0 {
		t.Errorf("not marked private-run: %+v", r)
	}
	rec.Evidence.Observed = ObservedPrivateRun
	f.record(rec, false)
	r := check()
	if !r.Passed() || len(r.Orphans) != 0 || len(r.PrivateRunOnly) != 1 {
		t.Errorf("private-run: %+v", r)
	}
	var out strings.Builder
	r.Print(&out)
	if !strings.Contains(out.String(), "rows only in the private acceptance run") || !strings.Contains(out.String(), "orphan check): F-0002") {
		t.Errorf("the exemption is not listed:\n%s", out.String())
	}
	rec.Evidence.ReportRows = []string{"conform:e:-:x@1.0.0:L4"}
	f.record(rec, false)
	if r := check(); r.Passed() || len(r.Orphans) != 1 {
		t.Errorf("private-run with report rows: %+v", r)
	}
}

// A report made with the overlay is refused without one; with the overlay its rows resolve to overlay records.
func TestCheckOverlay(t *testing.T) {
	f := newFixture(t)
	emb := recordIn(t, "F-5907", "candidate")
	emb.Visibility, emb.SecurityRelevant = "embargoed", true
	emb.Embargo = &Embargo{Trigger: "severity-undetermined", Policy: "none in repository", Channel: "bug bounty"}
	f.record(emb, true)
	f.report("private.json", true, replayRow("r1", true, str("F-5907"), "pipeline"))
	if _, err := f.check(Development, false); err == nil || !strings.Contains(err.Error(), "overlay") {
		t.Errorf("overlay report without --overlay: %v", err)
	}
	r, err := f.check(Development, true)
	if err != nil || !r.Passed() {
		t.Errorf("with the overlay: %v %+v", err, r)
	}
}

// FindReports picks xcc.report/v1 files at any depth and skips other JSON.
func TestFindReports(t *testing.T) {
	f := newFixture(t)
	f.report("a/b/report.json", false, replayRow("r1", false, nil, "pipeline"))
	os.WriteFile(filepath.Join(f.reports, "a", "matrix.json"), []byte(`{"cells":[{"schema":"x"}],"schema":"xcc.matrix/v1"}`), 0o644)
	os.WriteFile(filepath.Join(f.reports, "notes.txt"), []byte("x"), 0o644)
	got, err := FindReports(f.reports)
	if err != nil || len(got) != 1 || !strings.HasSuffix(got[0], filepath.Join("a", "b", "report.json")) {
		t.Errorf("%v %v", got, err)
	}
	ex, err := FindReports(reportsExDir)
	if err != nil || len(ex) == 0 {
		t.Errorf("schema example reports: %v %v", ex, err)
	}
	for _, p := range ex {
		if _, _, err := report.ReadFile(p, func(*report.Row) error { return nil }); err != nil && strings.Contains(p, "valid-") && !strings.Contains(p, "invalid") {
			t.Errorf("%s: %v", p, err)
		}
	}
}

// TestOverlayIDRange: an empty overlay starts at F-5001, a public-range record found in the overlay is a
// problem (it would have consumed a public ID), and the public sequence stays gap-free.
func TestOverlayIDRange(t *testing.T) {
	f := newFixture(t)
	f.record(recordIn(t, "F-0001", "candidate"), false)
	f.record(recordIn(t, "F-0002", "candidate"), true)
	s, err := Load(f.schema, f.public, f.overlay)
	if err != nil {
		t.Fatal(err)
	}
	if id := s.NextID(false); id != "F-0003" {
		t.Errorf("next public ID %s, want F-0003", id)
	}
	if id := s.NextID(true); id != "F-5001" {
		t.Errorf("next overlay ID %s, want F-5001", id)
	}
	found := false
	for _, p := range s.Problems {
		found = found || strings.Contains(p, "F-0002 (overlay)") && strings.Contains(p, "never consumes a public ID")
	}
	if !found {
		t.Errorf("public-range overlay record not reported: %v", s.Problems)
	}
	if !OverlayRange("F-5001") || OverlayRange("F-5000") || OverlayRange("F-0001") || IDNumber("P-0001") != 0 {
		t.Error("OverlayRange or IDNumber")
	}
}

func TestNextIDAndWrite(t *testing.T) {
	f := newFixture(t)
	f.record(recordIn(t, "F-0003", "candidate"), false)
	os.MkdirAll(filepath.Join(f.overlay, "F-5911"), 0o755) // an overlay ID in use, even without a readable record
	s, err := Load(f.schema, f.public, f.overlay)
	if err != nil {
		t.Fatal(err)
	}
	// The two ranges are numbered independently: overlay records never consume a public ID.
	if id := s.NextID(false); id != "F-0004" {
		t.Errorf("next public ID %s", id)
	}
	if id := s.NextID(true); id != "F-5912" {
		t.Errorf("next overlay ID %s", id)
	}
	emb := recordIn(t, "F-5912", "candidate")
	emb.Visibility, emb.SecurityRelevant = "embargoed", true
	emb.Embargo = &Embargo{Trigger: "severity-undetermined", Policy: "p", Channel: "c"}
	if _, err := s.Write(emb, false); err == nil {
		t.Error("an embargoed record was written to the public tree")
	}
	if _, err := s.Write(emb, true); err != nil {
		t.Error(err)
	}
	broken := recordIn(t, "F-0004", "draft")
	broken.Reproduction = nil
	if _, err := s.Write(broken, false); err == nil {
		t.Error("an invalid record was written")
	}
}

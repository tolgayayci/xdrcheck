package siblings

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/tolgayayci/xdrcheck/go/internal/conform/verdict"
	"github.com/tolgayayci/xdrcheck/go/internal/findings"
)

const today = "2026-11-12"

func run(t *testing.T, tr Tracker, store *findings.Store, sig *Signature, m *verdict.Matrix, manual []*Manual, o Options) *Plan {
	t.Helper()
	o.Today, o.Templates = today, templates(t)
	p, err := Run(context.Background(), tr, store, sig, m, manual, o)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func resultOf(t *testing.T, p *Plan, sdk string) *Result {
	t.Helper()
	for _, r := range p.Results {
		if r.Family.SDK == sdk {
			return r
		}
	}
	t.Fatalf("no result for %s", sdk)
	return nil
}

func draftOf(p *Plan, sdk string) *Draft {
	for _, d := range p.Drafts {
		if d.SDK == sdk {
			return d
		}
	}
	return nil
}

// privateSibling is an unreported overlay record in the same defect group, for a project no public record
// names. No public draft or record may mention it.
func privateSibling() *findings.Record {
	return &findings.Record{Schema: findings.SchemaID, ID: "F-5001", Title: "Pool asset order compared as text in a private sibling",
		DefectGroup: "DG-pool-asset-order", Component: "sdk", Class: "rejects_valid", Severity: "medium", Visibility: "public", State: "candidate",
		Target:  findings.Target{Project: "example-private/hidden-sdk", VersionsAffected: "1.0.0", VersionsTested: []string{"1.0.0"}},
		Entries: []findings.Entry{{ID: "cap-0038/api-liquidity-pool-issuer-ordering.network-order", Scope: "L4", Expected: "conform", Observed: "refused"}},
		History: []findings.HistoryItem{{Date: today, State: "candidate"}}}
}

// The done-condition: for the issuer-ordering finding, Java gets a release request (its fix is merged after
// its latest release), .NET gets an evidence comment on its open issue (from manual evidence: the kit has no
// .NET driver), Go and Python are fixed in their latest columns and get nothing, Rust has no surface for these
// cells; nothing is filed and every draft carries the command a person would run.
func TestIssuerOrderingSiblings(t *testing.T) {
	store := newStore(t, issuerRecords, []*findings.Record{privateSibling()}, true)
	m := fixtureMatrix(t)
	sig, err := FromFinding(m, store.Records["F-0016"])
	if err != nil {
		t.Fatal(err)
	}
	tr := upstreamToday()
	p := run(t, tr, store, sig, m, []*Manual{dotnetEvidence(t)}, Options{})

	if p.Group != "DG-pool-asset-order" {
		t.Errorf("group %s: the original has none, its existing siblings share DG-pool-asset-order", p.Group)
	}
	want := map[string]string{"go": Fixed, "python": Fixed, "java": Affected, "rust": NotExercised, "dotnet": Affected}
	for sdk, st := range want {
		if r := resultOf(t, p, sdk); r.Status != st {
			t.Errorf("%s: status %s, want %s", sdk, r.Status, st)
		}
	}
	for sdk, rec := range map[string]string{"go": "F-0023", "python": "F-0027", "java": "F-0028"} {
		if r := resultOf(t, p, sdk); r.Record == nil || r.Record.Record.ID != rec {
			t.Errorf("%s: existing record %v, want %s", sdk, r.Record, rec)
		}
	}
	for _, x := range p.Results {
		if x.Family.SDK == "js" {
			t.Errorf("the original's own SDK is listed as a sibling")
		}
	}
	// The Java matches are the cells its record lists; the map-order cells conform on Java.
	if n := len(resultOf(t, p, "java").Matches); n != len(repoRecord(t, "F-0028").Entries) {
		t.Errorf("java: %d matching cells, want one per F-0028 entry", n)
	}
	// Go and Python are not looked up: they are not affected today.
	for _, c := range tr.calls {
		if strings.Contains(c, "go-stellar-sdk") || strings.Contains(c, "py-stellar-base") {
			t.Errorf("tracker asked about an SDK that is not affected: %s", c)
		}
	}

	if len(p.Drafts) != 2 {
		t.Fatalf("%d drafts, want Java and .NET", len(p.Drafts))
	}
	java, dotnet := draftOf(p, "java"), draftOf(p, "dotnet")
	if java == nil || dotnet == nil {
		t.Fatalf("drafts: %+v", p.Drafts)
	}

	// Java: the existing public record F-0028, a release request citing the merged fix.
	if java.New || java.Overlay || java.Kind != KindRelease || java.Record.ID != "F-0028" {
		t.Errorf("java draft: %+v", java)
	}
	wantCmd := `gh issue create --repo lightsail-network/java-stellar-sdk --title "Release request: ` + repoRecord(t, "F-0028").Title + `" --body-file findings/F-0028/issue-java-stellar-sdk.md`
	if java.Command != wantCmd {
		t.Errorf("java command\n got %s\nwant %s", java.Command, wantCmd)
	}
	for _, s := range []string{"https://github.com/lightsail-network/java-stellar-sdk/pull/832", "2026-11-05", "6.0.0 (2026-10-28)",
		"cap-0038/api-liquidity-pool-issuer-ordering.network-order", "Executed on java@6.0.0", "https://github.com/stellar/js-stellar-sdk/pull/1766"} {
		if !strings.Contains(java.Body, s) {
			t.Errorf("java body lacks %q:\n%s", s, java.Body)
		}
	}

	// .NET: a new public candidate (its issue is public) with an evidence comment on that issue.
	if !dotnet.New || dotnet.Overlay || dotnet.Kind != KindComment || findings.OverlayRange(dotnet.Record.ID) {
		t.Errorf("dotnet draft: new %v overlay %v kind %s id %s", dotnet.New, dotnet.Overlay, dotnet.Kind, dotnet.Record.ID)
	}
	wantCmd = "gh issue comment 257 --repo Beans-BV/dotnet-stellar-sdk --body-file findings/" + dotnet.Record.ID + "/issue-dotnet-stellar-sdk.md"
	if dotnet.Command != wantCmd {
		t.Errorf("dotnet command\n got %s\nwant %s", dotnet.Command, wantCmd)
	}
	for _, s := range []string{"#257", "Not executed", "no conformance driver", "6eea5fcadff5bd64bd418f1995a1c6c1d11055d3", "stellar-dotnet-sdk@17.0.0",
		"https://github.com/stellar/go-stellar-sdk/pull/5974", "fixed in v0.7.2"} {
		if !strings.Contains(dotnet.Body, s) {
			t.Errorf("dotnet body lacks %q:\n%s", s, dotnet.Body)
		}
	}
	rec := dotnet.Record
	if rec.State != "candidate" || rec.Target.Ecosystem != "nuget" || rec.DefectGroup != "DG-pool-asset-order" || rec.Class != "rejects_valid" ||
		rec.UpstreamSearch == nil || rec.UpstreamSearch.Result != "existing-open" || rec.Upstream == nil || rec.Upstream.State != "open" ||
		len(rec.Evidence.ReportRows) != 0 || rec.Title != repoRecord(t, "F-0028").Title {
		t.Errorf("dotnet record: %+v", rec)
	}
	if strings.Join(rec.Siblings, ",") != "F-0016,F-0023,F-0027,F-0028" {
		t.Errorf("dotnet siblings %v", rec.Siblings)
	}
	possible := false
	for _, n := range dotnet.Notes {
		possible = possible || strings.Contains(n, "/pull/272")
	}
	if !possible {
		t.Errorf("the open .NET pull request found by search is not shown to the reviewer: %v", dotnet.Notes)
	}

	// Public drafts and records never name the overlay record or its project.
	for _, d := range p.Drafts {
		b, _ := findings.Encode(d.Record)
		for _, leak := range []string{"F-5001", "hidden-sdk"} {
			if strings.Contains(d.Body, leak) || strings.Contains(string(b), leak) {
				t.Errorf("%s draft names the overlay record (%s)", d.SDK, leak)
			}
		}
	}

	// Writing: both records validate and land in the public tree next to their bodies; the overlay is untouched.
	written, err := Apply(store, p)
	if err != nil {
		t.Fatal(err)
	}
	if len(written) != 4 {
		t.Errorf("written %v", written)
	}
	for _, d := range p.Drafts {
		body, err := os.ReadFile(filepath.Join(store.PublicDir, d.Record.ID, d.File))
		if err != nil || string(body) != d.Body {
			t.Errorf("%s body not written: %v", d.SDK, err)
		}
	}
	ents, _ := os.ReadDir(store.OverlayDir)
	if len(ents) != 1 {
		t.Errorf("overlay now holds %d entries, want only the fixture record", len(ents))
	}
	reloaded, err := findings.Load(loadSchema(t), store.PublicDir, store.OverlayDir)
	if err != nil || len(reloaded.Problems) > 0 {
		t.Fatalf("records after writing: %v %v", err, reloaded.Problems)
	}
	if d := reloaded.Records["F-0028"].Record.IssueDraft; d == nil || d.Kind != KindRelease || d.DryRunCommand != java.Command {
		t.Errorf("F-0028 issue_draft %+v", d)
	}
}

// Starting from the known divergence instead of the record finds the same siblings.
func TestFromDivergence(t *testing.T) {
	store := newStore(t, issuerRecords, nil, true)
	m := fixtureMatrix(t)
	sig, err := FromDivergence(m, "https://github.com/stellar/js-stellar-sdk/pull/1766")
	if err != nil {
		t.Fatal(err)
	}
	if !sig.SourceSDKs["js"] || len(sig.SourceSDKs) != 1 || sig.Project != "stellar/js-stellar-sdk" {
		t.Fatalf("signature %+v", sig)
	}
	p := run(t, upstreamToday(), store, sig, m, []*Manual{dotnetEvidence(t)}, Options{})
	if p.Group != "DG-pool-asset-order" || len(p.Drafts) != 2 || draftOf(p, "java").Kind != KindRelease || draftOf(p, "dotnet").Kind != KindComment {
		t.Errorf("group %s drafts %+v", p.Group, p.Drafts)
	}
}

// When the latest Go release still shows the defect after its fix shipped, the closed fix does not stand for
// it: the new issue is an unreported defect and is drafted only in the overlay, with the open item search
// found shown as a possible duplicate. Once a person confirms that item, the draft becomes a public evidence
// comment on it.
func TestRegressionDraftsPrivatelyUntilConfirmed(t *testing.T) {
	m := fixtureMatrix(t)
	for i := range m.Cells {
		c := &m.Cells[i]
		if c.Column == "go@v0.8.0" && c.Entry == "cap-0038/api-liquidity-pool-issuer-ordering.network-order" {
			c.Outcome, c.Verdict, c.Check = "reject", "reject_valid", "undeclared"
		}
	}
	tr := upstreamToday()
	open := Item{Repo: "stellar/go-stellar-sdk", Number: 9001, URL: "https://github.com/stellar/go-stellar-sdk/issues/9001", State: "open", Title: "liquidity pool asset order again"}
	tr.items[open.URL] = open
	tr.search["stellar/go-stellar-sdk"] = []Item{open}

	// Without Go's record, so that the decision rests on the tracker alone.
	public := []string{"F-0016", "F-0027", "F-0028"}
	store := newStore(t, public, nil, true)
	sig, _ := FromFinding(m, store.Records["F-0016"])
	p := run(t, tr, store, sig, m, nil, Options{})
	g := draftOf(p, "go")
	if g == nil || !g.New || !g.Overlay || g.Kind != KindNew || !findings.OverlayRange(g.Record.ID) {
		t.Fatalf("go draft %+v", g)
	}
	if d := p.Decisions["go"]; d.SearchResult != "existing-closed" || len(d.Possible) != 1 || d.Possible[0].Number != 9001 {
		t.Errorf("go decision %+v", d)
	}
	if !strings.HasPrefix(g.Command, "gh issue create --repo stellar/go-stellar-sdk") {
		t.Errorf("command %s", g.Command)
	}

	// The same without an overlay directory: nothing is written at all.
	noOverlay := newStore(t, public, nil, false)
	p = run(t, upstreamToday2(tr), noOverlay, sig, m, nil, Options{})
	if _, err := Apply(noOverlay, p); err == nil || !strings.Contains(err.Error(), "overlay") {
		t.Errorf("apply without overlay: %v", err)
	}
	ents, _ := os.ReadDir(noOverlay.PublicDir)
	if len(ents) != len(public) {
		t.Errorf("public tree changed: %d entries", len(ents))
	}

	// Confirmed: a public evidence comment.
	store = newStore(t, public, nil, true)
	p = run(t, tr, store, sig, m, nil, Options{Confirm: []string{open.URL}})
	g = draftOf(p, "go")
	if g == nil || g.Overlay || g.Kind != KindComment || g.Command != "gh issue comment 9001 --repo stellar/go-stellar-sdk --body-file findings/"+g.Record.ID+"/issue-go-stellar-sdk.md" {
		t.Fatalf("go draft after confirmation %+v", g)
	}
}

// upstreamToday2 is a fresh copy of a tracker's state.
func upstreamToday2(f *fakeTracker) *fakeTracker {
	return &fakeTracker{items: f.items, search: f.search, releases: f.releases}
}

// A fix released in a version newer than the one checked is not a release request: the column is out of date.
func TestReleasedNewerThanChecked(t *testing.T) {
	store := newStore(t, issuerRecords, nil, true)
	m := fixtureMatrix(t)
	sig, _ := FromFinding(m, store.Records["F-0016"])
	tr := upstreamToday()
	tr.releases["lightsail-network/java-stellar-sdk"] = &Release{Tag: "6.0.1", PublishedAt: "2026-11-10T00:00:00Z"}
	p := run(t, tr, store, sig, m, nil, Options{})
	if draftOf(p, "java") != nil || !strings.Contains(p.Decisions["java"].Why, "add a column") {
		t.Errorf("java: %+v", p.Decisions["java"])
	}
	if r := resultOf(t, p, "dotnet"); r.Status != NoColumn || draftOf(p, "dotnet") != nil {
		t.Errorf("dotnet without manual evidence: %s", r.Status)
	}
}

// Offline, the recorded upstream states decide: Java's record says its fix is merged and unreleased, and the
// .NET evidence names its issue. Nothing is searched and the new record carries no search.
func TestOffline(t *testing.T) {
	store := newStore(t, issuerRecords, nil, true)
	m := fixtureMatrix(t)
	sig, _ := FromFinding(m, store.Records["F-0016"])
	ev := dotnetEvidence(t)
	tr := RecordedFrom(store, m, nil)
	for _, u := range ev.Upstream {
		tr.Add(u, "open")
	}
	p := run(t, tr, store, sig, m, []*Manual{ev}, Options{Offline: true})
	java, dotnet := draftOf(p, "java"), draftOf(p, "dotnet")
	if java == nil || java.Kind != KindRelease || !strings.Contains(p.Decisions["java"].Why, "no release information") {
		t.Errorf("java offline: %+v %+v", java, p.Decisions["java"])
	}
	if dotnet == nil || dotnet.Kind != KindComment || dotnet.Record.UpstreamSearch != nil || p.Decisions["dotnet"].Searched {
		t.Errorf("dotnet offline: %+v", dotnet)
	}
	if _, err := Apply(store, p); err != nil {
		t.Fatal(err)
	}
}

// A finding that lives in the private overlay keeps every sibling draft there, even where a public item exists.
func TestPrivateOriginalStaysPrivate(t *testing.T) {
	orig := repoRecord(t, "F-0016")
	orig.ID = "F-5902"
	store := newStore(t, []string{"F-0023", "F-0027"}, []*findings.Record{orig}, true)
	m := fixtureMatrix(t)
	sig, err := FromFinding(m, store.Records["F-5902"])
	if err != nil {
		t.Fatal(err)
	}
	p := run(t, upstreamToday(), store, sig, m, []*Manual{dotnetEvidence(t)}, Options{})
	if len(p.Drafts) != 2 {
		t.Fatalf("drafts %+v", p.Drafts)
	}
	for _, d := range p.Drafts {
		if !d.Overlay || !d.New || !findings.OverlayRange(d.Record.ID) {
			t.Errorf("%s: overlay %v new %v id %s", d.SDK, d.Overlay, d.New, d.Record.ID)
		}
	}
	if _, err := Apply(store, p); err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(store.PublicDir)
	if len(ents) != 2 {
		t.Errorf("public tree changed: %d entries", len(ents))
	}
}

func TestManualCheck(t *testing.T) {
	good := dotnetEvidence(t)
	if good.Column() != "dotnet@17.0.0" || good.Executed() {
		t.Errorf("%s %v", good.Column(), good.Executed())
	}
	cases := map[string]func(m *Manual){
		"schema":   func(m *Manual) { m.Schema = "x" },
		"method":   func(m *Manual) { m.Method = "guess" },
		"verdict":  func(m *Manual) { m.Cells[0].Verdict = "bad" },
		"level":    func(m *Manual) { m.Cells[0].Level = "L9" },
		"observed": func(m *Manual) { m.Cells[0].Observed = " " },
		"twice":    func(m *Manual) { m.Cells = append(m.Cells, m.Cells[0]) },
		"upstream": func(m *Manual) { m.Upstream = []string{"https://example.com/1"} },
		"basis":    func(m *Manual) { m.Basis = "" },
		"project":  func(m *Manual) { m.Project = "no-slash" },
	}
	for name, mut := range cases {
		m := *good
		m.Cells = append([]ManualCell(nil), good.Cells...)
		mut(&m)
		if err := m.Check(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Manual evidence cannot stand in for an SDK the matrix has columns for, nor for the original's SDK.
	m := fixtureMatrix(t)
	store := newStore(t, issuerRecords, nil, false)
	sig, _ := FromFinding(m, store.Records["F-0016"])
	for _, sdk := range []string{"java", "js"} {
		fake := *good
		fake.SDK, fake.Project = sdk, "x/y"
		if _, err := Analyse(sig, m, []*Manual{&fake}, store); err == nil {
			t.Errorf("manual evidence for %s accepted", sdk)
		}
	}
}

func TestParseRowIDAndTerms(t *testing.T) {
	k, col, ok := ParseRowID("conform:cap-0038/x.y:-:rust@30.0.0:limits-none:L2")
	if !ok || col != "rust@30.0.0:limits-none" || k.Variant != "" || k.Level != "L2" || k.Entry != "cap-0038/x.y" {
		t.Errorf("%v %s %v", k, col, ok)
	}
	if _, _, ok := ParseRowID("replay:x"); ok {
		t.Error("replay row parsed")
	}
	if got := SearchTerms("Liquidity pool asset order compared as strkey text: valid pairs refused"); got != "liquidity pool asset order" {
		t.Errorf("terms %q", got)
	}
	if repo, n, pull, ok := ParseItemURL("https://github.com/Beans-BV/dotnet-stellar-sdk/issues/257"); !ok || repo != "Beans-BV/dotnet-stellar-sdk" || n != 257 || pull {
		t.Errorf("%s %d %v %v", repo, n, pull, ok)
	}
}

// The package never starts a process: no file imports os/exec or syscall. Tracker access is net/http through
// the read-only transport, tested in tracker_test.go.
func TestNoExec(t *testing.T) {
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
				if p == "os/exec" || p == "syscall" {
					t.Errorf("%s imports %s", f, p)
				}
			}
			return true
		})
	}
}

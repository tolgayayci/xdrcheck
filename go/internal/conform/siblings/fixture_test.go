package siblings

// Fixtures: the repository's public issuer-ordering records, a conformance matrix built from their report rows,
// and a fake tracker. Nothing here touches the network.

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tolgayayci/xdrcheck/go/internal/conform/verdict"
	"github.com/tolgayayci/xdrcheck/go/internal/findings"
	"github.com/tolgayayci/xdrcheck/go/internal/report"
)

var update = flag.Bool("update", false, "rewrite testdata/matrix.json from the fixture builder")

// repoRoot is the repository root, four levels up from this package.
var repoRoot = func() string { a, _ := filepath.Abs("../../../.."); return a }()

// issuerRecords are the public records of the issuer-ordering defect: the JS original and its Go, Python and
// Java siblings.
var issuerRecords = []string{"F-0016", "F-0023", "F-0027", "F-0028"}

func loadSchema(t *testing.T) *findings.Schema {
	t.Helper()
	s, err := findings.LoadSchema(filepath.Join(repoRoot, "corpus", "schema", "finding-record.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func repoRecord(t *testing.T, id string) *findings.Record {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot, "findings", id, findings.RecordFile))
	if err != nil {
		t.Fatal(err)
	}
	var r findings.Record
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	return &r
}

// newStore copies the given public records into a temporary public tree, puts overlay records into a temporary
// overlay, and loads both. overlay "" means no overlay directory.
func newStore(t *testing.T, public []string, overlayRecs []*findings.Record, withOverlay bool) *findings.Store {
	t.Helper()
	pub := filepath.Join(t.TempDir(), "findings")
	for _, id := range public {
		putRecord(t, pub, repoRecord(t, id))
	}
	ov := ""
	if withOverlay {
		ov = filepath.Join(t.TempDir(), "findings")
		os.MkdirAll(ov, 0o755)
		for _, r := range overlayRecs {
			putRecord(t, ov, r)
		}
	}
	s, err := findings.Load(loadSchema(t), pub, ov)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Problems) > 0 {
		t.Fatalf("fixture records: %v", s.Problems)
	}
	return s
}

func putRecord(t *testing.T, dir string, r *findings.Record) {
	t.Helper()
	b, err := findings.Encode(r)
	if err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Join(dir, r.ID), 0o755)
	if err := os.WriteFile(filepath.Join(dir, r.ID, findings.RecordFile), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// Fixture columns: every SDK column of the public and Java sets at their pinned versions, and stellar-core.
var fixtureColumns = []verdict.MatrixColumn{
	{ID: "core@30.0.0", SDK: "core", Target: "stellar-core", Version: "30.0.0", Kind: "core", Role: "extra"},
	{ID: "go@v0.7.1", SDK: "go", Target: "github.com/stellar/go-stellar-sdk", Version: "v0.7.1", Kind: "sdk", Role: "historical"},
	{ID: "go@v0.7.2", SDK: "go", Target: "github.com/stellar/go-stellar-sdk", Version: "v0.7.2", Kind: "sdk", Role: "historical"},
	{ID: "go@v0.8.0", SDK: "go", Target: "github.com/stellar/go-stellar-sdk", Version: "v0.8.0", Kind: "sdk", Role: "required", Required: true},
	{ID: "java@6.0.0", SDK: "java", Target: "network.lightsail:stellar-sdk", Version: "6.0.0", Kind: "sdk", Role: "extra"},
	{ID: "js@16.3.0", SDK: "js", Target: "@stellar/stellar-sdk", Version: "16.3.0", Kind: "sdk", Role: "extra"},
	{ID: "js@16.3.1", SDK: "js", Target: "@stellar/stellar-sdk", Version: "16.3.1", Kind: "sdk", Role: "extra"},
	{ID: "js@16.4.1", SDK: "js", Target: "@stellar/stellar-sdk", Version: "16.4.1", Kind: "sdk", Role: "extra"},
	{ID: "js@17.2.0", SDK: "js", Target: "@stellar/stellar-sdk", Version: "17.2.0", Kind: "sdk", Role: "historical"},
	{ID: "js@17.2.1", SDK: "js", Target: "@stellar/stellar-sdk", Version: "17.2.1", Kind: "sdk", Role: "historical"},
	{ID: "js@17.4.0", SDK: "js", Target: "@stellar/stellar-sdk", Version: "17.4.0", Kind: "sdk", Role: "required", Required: true},
	{ID: "python@17.0.0", SDK: "python", Target: "stellar-sdk", Version: "17.0.0", Kind: "sdk", Role: "extra"},
	{ID: "python@17.0.1", SDK: "python", Target: "stellar-sdk", Version: "17.0.1", Kind: "sdk", Role: "extra"},
	{ID: "rust@30.0.0:limits-default", SDK: "rust", Target: "stellar-xdr", Version: "30.0.0", Profile: "limits-default", Kind: "sdk", Role: "required", Required: true},
	{ID: "rust@30.0.0:limits-none", SDK: "rust", Target: "stellar-xdr", Version: "30.0.0", Profile: "limits-none", Kind: "sdk", Role: "required", Required: true},
}

// fixtureVerdict is the verdict a failing report row of the issuer-ordering records stands for: the pair in
// XDR byte order is refused, the reversed or identical pair accepted, the map keys misordered.
func fixtureVerdict(k Key) string {
	switch {
	case strings.Contains(k.Entry, "scval-map-sort-order"):
		return "diverge"
	case strings.Contains(k.Entry, "reversed-order"), strings.Contains(k.Entry, "identical-assets"):
		return "accepts_invalid"
	}
	return "reject_valid"
}

// fixtureMatrix is the matrix the issuer-ordering records' report rows describe: each listed row fails with
// its verdict and cites its record's upstream item; every other SDK cell conforms, except that the Rust XDR
// library has no API (L4) or object (L1) surface for these entries and stellar-core is not an API column.
func fixtureMatrix(t *testing.T) *verdict.Matrix {
	t.Helper()
	m := &verdict.Matrix{Schema: verdict.MatrixSchema, Corpus: report.CorpusRef{Version: "fixture", ManifestSHA256: strings.Repeat("0", 64), Schema: "xcc.manifest.entry/v1", Tier: "curated"},
		Columns: fixtureColumns, Entries: []verdict.MatrixEntry{}, CrossSDK: []verdict.CrossSDK{}, NotExercised: []verdict.NotExercised{},
		Infrastructure: []string{}, Summary: map[string]int{}}
	type fail struct {
		verdict, ref, status, finding string
	}
	failing := map[string]fail{}
	var keys []Key
	seen := map[Key]bool{}
	for _, id := range issuerRecords {
		r := repoRecord(t, id)
		status := "fixed"
		if r.Upstream.State == "fix-merged-unreleased" {
			status = "fixed_unreleased"
		}
		for _, row := range r.Evidence.ReportRows {
			k, col, ok := ParseRowID(row)
			if !ok {
				t.Fatalf("%s: row %s", id, row)
			}
			failing[k.String()+" "+col] = fail{fixtureVerdict(k), r.Upstream.URL, status, id}
			if !seen[k] {
				seen[k] = true
				keys = append(keys, k)
			}
		}
	}
	for _, k := range keys {
		m.Entries = appendEntry(m.Entries, k.Entry)
		for _, c := range fixtureColumns {
			cell := verdict.Cell{Entry: k.Entry, Variant: k.Variant, Level: k.Level, Column: c.ID, Source: "driver", Reference: "protocol-rule",
				ExpectedVerdict: "conform", Outcome: "ok", Verdict: "conform", Check: "conform"}
			switch f, bad := failing[k.String()+" "+c.ID]; {
			case c.SDK == "core" || c.SDK == "rust" && k.Level != "L0" && k.Level != "L2":
				cell.Outcome, cell.Verdict, cell.Check, cell.ExpectedVerdict = "n_a", "n_a", "n_a", "n_a"
			case bad:
				cell.Verdict, cell.Check, cell.ExpectedVerdict, cell.Finding = f.verdict, "known", f.verdict, f.finding
				cell.KnownDivergence = &verdict.KnownRef{Reference: f.ref, Status: f.status, Versions: "fixture", Outcome: f.verdict}
				if f.verdict == "reject_valid" {
					cell.Outcome, cell.Reason = "reject", "ordering"
					cell.Evidence = json.RawMessage(`{"message":"Assets are not in lexicographic order"}`)
				}
			}
			m.Cells = append(m.Cells, cell)
			m.Summary[cell.Check]++
		}
	}
	return m
}

func appendEntry(list []verdict.MatrixEntry, id string) []verdict.MatrixEntry {
	for _, e := range list {
		if e.ID == id {
			return list
		}
	}
	kind := "api"
	if !strings.Contains(id, "/api-") {
		kind = "ledger"
	}
	return append(list, verdict.MatrixEntry{ID: id, Kind: kind, ProtocolIntroduced: 18, Reference: "protocol-rule", Expected: "exact-or-refuse"})
}

// The committed testdata/matrix.json (used by the command's tests) is the fixture builder's output.
func TestFixtureMatrixFile(t *testing.T) {
	m := fixtureMatrix(t)
	b, err := json.MarshalIndent(m, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	b = append(b, '\n')
	path := filepath.Join("testdata", "matrix.json")
	if *update {
		if err := os.WriteFile(path, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(b) {
		t.Fatalf("%s is stale; run go test ./internal/conform/siblings -run TestFixtureMatrixFile -update (%v)", path, err)
	}
	if _, err := verdict.ReadMatrix(path); err != nil {
		t.Fatal(err)
	}
}

// fakeTracker serves fixed upstream state and records every call.
type fakeTracker struct {
	items    map[string]Item // by URL
	search   map[string][]Item
	releases map[string]*Release
	calls    []string
}

func (f *fakeTracker) Search(_ context.Context, repo, terms string) ([]Item, error) {
	f.calls = append(f.calls, "search "+repo+" "+terms)
	return f.search[repo], nil
}

func (f *fakeTracker) Item(_ context.Context, repo string, n int) (*Item, error) {
	f.calls = append(f.calls, fmt.Sprintf("item %s#%d", repo, n))
	for _, it := range f.items {
		if it.Repo == repo && it.Number == n {
			it := it
			return &it, nil
		}
	}
	return nil, fmt.Errorf("%s#%d: not found", repo, n)
}

func (f *fakeTracker) LatestRelease(_ context.Context, repo string) (*Release, error) {
	f.calls = append(f.calls, "release "+repo)
	return f.releases[repo], nil
}

// upstreamToday is the upstream state of the issuer-ordering defect on 2026-11-12: JS, Go and Python fixed and
// released; Java fixed on its default branch after its latest release; .NET reported in an open issue with an
// open pull request.
func upstreamToday() *fakeTracker {
	f := &fakeTracker{items: map[string]Item{}, search: map[string][]Item{}, releases: map[string]*Release{}}
	add := func(it Item) Item { f.items[it.URL] = it; return it }
	add(Item{Repo: "stellar/js-stellar-sdk", Number: 1766, URL: "https://github.com/stellar/js-stellar-sdk/pull/1766", PullRequest: true, State: "closed", MergedAt: "2026-10-01T00:25:29Z", Title: "fix asset ordering"})
	add(Item{Repo: "stellar/go-stellar-sdk", Number: 5974, URL: "https://github.com/stellar/go-stellar-sdk/pull/5974", PullRequest: true, State: "closed", MergedAt: "2026-08-06T23:52:23Z", Title: "xdr: compare assets by their XDR encoding"})
	add(Item{Repo: "StellarCN/py-stellar-base", Number: 1246, URL: "https://github.com/StellarCN/py-stellar-base/issues/1246", State: "closed", Title: "asset order"})
	add(Item{Repo: "lightsail-network/java-stellar-sdk", Number: 832, URL: "https://github.com/lightsail-network/java-stellar-sdk/pull/832", PullRequest: true, State: "closed", MergedAt: "2026-11-05T09:00:00Z", Title: "fix: compare issuers by bytes"})
	issue := add(Item{Repo: "Beans-BV/dotnet-stellar-sdk", Number: 257, URL: "https://github.com/Beans-BV/dotnet-stellar-sdk/issues/257", State: "open", Title: "Liquidity pool parameters reject the asset order the network requires (issuers compared as strkey text)"})
	pr := Item{Repo: "Beans-BV/dotnet-stellar-sdk", Number: 272, URL: "https://github.com/Beans-BV/dotnet-stellar-sdk/pull/272", PullRequest: true, State: "open", Title: "fix: liquidity pool parameters ordering"}
	f.search["Beans-BV/dotnet-stellar-sdk"] = []Item{pr, issue, {Repo: "Beans-BV/dotnet-stellar-sdk", Number: 141, URL: "https://github.com/Beans-BV/dotnet-stellar-sdk/pull/141", PullRequest: true, State: "closed", Title: "chore: docs"}}
	f.releases["lightsail-network/java-stellar-sdk"] = &Release{Tag: "6.0.0", PublishedAt: "2026-10-28T12:00:00Z"}
	f.releases["stellar/go-stellar-sdk"] = &Release{Tag: "v0.8.0", PublishedAt: "2026-10-20T12:00:00Z"}
	return f
}

func dotnetEvidence(t *testing.T) *Manual {
	t.Helper()
	m, err := LoadManual(filepath.Join(repoRoot, "findings", "templates", "manual-evidence.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func templates(t *testing.T) Templates {
	t.Helper()
	tm, err := LoadTemplates(filepath.Join(repoRoot, "findings", "templates"))
	if err != nil {
		t.Fatal(err)
	}
	return tm
}

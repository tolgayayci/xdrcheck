package conform

import (
	"bytes"
	"context"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
	"github.com/tolgayayci/xdrcheck/go/internal/testcorpus"
)

// Spec entries are planned at the spec level only, on every column that does not narrow its levels; the json
// level is planned for every ledger and xdr variant, and only on columns that list it.
func TestPlanSpecAndJSON(t *testing.T) {
	c := fullCorpus(t)
	all, _ := CompileGlobs("")
	plain := &Column{ID: "a@1"}
	json := &Column{ID: "j@1", Levels: []string{"json"}}
	spec := &Column{ID: "s@1", Levels: []string{"spec"}}
	var specEntries, xdrVariants int
	for _, e := range c.Entries {
		switch e.Kind {
		case "spec":
			specEntries++
		case "ledger", "xdr":
			xdrVariants += len(e.Variants)
		}
	}
	count := func(cells []*Cell, col, level string) int {
		n := 0
		for _, x := range cells {
			if x.Column.ID == col && x.Level == level {
				n++
			}
		}
		return n
	}
	cells := Plan(c, []*Column{plain, json, spec}, all, nil)
	if got := count(cells, "a@1", "spec"); got != specEntries || specEntries < 10 {
		t.Errorf("plain column: %d spec cells for %d spec entries", got, specEntries)
	}
	if got := count(cells, "a@1", "json"); got != 0 {
		t.Errorf("plain column has %d json cells", got)
	}
	if got := count(cells, "j@1", "json"); got != xdrVariants {
		t.Errorf("json column: %d json cells for %d ledger and xdr variants", got, xdrVariants)
	}
	for _, x := range cells {
		if x.Column.ID == "j@1" && x.Level != "json" || x.Column.ID == "s@1" && x.Level != "spec" {
			t.Fatalf("%s planned on a narrowed column", x.RowID())
		}
	}
	// --levels json keeps json cells only.
	if n := len(Plan(c, []*Column{plain, json}, all, map[string]bool{"json": true})); n != xdrVariants {
		t.Errorf("--levels json: %d cells, want %d", n, xdrVariants)
	}
	// A Wasm spec request carries the sections the corpus's reader located.
	e := c.Entry("contract-spec/two-spec-sections")
	req, err := Request(c, &Cell{Entry: e, Variant: e.Variants[0], VariantKey: "none", Level: "spec", Column: spec})
	if err != nil {
		t.Fatal(err)
	}
	if req.Input.Kind != "spec" || req.Input.Container != "wasm" || len(req.Input.Sections) != 2 {
		t.Fatalf("spec request %+v", req.Input)
	}
	b, _ := os.ReadFile(req.Input.Path)
	for _, s := range req.Input.Sections {
		if s.Offset+s.Length > len(b) {
			t.Errorf("section %+v outside the %d-byte module", s, len(b))
		}
	}
}

// The stub answers the spec level with a canned entry list; the cell is validated and judged like any other.
func TestSpecCellsThroughTheStub(t *testing.T) {
	entries := []map[string]any{{"kind": "function", "name": "first", "args": []map[string]any{{"name": "a", "type": "u32"}}, "outputs": []string{"u32"}}}
	col := stubColumn(t, "stub@0.1.0", rules(
		map[string]any{"entry": "contract-spec/two-spec-sections", "level": "spec", "do": "ok", "actual": map[string]any{"spec": map[string]any{"entries": entries}}},
		map[string]any{"entry": "contract-spec/*", "level": "spec", "do": "reject", "code": "spec_sections"},
	))
	g, _ := CompileGlobs("contract-spec/two-spec-sections,contract-spec/truncated-spec-section")
	var log bytes.Buffer
	res, err := Run(context.Background(), Options{Sets: &Sets{Root: repoRoot}, Columns: []*Column{col}, Corpus: fullCorpus(t),
		Entries: g, Jobs: 1, Limits: Limits{Timeout: 20 * time.Second}, Validator: validator(t), Log: &log})
	if err != nil {
		t.Fatal(err)
	}
	res.Apply(ObservedJudge{})
	var got []string
	for _, o := range res.Observations {
		if o.ProtocolError != "" || o.NotRun != "" {
			t.Fatalf("%s: protocol %q not run %q", o.Cell.RowID(), o.ProtocolError, o.NotRun)
		}
		got = append(got, o.Cell.Entry.ID+" "+o.Outcome+" "+o.Judgement.Verdict)
	}
	want := []string{"contract-spec/truncated-spec-section reject conform", "contract-spec/two-spec-sections ok accepts_invalid"}
	if !slices.Equal(got, want) {
		t.Errorf("cells %v, want %v", got, want)
	}
}

// fullCorpus is every entry of the corpus (the spec entries among them), copied by the test-corpus builder.
func fullCorpus(t *testing.T) *manifest.Corpus {
	t.Helper()
	c, err := manifest.Load(testcorpus.Build(t, nil, testcorpus.Options{}), manifest.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

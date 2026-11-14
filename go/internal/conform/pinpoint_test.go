package conform

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
	"github.com/tolgayayci/xdrcheck/go/internal/testcorpus"
)

// A key-selected pinpoint (expect.values[].select) reaches the driver as the plain JSON Pointer of the change
// with that ledger key in each variant's sidecar; the verdict engine compares at the same pointer.
func TestKeySelectedPinpointsResolvePerVariant(t *testing.T) {
	const id = "cap-0001/bump-sequence-noop-updates-seq-time"
	const changes = "/v2/tx_processing/0/tx_apply_processing/v4/operations/0/changes"
	const account = "GCLI5BBS3Z7RSEGAK2SKKEEV7BHXQX4C5WHXG4PYZQFX7GUMYVSBD5TV"

	plain, err := manifest.Load(testcorpus.Build(t, []string{id}, testcorpus.Options{}), manifest.Options{SkipBlobCheck: true})
	if err != nil {
		t.Fatal(err)
	}
	root := testcorpus.Build(t, []string{id}, testcorpus.Options{})
	file := filepath.Join(root, "manifest", id+".json")
	rewrite := func(edit func(values []any)) {
		t.Helper()
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(data, &m); err != nil {
			t.Fatal(err)
		}
		edit(m["expect"].(map[string]any)["values"].([]any))
		out, _ := json.MarshalIndent(m, "", "  ")
		if err := os.WriteFile(file, out, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	selected := 0
	rewrite(func(values []any) {
		for _, x := range values {
			v := x.(map[string]any)
			rest, ok := strings.CutPrefix(v["path"].(string), changes+"/")
			if !ok {
				continue
			}
			_, rel, _ := strings.Cut(rest, "/")
			arm, _, _ := strings.Cut(rel, "/")
			v["select"] = map[string]any{"in": changes, "key": map[string]any{"account": map[string]any{"account_id": account}}, "change": arm}
			v["path"] = "/" + rel
			selected++
		}
	})
	if selected < 2 {
		t.Fatalf("%s has %d change pinpoints", id, selected)
	}
	c, err := manifest.Load(root, manifest.Options{SkipBlobCheck: true})
	if err != nil {
		t.Fatal(err)
	}
	e, want := c.Entry(id), plain.Entry(id)
	col := &Column{ID: "stub"}
	for i, v := range e.Variants {
		w := want.Variants[i]
		for j, val := range v.Resolved.Values {
			if val.Select != nil || val.Path != w.Resolved.Values[j].Path {
				t.Errorf("%s values[%d]: resolved to %q (select %v), the positional pinpoint is %q", v.Network, j, val.Path, val.Select, w.Resolved.Values[j].Path)
			}
		}
		req, err := Request(c, &Cell{Entry: e, Variant: v, VariantKey: v.Network, Level: "L2", Column: col})
		if err != nil {
			t.Fatal(err)
		}
		for j, p := range req.Input.Pinpoints {
			if p != w.Resolved.Values[j].Path {
				t.Errorf("%s: L2 pinpoint %d sent as %q", v.Network, j, p)
			}
		}
	}

	// A selection that matches two changes (no change type) fails the load.
	rewrite(func(values []any) {
		for _, x := range values {
			if sel, ok := x.(map[string]any)["select"].(map[string]any); ok {
				delete(sel, "change")
				return
			}
		}
	})
	if _, err := manifest.Load(root, manifest.Options{SkipBlobCheck: true}); err == nil || !strings.Contains(err.Error(), "add `change`") {
		t.Errorf("an ambiguous selection: %v", err)
	}
}

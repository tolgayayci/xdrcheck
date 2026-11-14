package verdict

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tolgayayci/xdrcheck/go/internal/conform"
	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
)

func corpusEntry(t *testing.T, id string) *manifest.Entry {
	t.Helper()
	c, err := manifest.Load(filepath.Join(repoRoot(), "corpus"), manifest.Options{})
	if err != nil {
		t.Fatal(err)
	}
	e := c.Entry(id)
	if e == nil {
		t.Fatalf("no entry %s", id)
	}
	return e
}

func specActual(t *testing.T, entries []manifest.SpecEntry) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"spec": map[string]any{"entries": entries}})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The planted spec disagreement: a Wasm with two contractspecv0 sections. One reader takes the first section
// (accepts, with half the interface), another refuses it as SEP-48 requires; the matrix reports the split, and
// the accepting reader's cell is a failure.
func TestPlantedSpecSplit(t *testing.T) {
	e := corpusEntry(t, "contract-spec/two-spec-sections")
	if !e.Negative || e.Expect.Spec == nil || *e.Expect.Spec.Sections != 2 || len(e.Expect.Spec.Entries) != 2 {
		t.Fatalf("the two-section entry changed: %+v", e.Expect.Spec)
	}
	first := e.Expect.Spec.Entries[:1]
	reader := func(sdk string) *conform.Column {
		return &conform.Column{ID: sdk + "@1.0.0", SDK: sdk, Kind: "sdk", Target: sdk, Version: "1.0.0", Role: "extra"}
	}
	m := matrix(t, []*conform.Observation{
		obs(e, reader("first-section"), "spec", "ok", "", specActual(t, first)),
		obs(e, reader("refuses"), "spec", "reject", "spec_sections", ""),
	})
	var split *CrossSDK
	for i := range m.CrossSDK {
		if m.CrossSDK[i].Entry == e.ID && m.CrossSDK[i].Level == "spec" {
			split = &m.CrossSDK[i]
		}
	}
	if split == nil || split.Agree || len(split.Classes["reject"]) != 1 {
		t.Fatalf("no cross-reader split: %+v", m.CrossSDK)
	}
	f := m.Failing()
	if len(f) != 1 || f[0].Column != "first-section@1.0.0" || f[0].Verdict != "accepts_invalid" {
		t.Errorf("failing cells %+v", f)
	}
	var md bytes.Buffer
	m.CrossSDKMarkdown(&md)
	if !strings.Contains(md.String(), "contract-spec/two-spec-sections") {
		t.Errorf("cross-sdk.md lacks the split:\n%s", md.String())
	}
}

func TestSpecLevel(t *testing.T) {
	good := corpusEntry(t, "contract-spec/every-entry-kind-and-type")
	none := corpusEntry(t, "contract-spec/spec-less-mainnet-wasm")
	c := &conform.Column{ID: "r@1.0.0", SDK: "r", Kind: "sdk", Target: "r", Version: "1.0.0", Role: "extra"}
	all := good.Expect.Spec.Entries
	renamed := append([]manifest.SpecEntry(nil), all...)
	renamed[1].Args = append([]manifest.SpecArg(nil), renamed[1].Args...)
	renamed[1].Args[0].Name = "other"
	run(t, []row{
		{"every entry read", obs(good, c, "spec", "ok", "", specActual(t, all)), "conform", "conform", ""},
		{"an entry missing", obs(good, c, "spec", "ok", "", specActual(t, all[1:])), "diverge", "undeclared", ""},
		{"a field renamed", obs(good, c, "spec", "ok", "", specActual(t, renamed)), "diverge", "undeclared", ""},
		{"valid spec refused", obs(good, c, "spec", "reject", "decode_error", ""), "reject_valid", "undeclared", ""},
		{"no spec, empty interface", obs(none, c, "spec", "ok", "", specActual(t, []manifest.SpecEntry{})), "conform", "conform", ""},
		{"no spec, reported as an error", obs(none, c, "spec", "reject", "decode_error", ""), "conform", "conform", ""},
	})
}

// The json level keeps its three kinds of difference apart: a converter's JSON that breaks its own schema, a
// round trip that does not come back to the bytes, and converters that disagree with each other.
func TestJSONLevelVerdicts(t *testing.T) {
	c, err := manifest.Load(filepath.Join(repoRoot(), "corpus"), manifest.Options{})
	if err != nil {
		t.Fatal(err)
	}
	var e *manifest.Entry
	for _, x := range c.Entries {
		if x.Kind == "xdr" && !x.Negative && len(x.Variants) > 0 {
			e = x
			break
		}
	}
	sha := e.Variants[0].Blob.SHA256
	h1, h2 := strings.Repeat("a", 64), strings.Repeat("b", 64)
	facts := func(js, schema, rt, rtSHA string) string {
		b, _ := json.Marshal(map[string]any{"json": map[string]any{"json_sha256": js, "schema": schema, "roundtrip": rt, "roundtrip_sha256": rtSHA}})
		return string(b)
	}
	conv := func(sdk string) *conform.Column {
		return &conform.Column{ID: sdk + "@1.0.0", SDK: sdk, Kind: "sdk", Target: sdk, Version: "1.0.0", Role: "extra", Levels: []string{"json"}}
	}
	run(t, []row{
		{"clean", obs(e, conv("a"), "json", "ok", "", facts(h1, "valid", "identical", sha)), "conform", "conform", ""},
		{"schema", obs(e, conv("a"), "json", "ok", "", facts(h1, "invalid", "identical", sha)), "schema_invalid", "undeclared", ""},
		{"round trip", obs(e, conv("a"), "json", "ok", "", facts(h1, "valid", "changed", h2)), "roundtrip_changed", "undeclared", ""},
		{"round trip refused", obs(e, conv("a"), "json", "ok", "", facts(h1, "valid", "refused", "")), "roundtrip_refused", "undeclared", ""},
		{"no schema published", obs(e, conv("a"), "json", "ok", "", facts(h1, "not_checked", "not_supported", "")), "conform", "conform", ""},
	})
	k := kd("a", "1.0.0", "json", "wrong_value")
	e2 := *e
	e2.Conformance = &manifest.Conformance{KnownDivergences: []manifest.KnownDivergence{k}}
	run(t, []row{{"cited", obs(&e2, conv("a"), "json", "ok", "", facts(h1, "invalid", "identical", sha)), "schema_invalid", "known", "wrong_value"}})
	// A converter that refuses its own JSON is predicted by a reject at the json level, not by a wrong value.
	e3 := *e
	e3.Conformance = &manifest.Conformance{KnownDivergences: []manifest.KnownDivergence{kd("a", "1.0.0", "json", "reject")}}
	run(t, []row{
		{"refusal cited", obs(&e3, conv("a"), "json", "ok", "", facts(h1, "valid", "refused", "")), "roundtrip_refused", "known", "reject"},
		{"refusal is not a wrong value", obs(&e2, conv("a"), "json", "ok", "", facts(h1, "valid", "refused", "")), "roundtrip_refused", "known-changed", "wrong_value"},
	})

	m := matrix(t, []*conform.Observation{
		obs(e, conv("a"), "json", "ok", "", facts(h1, "valid", "identical", sha)),
		obs(e, conv("b"), "json", "ok", "", facts(h2, "invalid", "identical", sha)),
		obs(e, conv("c"), "json", "ok", "", facts(h1, "valid", "changed", h2)),
	})
	var md bytes.Buffer
	m.CrossSDKMarkdown(&md)
	s := md.String()
	for _, want := range []string{"### Schema-invalid", "b@1.0.0 (**new**)", "### Round-trip-changed", "c@1.0.0 (**new**)", "### Cross-binding-different", "accept:"} {
		if !strings.Contains(s, want) {
			t.Errorf("cross-sdk.md lacks %q:\n%s", want, s)
		}
	}
}

package manifest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
)

// schemaDetailKeys reads the state-change kind enum and the detail keys per kind from a schema's state-change
// item object.
func schemaDetailKeys(t *testing.T, item map[string]any) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	for _, k := range item["properties"].(map[string]any)["kind"].(map[string]any)["enum"].([]any) {
		out[k.(string)] = nil
	}
	for _, r := range item["allOf"].([]any) {
		rule := r.(map[string]any)
		kind := rule["if"].(map[string]any)["properties"].(map[string]any)["kind"].(map[string]any)["const"].(string)
		names := rule["then"].(map[string]any)["properties"].(map[string]any)["detail"].(map[string]any)["propertyNames"].(map[string]any)["enum"].([]any)
		for _, n := range names {
			if s := n.(string); !strings.HasSuffix(s, "_as_stored") {
				out[kind] = append(out[kind], s)
			}
		}
	}
	return out
}

func readSchema(t *testing.T, name string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(corpusRoot, "schema", name+".schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var s map[string]any
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

// The closed state-change vocabulary is one list: the manifest schema, the observation schema and DetailKeys
// name the same kinds with the same detail keys.
func TestStateChangeVocabularyMatchesTheSchemas(t *testing.T) {
	defs := func(s map[string]any) map[string]any { return s["$defs"].(map[string]any) }
	m := defs(readSchema(t, "manifest-entry"))["expect"].(map[string]any)["properties"].(map[string]any)["state_changes"].(map[string]any)["items"].(map[string]any)
	o := defs(readSchema(t, "observation"))["ledger"].(map[string]any)["properties"].(map[string]any)["state_changes"].(map[string]any)["items"].(map[string]any)
	for name, got := range map[string]map[string][]string{"manifest-entry": schemaDetailKeys(t, m), "observation": schemaDetailKeys(t, o)} {
		if len(got) != len(DetailKeys) {
			t.Errorf("%s: %d kinds, DetailKeys has %d", name, len(got), len(DetailKeys))
		}
		for kind, keys := range DetailKeys {
			want := slices.Clone(keys)
			have := slices.Clone(got[kind])
			sort.Strings(want)
			sort.Strings(have)
			if !slices.Equal(want, have) {
				t.Errorf("%s: %s detail keys %v, DetailKeys %v", name, kind, have, want)
			}
		}
	}
	for _, k := range []string{"account_flags_changed", "home_domain_changed", "inflation_destination_changed", "ttl_extended", "contract_code_created"} {
		if _, ok := DetailKeys[k]; !ok {
			t.Errorf("kind %s missing", k)
		}
	}
	if !slices.Contains(AmbientStateChangeKinds, "ttl_extended") {
		t.Error("ttl_extended is not ambient")
	}
}

// The new variant and reject fields decode and keep their values.
func TestFramingDepthAndJSONExceptionDecode(t *testing.T) {
	e, err := LoadEntry(filepath.Join(corpusRoot, "schema/examples/manifest-entry/valid-05.json"))
	if err != nil {
		t.Fatal(err)
	}
	if v := e.Variants[0]; !v.RecordMarked() || v.FrameOf() != 0 || e.Expect.Reject.Reason != "record_mark" {
		t.Errorf("framing %q frame %d reason %q", v.Framing, v.FrameOf(), e.Expect.Reject.Reason)
	}
	e, err = LoadEntry(filepath.Join(corpusRoot, "schema/examples/manifest-entry/valid-04.json"))
	if err != nil {
		t.Fatal(err)
	}
	if l := e.Expect.Reject.Limits; l == nil || l.Depth != 2000 {
		t.Errorf("reject limits %+v", l)
	}
	e, err = LoadEntry(filepath.Join(corpusRoot, "schema/examples/manifest-entry/valid-06.json"))
	if err != nil {
		t.Fatal(err)
	}
	if j := e.Variants[0].JSONRoundtrip; j == nil || !j.Skip || j.Reason == "" {
		t.Errorf("json_roundtrip %+v", j)
	}
}

package manifest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The optional source fields (local-core submission and core_role, history selected_by, history-archive
// file_kind) decode strictly from the schema's valid examples and write back unchanged.
func TestOptionalSourceFields(t *testing.T) {
	seen := map[string]bool{}
	for _, name := range []string{"valid-08.json", "valid-09.json", "valid-10.json"} {
		data, err := os.ReadFile(filepath.Join("..", "..", "..", "corpus", "schema", "examples", "manifest-entry", name))
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Variants []struct {
				Source json.RawMessage `json:"source"`
			} `json:"variants"`
		}
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatal(err)
		}
		for _, v := range doc.Variants {
			var s Source
			if err := json.Unmarshal(v.Source, &s); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			switch {
			case s.LocalCore != nil && s.LocalCore.Submission != nil:
				seen["submission"] = s.LocalCore.Submission.EnvelopeEntry != "" && s.LocalCore.CoreRole == "buildtests"
			case s.History != nil && s.History.SelectedBy != nil:
				seen["selected_by"] = s.History.SelectedBy.QueryID != ""
			case s.HistoryArchive != nil:
				seen["file_kind"] = s.HistoryArchive.FileKind == "scp"
			}
			out, err := json.Marshal(s)
			if err != nil {
				t.Fatal(err)
			}
			var a, b any
			_ = json.Unmarshal(v.Source, &a)
			_ = json.Unmarshal(out, &b)
			if ja, jb := mustJSON(a), mustJSON(b); ja != jb {
				t.Errorf("%s: source does not write back unchanged:\n%s\n%s", name, ja, jb)
			}
		}
	}
	for _, k := range []string{"submission", "selected_by", "file_kind"} {
		if !seen[k] {
			t.Errorf("%s: not read from the examples", k)
		}
	}
	var s Source
	if err := json.Unmarshal([]byte(`{"kind":"history-archive","store":"s","object":"o","object_sha256":"x","byte_offset":0,"core_role":"vnext"}`), &s); err == nil {
		t.Error("a local-core field on a history-archive source was accepted")
	}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

package adapterkit

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const examplesDir = "../../corpus/schema/examples/adapter-protocol"

func TestSchemaCopiesAreTheFrozenOnes(t *testing.T) {
	for _, name := range []string{"adapter-protocol.schema.json", "observation.schema.json"} {
		frozen, err := os.ReadFile(filepath.Join("../../corpus/schema", name))
		if err != nil {
			t.Fatal(err)
		}
		copied, err := schemaFS.ReadFile("schemas/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(frozen, copied) {
			t.Errorf("schemas/%s differs from corpus/schema/%s; copy it again", name, name)
		}
	}
}

// Every example the schema directory holds validates (or fails) as check_schemas.py says it must.
func TestSchemaExamples(t *testing.T) {
	for dir, validate := range map[string]func([]byte) []SchemaError{
		"adapter-protocol": ValidateMessage,
		"observation":      ValidateObservation,
	} {
		files, _ := filepath.Glob(filepath.Join("../../corpus/schema/examples", dir, "*.json"))
		if len(files) < 2 {
			t.Fatalf("%s: no examples", dir)
		}
		for _, f := range files {
			data, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			errs := validate(data)
			if strings.HasPrefix(filepath.Base(f), "valid-") && len(errs) > 0 {
				t.Errorf("%s: %v", f, errs)
			}
			if strings.HasPrefix(filepath.Base(f), "invalid-") && len(errs) == 0 {
				t.Errorf("%s validates but must not", f)
			}
		}
	}
}

// The validator enforces the parts of the schema that typed decoding alone would miss.
func TestValidatorRules(t *testing.T) {
	base := string(mustRead(t, "valid-10.json"))
	cases := []struct {
		name, old, new string
		ok             bool
	}{
		{"as is", "", "", true},
		{"integer written as 4437357.0 is an integer", `"ledger_seq": 4437357`, `"ledger_seq": 4437357.0`, true},
		{"fractional ledger", `"ledger_seq": 4437357`, `"ledger_seq": 4437357.5`, false},
		{"hash pattern", `"hash": "d9f7`, `"hash": "D9F7`, false},
		{"detail key closed per kind", `"native_label": "SIGNER/ADD"`, `"native_label": "SIGNER/ADD", "detail": {"limit": "1"}`, false},
		{"detail key of the kind", `"native_label": "SIGNER/ADD"`, `"native_label": "SIGNER/ADD", "detail": {"weight_before": 0, "sponsor_as_stored": "x"}`, true},
		{"account needs a form", `"account": {
              "address": "GBCK2RYYLIYOSHBEL2FQLAVRSHRH3GP3ID476SGKBV7BEZHMQ6NSBB7B",
              "as_stored": {
                "encoding": "version_byte_payload_hex",
                "value": "3044ad47185a30e91c245e8b0582b191e27d99fb40f9ff48ca0d7e1264ec879b20"
              }
            }
          }
        ],
        "state_changes"`, `"account": {"roles": ["source"]}}], "state_changes"`, false},
		{"not_applicable needs a reason", `"status": "not_applicable",
        "reason": "adapter v0.1 maps state changes only"`, `"status": "not_applicable"`, false},
		{"unknown property", `"errors": []`, `"errors": [], "extra": 1`, false},
		{"stored encoding enum", `"encoding": "version_byte_payload_hex",
              "value": "7844`, `"encoding": "base64",
              "value": "7844`, false},
	}
	for _, tc := range cases {
		doc := base
		if tc.old != "" {
			if !strings.Contains(doc, tc.old) {
				t.Fatalf("%s: example text not found", tc.name)
			}
			doc = strings.Replace(doc, tc.old, tc.new, 1)
		}
		errs := ValidateMessage([]byte(doc))
		if tc.ok && len(errs) > 0 {
			t.Errorf("%s: %v", tc.name, errs)
		}
		if !tc.ok && len(errs) == 0 {
			t.Errorf("%s: validates but must not", tc.name)
		}
	}

	// ingest: refusal only with status refused (if/then/else in the schema).
	ingest := string(mustRead(t, "valid-08.json"))
	if errs := ValidateMessage([]byte(strings.Replace(ingest, `"status": "refused"`, `"status": "halted"`, 1))); len(errs) == 0 {
		t.Error("a halted result with a refusal validates")
	}
	// requests: loopback-only URLs.
	req := string(mustRead(t, "valid-05.json"))
	if errs := ValidateMessage([]byte(strings.Replace(req, "http://127.0.0.1:58090", "http://10.0.0.1:58090", 1))); len(errs) == 0 {
		t.Error("a non-loopback endpoint validates")
	}
}

func mustRead(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(examplesDir, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

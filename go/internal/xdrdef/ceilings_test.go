package xdrdef

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func miniSet(t *testing.T) *Set {
	t.Helper()
	defs, err := ParseFile("m.x", `enum SCAddressType { A = 0, B = 7 }; enum ConfigSettingID { X = 0, Y = 20 }; enum Other { Z = 3 };`)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSet(defs)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestUpdateCeilingsEveryLanguage rewrites a block in each driver language's syntax, with the SDK's own
// spelling of the enum names, and reports what moved.
func TestUpdateCeilingsEveryLanguage(t *testing.T) {
	s := miniSet(t)
	for name, text := range map[string]string{
		"py":   "CEILING = {\n    # BEGIN generated: xdrcheck xdr ceilings (old)\n    \"SCAddressType\": 5, \"ConfigSettingID\": 20,\n    # END generated: xdrcheck xdr ceilings\n}\n",
		"js":   "export const CEILING = {\n  // BEGIN generated: xdrcheck xdr ceilings (old)\n  ScAddressType: 5, ConfigSettingId: 20,\n  // END generated: xdrcheck xdr ceilings\n};\n",
		"rust": "pub const CEILING: [(&str, i32); 2] = [\n    // BEGIN generated: xdrcheck xdr ceilings (old)\n    (\"ScAddressType\", 5),\n    (\"ConfigSettingId\", 20),\n    // END generated: xdrcheck xdr ceilings\n];\n",
		"go":   "var ceiling = []c{\n\t// BEGIN generated: xdrcheck xdr ceilings (old)\n\t{\"ScAddressType\", 5, xdr.ScAddressType(0).ValidEnum},\n\t{\"ConfigSettingId\", 20, xdr.ConfigSettingId(0).ValidEnum},\n\t// END generated: xdrcheck xdr ceilings\n}\n",
	} {
		out, drift, err := UpdateCeilings(name, text, s, "stellar-xdr v31.0")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(drift) != 2 || drift[0].Enum != "(label)" || drift[1].Have != "5" || drift[1].Want != "7" {
			t.Errorf("%s: drift %v", name, drift)
		}
		if !strings.Contains(out, "(stellar-xdr v31.0)") || strings.Count(out, "7") != 1 || !strings.Contains(out, "20") {
			t.Errorf("%s: rewritten as\n%s", name, out)
		}
		again, drift, err := UpdateCeilings(name, out, s, "stellar-xdr v31.0")
		if err != nil || len(drift) != 0 || again != out {
			t.Errorf("%s: not idempotent: %v %v", name, drift, err)
		}
	}
	for _, bad := range []string{
		"x\n",
		"// BEGIN generated: xdrcheck xdr ceilings (v)\nNope: 1,\n// END generated: xdrcheck xdr ceilings\n",
		"// BEGIN generated: xdrcheck xdr ceilings (v)\nSCAddressType: 1,\n",
		"// BEGIN generated: xdrcheck xdr ceilings\nSCAddressType: 1,\n// END generated: xdrcheck xdr ceilings\n",
	} {
		if _, _, err := UpdateCeilings("bad", bad, s, "v"); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

// TestDriverCeilingsMatchPinnedDefinitions is the drift check: every driver's ceiling block holds the values
// of the pinned definitions (the vendored JSON the corpus tools compile in).
func TestDriverCeilingsMatchPinnedDefinitions(t *testing.T) {
	s, err := LoadIR(vendoredIR(t))
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join("..", "..", "..")
	files, err := FindCeilingFiles(filepath.Join(root, "drivers"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 5 {
		t.Fatalf("found %d ceiling blocks under drivers/, want one per driver language (5): %v", len(files), files)
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		_, drift, err := UpdateCeilings(f, string(b), s, labelOf(string(b)))
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range drift {
			t.Errorf("%s (run make xdr-ceilings)", d)
		}
	}
}

// labelOf reads the label a block was generated with, so this test checks values only (the command checks
// the label against pins.toml).
func labelOf(text string) string {
	i := strings.Index(text, CeilingBegin)
	line := text[i:]
	line = line[:strings.Index(line, "\n")]
	m := beginLabel.FindStringSubmatch(line)
	return m[1]
}

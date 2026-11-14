package xdrdef

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// vendoredIR is the pinned definitions JSON the corpus tools compile in.
func vendoredIR(t *testing.T) string {
	t.Helper()
	p := filepath.Join("..", "..", "..", "crates", "xdrcheck-corpus", "data", "xdr-definitions-v30.0.0.json.zst")
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("vendored definitions: %v", err)
	}
	return p
}

var topLevel = regexp.MustCompile(`^(const|typedef|enum\s+\w+|struct\s+\w+|union\s+\w+\s+switch)\b`)

// sourceFromIR rebuilds a .x text per file from the `source` of every top-level definition the JSON holds.
func sourceFromIR(t *testing.T, path string) map[string]string {
	t.Helper()
	b, err := ReadMaybeZstd(path)
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Files []struct {
			Name string `json:"name"`
		} `json:"files"`
		Definitions []struct {
			Source    string `json:"source"`
			FileIndex int    `json:"file_index"`
		} `json:"definitions"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, d := range f.Definitions {
		if !topLevel.MatchString(d.Source) {
			continue
		}
		n := strings.TrimPrefix(f.Files[d.FileIndex].Name, "xdr/")
		out[n] += d.Source + "\n\n"
	}
	return out
}

// canon renders a set as comparable lines, with sizes resolved through the set's constants.
func canon(s *Set) []string {
	consts := map[string]string{}
	for _, d := range s.Defs {
		if d.Kind == "const" {
			consts[d.Name] = d.Value
		}
	}
	var ty func(*Type) string
	ty = func(t *Type) string {
		if t == nil {
			return "void"
		}
		c := *t
		if v, ok := consts[c.Size]; ok {
			c.Size = v
		}
		if c.Elem != nil {
			e := ty(c.Elem)
			c.Elem = &Type{Kind: "ref", Name: e}
		}
		return c.String()
	}
	var out []string
	for _, d := range s.Defs {
		switch d.Kind {
		case "const":
			out = append(out, "const "+d.Name+" "+d.Value)
		case "typedef":
			out = append(out, "typedef "+d.Name+" "+ty(d.Type))
		case "enum":
			for _, m := range d.Members {
				out = append(out, "enum "+d.Name+" "+m.Name+"="+strconv.FormatInt(m.Value, 10))
			}
		case "struct":
			for i, f := range d.Fields {
				out = append(out, "struct "+d.Name+" "+strconv.Itoa(i)+" "+f.Name+" "+ty(f.Type))
			}
		case "union":
			out = append(out, "union "+d.Name+" switch "+ty(d.Disc.Type))
			for _, a := range d.Arms {
				for _, c := range a.Cases {
					out = append(out, "union "+d.Name+" "+s.CaseLabel(d, c)+" "+a.Name+" "+ty(a.Type))
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// TestParserAgreesWithRustIR parses the .x text of every top-level definition of the pinned definitions JSON
// and checks the result equals the JSON's own structure, nested anonymous types (and their names) included.
func TestParserAgreesWithRustIR(t *testing.T) {
	path := vendoredIR(t)
	ir, err := LoadIR(path)
	if err != nil {
		t.Fatal(err)
	}
	var defs []*Def
	files := sourceFromIR(t, path)
	names := sortedKeys(files)
	for _, n := range names {
		d, err := ParseFile(n, files[n])
		if err != nil {
			t.Fatal(err)
		}
		defs = append(defs, d...)
	}
	parsed, err := NewSet(defs)
	if err != nil {
		t.Fatal(err)
	}
	a, b := canon(parsed), canon(ir)
	ia := map[string]bool{}
	for _, x := range a {
		ia[x] = true
	}
	ib := map[string]bool{}
	for _, x := range b {
		ib[x] = true
	}
	bad := 0
	for _, x := range a {
		if !ib[x] && bad < 20 {
			t.Errorf("parsed only: %s", x)
			bad++
		}
	}
	for _, x := range b {
		if !ia[x] && bad < 40 {
			t.Errorf("JSON only:   %s", x)
			bad++
		}
	}
	if len(parsed.Defs) != len(ir.Defs) {
		t.Errorf("parsed %d definitions, the JSON has %d", len(parsed.Defs), len(ir.Defs))
	}
	// The arm universe the corpus tools count from the ledger batch is the same from either source.
	ua, ub := parsed.ArmIDs("LedgerCloseMetaBatch"), ir.ArmIDs("LedgerCloseMetaBatch")
	if len(ua) != len(ub) || len(ua) == 0 {
		t.Errorf("arm universe: parsed %d, JSON %d", len(ua), len(ub))
	}
}

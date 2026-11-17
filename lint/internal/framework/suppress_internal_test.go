package framework

import (
	"testing"
	"testing/fstest"
)

// TestSuppressionLine: an entry with a line suppresses the report at that
// line only, so a new report elsewhere in the same function is not accepted
// with it; every key the entry gives must match.
func TestSuppressionLine(t *testing.T) {
	fsys := fstest.MapFS{"supp.yml": {Data: []byte(`- rule: XDR102
  file: internal/x.go
  function: walk
  line: 12
  reason: reviewed site
- rule: XDR102
  file: internal/y.go
  line: 7
  reason: a line alone names the site
- rule: XDR102
  file: internal/z.go
  line: -1
  reason: not a line
`)}}
	sf, err := loadSuppressionFile(source{fsys: fsys, name: "supp.yml", display: "supp.yml"})
	if err != nil {
		t.Fatal(err)
	}
	if p := sf.Entries[0].Problem + sf.Entries[1].Problem; p != "" {
		t.Fatalf("valid entries rejected: %s", p)
	}
	if sf.Entries[2].Problem != "line -1 is not a line number" {
		t.Errorf("negative line: problem %q", sf.Entries[2].Problem)
	}
	c := &Config{SuppressionFiles: []*SuppressionFile{sf}}
	for _, tc := range []struct {
		file, function string
		line           int
		want           bool
	}{
		{"internal/x.go", "walk", 12, true},
		{"internal/x.go", "walk", 13, false},   // a second report in the suppressed function
		{"internal/x.go", "other", 12, false},  // the line, but another function
		{"internal/y.go", "anything", 7, true}, // no function given
		{"internal/y.go", "anything", 8, false},
	} {
		got := c.matchSuppression("XDR102", tc.file, tc.function, tc.line, "", "") != nil
		if got != tc.want {
			t.Errorf("%s:%d in %s: suppressed %v, want %v", tc.file, tc.line, tc.function, got, tc.want)
		}
	}
	if w := sf.Entries[0].where(); w != "function walk, line 12" {
		t.Errorf("where() = %q", w)
	}
}

// TestSuppressionMessage: an entry keyed by rule, file, function and message
// matches the report wherever it moves in the file, and only that report.
func TestSuppressionMessage(t *testing.T) {
	fsys := fstest.MapFS{"supp.yml": {Data: []byte(`- rule: XDR402
  file: internal/x.go
  function: build
  message: "int64(v) (line 12) narrows xdr.Uint64 into field Row.ID at x.go:40"
  reason: reviewed site
`)}}
	sf, err := loadSuppressionFile(source{fsys: fsys, name: "supp.yml", display: "supp.yml"})
	if err != nil {
		t.Fatal(err)
	}
	if p := sf.Entries[0].Problem; p != "" {
		t.Fatalf("valid entry rejected: %s", p)
	}
	c := &Config{SuppressionFiles: []*SuppressionFile{sf}}
	for _, tc := range []struct {
		function, msg string
		line          int
		want          bool
	}{
		{"build", "int64(v) (line 12) narrows xdr.Uint64 into field Row.ID at x.go:40", 40, true},
		{"build", "int64(v) (line 19) narrows xdr.Uint64 into field Row.ID at x.go:47", 47, true}, // moved
		{"build", "int32(v) (line 19) narrows xdr.Uint64 into field Row.ID at x.go:47", 47, false},
		{"other", "int64(v) (line 12) narrows xdr.Uint64 into field Row.ID at x.go:40", 40, false},
	} {
		got := c.matchSuppression("XDR402", "internal/x.go", tc.function, tc.line, "", tc.msg) != nil
		if got != tc.want {
			t.Errorf("%q in %s: suppressed %v, want %v", tc.msg, tc.function, got, tc.want)
		}
	}
}

func TestNormaliseMessage(t *testing.T) {
	for in, want := range map[string]string{
		"x (line 28) reaches y at events.go:12":      "x (line) reaches y at events.go",
		"read at lines 3-9 and processor.go:4:7":     "read at lines and processor.go",
		"no numbers here  but  spaces":               "no numbers here but spaces",
		"v4 only; 2^63 stays; line 1 of liner 22 ok": "v4 only; 2^63 stays; line of liner 22 ok",
	} {
		if got := NormaliseMessage(in); got != want {
			t.Errorf("NormaliseMessage(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestExpectAndPendingByMessage: expected and pending entries that name a
// message match by rule, file, function and normalised message.
func TestExpectAndPendingByMessage(t *testing.T) {
	f := Finding{Rule: "XDR402", File: "a.go", Function: "F", Message: "m at line 3"}
	f2 := Finding{Rule: "XDR402", File: "a.go", Function: "F", Message: "other at line 9"}
	exp := []ExpectEntry{{Rule: "XDR402", File: "a.go", Function: "F", Message: "m at line 99"}}
	if miss, extra := CompareExpect(exp, []Finding{f}); len(miss)+len(extra) != 0 {
		t.Errorf("message entry: missing %v extra %v", miss, extra)
	}
	if miss, extra := CompareExpect(exp, []Finding{f2}); len(miss) != 1 || len(extra) != 1 {
		t.Errorf("other message: missing %v extra %v", miss, extra)
	}
	// An entry without a message still accounts for any report of its key.
	if miss, extra := CompareExpect([]ExpectEntry{{Rule: "XDR402", File: "a.go", Function: "F"}}, []Finding{f2}); len(miss)+len(extra) != 0 {
		t.Errorf("entry without message: missing %v extra %v", miss, extra)
	}
	f.Position.Line = 3
	for _, p := range []PendingEntry{
		{Rule: "XDR402", File: "a.go", Function: "F", Message: "m at line 1"},
		{Rule: "XDR402", Site2: SiteHash2("XDR402", "a.go", "F", "m at line 7")},
	} {
		if !IsPending([]PendingEntry{p}, f) {
			t.Errorf("%+v does not match %+v", p, f)
		}
		if IsPending([]PendingEntry{p}, f2) {
			t.Errorf("%+v matches %+v", p, f2)
		}
	}
}

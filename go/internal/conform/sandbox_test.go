package conform

import (
	"testing"

	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
)

func TestParseSandbox(t *testing.T) {
	for in, want := range map[string]int64{
		"address-space cap RLIMIT_AS 1 GiB":   1 << 30,
		"address-space cap RLIMIT_AS 512 MiB": 512 << 20,
		"address-space cap RLIMIT_AS 2GiB":    2 << 30,
		"limits-none":                         0,
		"":                                    0,
		"address-space cap RLIMIT_AS 0 GiB":   0,
		"limits-none under address-space cap RLIMIT_AS 1 GiB": 1 << 30,
	} {
		if got := ParseSandbox(in); got != want {
			t.Errorf("%q: %d, want %d", in, got, want)
		}
	}
}

// A sandbox profile restricted to one decode profile applies to that profile's columns only, and only when the
// cell ran under that sandbox; a plain sandbox profile applies to every column of the target that ran under it.
func TestProfileCovers(t *testing.T) {
	const plain = "address-space cap RLIMIT_AS 1 GiB"
	const none = "limits-none under " + plain
	for _, c := range []struct {
		div, col, sandbox string
		want              bool
	}{
		{"", "limits-default", "", true},
		{"limits-none", "limits-none", "", true},
		{"limits-none", "limits-default", "", false},
		{plain, "", plain, true},
		{plain, "limits-default", plain, true},
		{plain, "", "", false},
		{none, "limits-none", none, true},
		{none, "limits-default", none, false},
		{none, "limits-none", "", false},
	} {
		if got := ProfileCovers(c.div, c.col, c.sandbox); got != c.want {
			t.Errorf("ProfileCovers(%q, %q, %q) = %v, want %v", c.div, c.col, c.sandbox, got, c.want)
		}
	}
	if got := SandboxDecodeProfile(none); got != "limits-none" {
		t.Errorf("SandboxDecodeProfile(%q) = %q", none, got)
	}
}

// A memory-stress entry whose divergence names an address-space cap runs every column of that divergence's
// target under the cap, in a fresh process, and never under the default limits; other targets' columns run it
// as usual.
func TestPlanSandbox(t *testing.T) {
	e := &manifest.Entry{ID: "x/length-prefix-at-end-of-input", Kind: "xdr", Negative: true,
		Conformance: &manifest.Conformance{Levels: []string{"L0"}, KnownDivergences: []manifest.KnownDivergence{{
			Target: "github.com/stellar/go-stellar-sdk", Versions: ">=0.7.1 <0.7.2", Level: "L0", Outcome: "crash",
			Profile: "address-space cap RLIMIT_AS 1 GiB", Reference: "https://example.org"}}}}
	e.Variants = []*manifest.Variant{{Network: "none", Protocol: 30, XDRType: "ScVal"}}
	c := &manifest.Corpus{Entries: []*manifest.Entry{e}}
	goOld := &Column{ID: "go@v0.7.1", SDK: "go", Target: "github.com/stellar/go-stellar-sdk", Version: "v0.7.1"}
	goNew := &Column{ID: "go@v0.8.0", SDK: "go", Target: "github.com/stellar/go-stellar-sdk", Version: "v0.8.0"}
	js := &Column{ID: "js@17.4.0", SDK: "js", Target: "@stellar/stellar-sdk", Version: "17.4.0"}
	cells := Plan(c, []*Column{goOld, goNew, js}, nil, nil)
	if len(cells) != 3 {
		t.Fatalf("%d cells", len(cells))
	}
	for _, cell := range cells {
		sandboxed := cell.Column.SDK == "go"
		if (cell.AddressSpaceMax == 1<<30) != sandboxed || (cell.Sandbox != "") != sandboxed || !cell.Isolate {
			t.Errorf("%s: sandbox %q %d isolate %v", cell.Column.ID, cell.Sandbox, cell.AddressSpaceMax, cell.Isolate)
		}
	}
}

package driver

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// What a column is expected to do where it does not decode a corpus ledger. A cell is held to a known
// divergence the manifest declares for this target and version at that level (outcome and declared reason),
// and a cell awaiting a finding is acknowledged without an asserted outcome: an item of the committed pending
// list (findings/pending/conformance.json) or a report row a finding record lists in evidence.report_rows
// (findings/, and the private overlay's findings/ when XDRCHECK_OVERLAY names one), as `xdrcheck conform check` reads
// them. As in the orchestrator, a declared or acknowledged refusal at L0
// leaves nothing to check at L1 and L2. Everything else must decode, so the tests keep holding as the corpus
// grows.

// sdkTarget is the manifest's target name for this SDK (drivers/sets.toml).
const sdkTarget = "github.com/stellar/go-stellar-sdk"

type knownDivergence struct {
	Target   string `json:"target"`
	Versions string `json:"versions"`
	Level    string `json:"level"`
	Outcome  string `json:"outcome"`
	Profile  string `json:"profile"`
	Match    struct {
		Reason string `json:"reason"`
	} `json:"match"`
}

type expectations struct {
	version, column string
	pending         map[[4]string]bool
}

func loadExpectations(t *testing.T, root, version string) *expectations {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, "findings", "pending", "conformance.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Pending []struct{ Entry, Variant, Column, Level string } `json:"pending"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	x := &expectations{version: version, column: "go@" + version, pending: map[[4]string]bool{}}
	for _, p := range doc.Pending {
		x.pending[[4]string{p.Entry, p.Variant, p.Column, p.Level}] = true
	}
	dirs := []string{filepath.Join(root, "findings")}
	if ov := os.Getenv("XDRCHECK_OVERLAY"); ov != "" {
		dirs = append(dirs, filepath.Join(ov, "findings"))
	}
	for _, dir := range dirs {
		recs, _ := filepath.Glob(filepath.Join(dir, "*", "finding.json"))
		for _, p := range recs {
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			var rec struct {
				Evidence struct {
					ReportRows []string `json:"report_rows"`
				} `json:"evidence"`
			}
			if err := json.Unmarshal(b, &rec); err != nil {
				t.Fatalf("%s: %v", p, err)
			}
			for _, row := range rec.Evidence.ReportRows {
				if c, ok := rowCell(row); ok {
					x.pending[c] = true
				}
			}
		}
	}
	return x
}

// rowCell reads a report row conform:<entry>:<variant or ->:<column>:<level> (a Rust column ID holds a colon
// itself) as the cell (entry, variant, column, level).
func rowCell(row string) ([4]string, bool) {
	parts := strings.Split(row, ":")
	if len(parts) < 5 || parts[0] != "conform" {
		return [4]string{}, false
	}
	variant := parts[2]
	if variant == "-" {
		variant = ""
	}
	return [4]string{parts[1], variant, strings.Join(parts[3:len(parts)-1], ":"), parts[len(parts)-1]}, true
}

// pendingAt reports whether the cell at the level awaits a finding.
func (x *expectations) pendingAt(e *manifestEntry, key, level string) bool {
	return x.pending[[4]string{e.ID, key, x.column, level}]
}

// at returns the known divergence declared for this column at one of the levels, or pending = true when the
// pending list names the cell at one of them.
func (x *expectations) at(e *manifestEntry, key string, levels ...string) (k *knownDivergence, pending bool) {
	for _, level := range levels {
		for i := range e.Conformance.KnownDivergences {
			d := &e.Conformance.KnownDivergences[i]
			if d.Target == sdkTarget && (d.Level == "" || d.Level == level) && d.Profile == "" && inRange(x.version, d.Versions) {
				return d, false
			}
		}
	}
	for _, level := range levels {
		if x.pending[[4]string{e.ID, key, x.column, level}] {
			return nil, true
		}
	}
	return nil, false
}

// variantKey is the report's variant key: the network, with @protocol when the entry's variants differ in
// protocol.
func (e *manifestEntry) variantKey(network string, protocol int) string {
	for _, o := range e.Variants {
		if o.Protocol != protocol {
			return network + "@" + strconv.Itoa(protocol)
		}
	}
	return network
}

// cmpVersion orders MAJOR[.MINOR[.PATCH]][-pre][+build] versions with an optional leading v; a release sorts
// after its prereleases.
func cmpVersion(a, b string) int {
	parse := func(s string) ([3]int, string, bool) {
		s = strings.TrimPrefix(strings.TrimSpace(s), "v")
		s, _, _ = strings.Cut(s, "+")
		core, pre, hasPre := strings.Cut(s, "-")
		var n [3]int
		for i, p := range strings.SplitN(core, ".", 3) {
			n[i], _ = strconv.Atoi(p)
		}
		return n, pre, hasPre
	}
	x, xp, xh := parse(a)
	y, yp, yh := parse(b)
	for i := range x {
		if x[i] != y[i] {
			if x[i] < y[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case xh == yh && xp == yp:
		return 0
	case !xh:
		return 1
	case !yh:
		return -1
	}
	return strings.Compare(xp, yp)
}

// inRange reports whether ver satisfies a known divergence's range (docs/manifest.md): alternatives joined by
// ||, each *, a hyphen range A - B, or space-separated comparators.
func inRange(ver, rng string) bool {
	for _, alt := range strings.Split(rng, "||") {
		alt = strings.TrimSpace(alt)
		if alt == "*" {
			return true
		}
		if lo, hi, ok := strings.Cut(alt, " - "); ok {
			if cmpVersion(ver, lo) >= 0 && cmpVersion(ver, hi) <= 0 {
				return true
			}
			continue
		}
		all := true
		for _, c := range strings.Fields(alt) {
			op := ""
			for _, o := range []string{">=", "<=", ">", "<", "="} {
				if strings.HasPrefix(c, o) {
					op = o
					break
				}
			}
			d := cmpVersion(ver, c[len(op):])
			switch op {
			case "<":
				all = all && d < 0
			case "<=":
				all = all && d <= 0
			case ">":
				all = all && d > 0
			case ">=":
				all = all && d >= 0
			default:
				all = all && d == 0
			}
		}
		if all {
			return true
		}
	}
	return false
}

func TestInRange(t *testing.T) {
	for _, c := range []struct {
		ver, rng string
		want     bool
	}{
		{"v0.7.1", ">=0.7.1 <0.7.2", true},
		{"v0.7.2", ">=0.7.1 <0.7.2", false},
		{"v0.7.1", "0.7.1", true},
		{"v0.8.0", "0.7.1 || 0.8.0", true},
		{"v0.7.3", "0.7.0 - 0.7.2", false},
		{"v0.7.2", "0.7.0 - 0.7.2", true},
		{"v0.6.0", "<0.6.1", true},
		{"v0.8.0", "*", true},
		{"v0.8.0", "0.8.0-rc.1", false},
		{"v0.8.0-rc.1", "<0.8.0", true},
	} {
		if got := inRange(c.ver, c.rng); got != c.want {
			t.Errorf("inRange(%q, %q) = %v, want %v", c.ver, c.rng, got, c.want)
		}
	}
}

func TestRowCell(t *testing.T) {
	for row, want := range map[string][4]string{
		"conform:limits/x:pubnet@29:rust@30.0.0:limits-default:L0": {"limits/x", "pubnet@29", "rust@30.0.0:limits-default", "L0"},
		"conform:strkey/y:-:go@v0.8.0:L4":                          {"strkey/y", "", "go@v0.8.0", "L4"},
	} {
		if got, ok := rowCell(row); !ok || got != want {
			t.Errorf("rowCell(%q) = %v, %v; want %v", row, got, ok, want)
		}
	}
	if _, ok := rowCell("lint:a:b:c:d"); ok {
		t.Error("a lint row is not a conformance cell")
	}
}

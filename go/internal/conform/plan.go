package conform

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
)

// Cell is one unit of work: one entry, one variant (none for api and strkey entries), one level, one column.
type Cell struct {
	Entry      *manifest.Entry
	Variant    *manifest.Variant // nil for api and strkey entries
	VariantKey string            // report variant key; "" for api and strkey entries
	Level      string
	Column     *Column
	// Isolate runs the cell in a fresh driver process of its own (entries built to stress a reader, and any
	// entry a known divergence says crashes or hangs), so that it cannot take the column's long-lived process
	// down with it.
	Isolate bool
	// Sandbox is the address-space profile the cell runs under instead of the run's default limits (a known
	// divergence's profile naming an RLIMIT_AS cap, for a column of that divergence's target), and
	// AddressSpaceMax its cap in bytes; "" and 0 for an ordinary cell. A sandboxed cell is always isolated.
	Sandbox         string
	AddressSpaceMax int64
}

// RowID is the cell's stable report row ID.
func (c *Cell) RowID() string {
	v := c.VariantKey
	if v == "" {
		v = "-"
	}
	return fmt.Sprintf("conform:%s:%s:%s:%s", c.Entry.ID, v, c.Column.ID, c.Level)
}

// less orders cells by entry, variant, column, level: the report order, whatever the scheduling.
func (c *Cell) less(o *Cell) bool {
	switch {
	case c.Entry.ID != o.Entry.ID:
		return c.Entry.ID < o.Entry.ID
	case c.VariantKey != o.VariantKey:
		return c.VariantKey < o.VariantKey
	case c.Column.ID != o.Column.ID:
		return c.Column.ID < o.Column.ID
	}
	return levelIndex(c.Level) < levelIndex(o.Level)
}

func levelIndex(l string) int {
	for i, x := range Levels {
		if x == l {
			return i
		}
	}
	return len(Levels)
}

// KindLevels are the levels that apply to each entry kind when the entry does not list its own
// (docs/manifest.md §10): L2 (decoded values) only for positive entries.
func KindLevels(e *manifest.Entry) []string {
	switch e.Kind {
	case "ledger":
		if e.Negative {
			return []string{"L0", "L1"}
		}
		return []string{"L0", "L1", "L2"}
	case "xdr":
		if e.Negative {
			return []string{"L0", "L1", "L3"}
		}
		return []string{"L0", "L1", "L2", "L3"}
	case "api", "strkey":
		return []string{"L4"}
	case "spec":
		return []string{"spec"}
	}
	return nil
}

// JSONLevel is the XDR-JSON level: run on every ledger and xdr variant, by the columns that list it in their
// sets.toml `levels` (the XDR-JSON converters), never by the others.
const JSONLevel = "json"

// ColumnLevels narrows an entry's planned levels to a column: a column that lists `levels` runs only those
// (and the json level on every ledger and xdr variant when it lists json); any other column runs the entry's
// levels but never json.
func ColumnLevels(e *manifest.Entry, col *Column, levels []string, want map[string]bool) []string {
	if len(col.Levels) == 0 {
		return levels
	}
	var out []string
	for _, l := range col.Levels {
		switch {
		case l == JSONLevel:
			if (e.Kind == "ledger" || e.Kind == "xdr") && (want == nil || want[JSONLevel]) {
				out = append(out, l)
			}
		case slices.Contains(levels, l):
			out = append(out, l)
		}
	}
	return out
}

// EntryLevels returns the levels planned for an entry: its conformance.levels if it lists them, else the
// levels of its kind; then only those in want (nil means all).
func EntryLevels(e *manifest.Entry, want map[string]bool) []string {
	levels := KindLevels(e)
	if e.Conformance != nil && len(e.Conformance.Levels) > 0 {
		levels = append([]string(nil), e.Conformance.Levels...)
		sort.Slice(levels, func(i, j int) bool { return levelIndex(levels[i]) < levelIndex(levels[j]) })
	}
	var out []string
	for _, l := range levels {
		if want == nil || want[l] {
			out = append(out, l)
		}
	}
	return out
}

// Isolated reports whether an entry runs in a fresh process per cell: an entry of the `limits` group (depth
// boundaries, size and memory vectors) or one with a known conformance divergence of outcome crash or hang.
func Isolated(e *manifest.Entry) bool {
	if strings.HasPrefix(e.ID, "limits/") {
		return true
	}
	if e.Conformance != nil {
		for _, k := range e.Conformance.KnownDivergences {
			if k.Level != "replay" && (k.Outcome == "crash" || k.Outcome == "hang") {
				return true
			}
		}
	}
	return false
}

// asProfileRe is the spelling of a known divergence's profile that names an address-space sandbox rather than a
// decode profile: "address-space cap RLIMIT_AS 1 GiB", or, for a divergence that shows only under one decode
// profile, "<decode profile> under address-space cap RLIMIT_AS 1 GiB" (docs/conformance-protocol.md).
var asProfileRe = regexp.MustCompile(`^(?:([a-z0-9][a-z0-9-]*) under )?address-space cap RLIMIT_AS ([1-9][0-9]*) ?(KiB|MiB|GiB)$`)

// ParseSandbox returns the address-space cap a known-divergence profile names, in bytes, or 0 when the profile is
// not an address-space sandbox (a decode profile such as limits-none, or none).
func ParseSandbox(profile string) int64 {
	m := asProfileRe.FindStringSubmatch(profile)
	if m == nil {
		return 0
	}
	n, err := strconv.ParseInt(m[2], 10, 64)
	if err != nil {
		return 0
	}
	return n << map[string]uint{"KiB": 10, "MiB": 20, "GiB": 30}[m[3]]
}

// SandboxDecodeProfile returns the decode profile an address-space sandbox profile is restricted to ("limits-none"
// for "limits-none under address-space cap RLIMIT_AS 1 GiB"), or "" when it names none or is not a sandbox.
func SandboxDecodeProfile(profile string) string {
	if m := asProfileRe.FindStringSubmatch(profile); m != nil {
		return m[1]
	}
	return ""
}

// ProfileCovers reports whether a known divergence's profile applies to a column with the given decode profile
// whose cell ran under the given sandbox: no profile; the column's decode profile; or the cell's sandbox, when
// the sandbox names no decode profile or names the column's.
func ProfileCovers(divergence, column, sandbox string) bool {
	switch {
	case divergence == "" || divergence == column:
		return true
	case sandbox == "" || divergence != sandbox:
		return false
	}
	dp := SandboxDecodeProfile(divergence)
	return dp == "" || dp == column
}

// SandboxFor returns the address-space sandbox the entry's known divergences name for the column's target: the
// profile and its cap. Memory-stress vectors are judged where their divergence was observed; under the default
// limits alone their outcome can depend on how much of a huge allocation the runtime happens to touch, which
// is load-dependent. Every column of that target runs the entry under the sandbox (each version inside or
// outside the divergence's range gets the same limits), and no column of it runs the entry under the
// default limits. Other targets' columns run it under the default limits.
func SandboxFor(e *manifest.Entry, col *Column) (string, int64) {
	if e.Conformance == nil || col == nil {
		return "", 0
	}
	for _, k := range e.Conformance.KnownDivergences {
		if k.Level == "replay" || k.Target != col.Target {
			continue
		}
		// A column that runs only some levels takes the sandbox of a divergence at one of them.
		if len(col.Levels) > 0 && k.Level != "" && !slices.Contains(col.Levels, k.Level) {
			continue
		}
		if n := ParseSandbox(k.Profile); n > 0 {
			return k.Profile, n
		}
	}
	return "", 0
}

// Plan builds the cells for the selected entries and columns, in report order.
func Plan(c *manifest.Corpus, columns []*Column, entries Globs, levels map[string]bool) []*Cell {
	var cells []*Cell
	for _, e := range c.Entries {
		if !entries.Match(e.ID) {
			continue
		}
		lv := EntryLevels(e, levels)
		iso := Isolated(e)
		variants := e.Variants
		if e.Kind == "api" || e.Kind == "strkey" {
			variants = []*manifest.Variant{nil}
		}
		for _, v := range variants {
			key := ""
			if v != nil {
				key = e.VariantKey(v)
			}
			for _, col := range columns {
				sandbox, as := SandboxFor(e, col)
				for _, l := range ColumnLevels(e, col, lv, levels) {
					cells = append(cells, &Cell{Entry: e, Variant: v, VariantKey: key, Level: l, Column: col, Isolate: iso || as > 0,
						Sandbox: sandbox, AddressSpaceMax: as})
				}
			}
		}
	}
	sort.SliceStable(cells, func(i, j int) bool { return cells[i].less(cells[j]) })
	return cells
}

// Request builds the run request for a cell (without id; the driver connection assigns it).
func Request(c *manifest.Corpus, cell *Cell) (*RunRequest, error) {
	e := cell.Entry
	req := &RunRequest{Entry: e.ID, Variant: cell.VariantKey, Level: cell.Level, Profile: cell.Column.Profile}
	switch e.Kind {
	case "ledger", "xdr":
		v := cell.Variant
		p := c.BlobPath(v)
		if p == "" {
			return nil, fmt.Errorf("%s (%s): the blob has no path (bulk tier); bulk-tier input is not supported yet", e.ID, cell.VariantKey)
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			return nil, err
		}
		in := Input{Kind: "xdr", XDRType: v.XDRType, Path: abs, Passphrase: v.Passphrase}
		if f, ok := bulkFrame(e, v); ok {
			in.Framing, in.FrameIndex = "record-marked", &f
		} else if v.RecordMarked() {
			// A record-mark error vector: the blob is the stream, the value its record frame_index.
			f := v.FrameOf()
			in.Framing, in.FrameIndex = "record-marked", &f
		}
		if v.Network == "none" {
			in.Passphrase = ""
		}
		if f := v.Focus; f != nil && (f.TxIndex != nil || f.OpIndex != nil || f.Path != "") {
			in.Focus = &ReqFocus{TxIndex: f.TxIndex, OpIndex: f.OpIndex, Path: f.Path}
		}
		if (cell.Level == "L2" || cell.Level == JSONLevel) && v.Resolved != nil {
			for _, val := range v.Resolved.Values {
				// A key-selected pinpoint is resolved to a plain pointer when the corpus is loaded
				// (manifest.ResolvePinpoints); drivers only ever receive plain pointers.
				if val.Select != nil {
					return nil, fmt.Errorf("%s: a key-selected pinpoint was not resolved against the variant's sidecar", e.ID)
				}
				in.Pinpoints = append(in.Pinpoints, val.Path)
			}
		}
		req.Input = in
	case "api":
		if e.API == nil {
			return nil, fmt.Errorf("%s: api entry without an api block", e.ID)
		}
		args := e.API.Input
		if args == nil {
			args = map[string]any{}
		}
		req.Input = Input{Kind: "api", APIOp: e.API.Op, Args: args}
	case "spec":
		v := cell.Variant
		p := c.BlobPath(v)
		abs, err := filepath.Abs(p)
		if err != nil {
			return nil, err
		}
		in := Input{Kind: "spec", Container: v.Container, Path: abs}
		if v.Container == "wasm" {
			b, err := os.ReadFile(abs)
			if err != nil {
				return nil, err
			}
			// A malformed module has no sections to hand on; the readers under test meet it as it is.
			in.Sections, _ = SpecSections(b)
		}
		req.Input = in
	case "strkey":
		if e.Strkey == nil {
			return nil, fmt.Errorf("%s: strkey entry without a strkey block", e.ID)
		}
		req.Input = Input{Kind: "strkey", Text: e.Strkey.Text, DeclaredType: e.Strkey.Type}
	default:
		return nil, fmt.Errorf("%s: unknown entry kind %q", e.ID, e.Kind)
	}
	return req, nil
}

package verdict

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/tolgayayci/xdrcheck/go/internal/conform"
	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
	"github.com/tolgayayci/xdrcheck/go/internal/report"
)

// MatrixSchema is the matrix file's schema ID.
const MatrixSchema = "xcc.conformance.matrix/v1"

// Output files beside report.json.
const (
	MatrixFile   = "matrix.json"
	MarkdownFile = "matrix.md"
	CrossSDKFile = "cross-sdk.md"
	SummaryFile  = "SUMMARY.md" // what a reader acts on: wrong answers, crashes and disagreements (summary.go)
)

// Matrix is the divergence matrix: entry × column × level → verdict (docs/driver-protocol.md §6). Everything but Run is comparable
// between runs: it carries no times or host names.
type Matrix struct {
	Schema         string           `json:"schema"`
	Corpus         report.CorpusRef `json:"corpus"`
	Run            *report.Run      `json:"run,omitempty"`
	Columns        []MatrixColumn   `json:"columns"`
	Entries        []MatrixEntry    `json:"entries"`
	Cells          []Cell           `json:"cells"`
	CrossSDK       []CrossSDK       `json:"cross_sdk"`
	NotExercised   []NotExercised   `json:"not_exercised"`
	Infrastructure []string         `json:"infrastructure"`
	Summary        map[string]int   `json:"summary"`
	// Expectations states, per entry, variant and level (RowKey), what the corpus expects, in words
	// (ExpectedValue): the summary and the cross-SDK page print it next to each column's answer.
	Expectations map[string]string `json:"expectations,omitempty"`
	// Unread lists the entry variants a column never read (conform.Result.Unread).
	Unread []conform.Unread `json:"unread,omitempty"`
}

// RowKey identifies a matrix row: one entry, variant and level, across columns.
func RowKey(entry, variant, level string) string { return entry + " " + variant + " " + level }

// MatrixColumn is one column and what its driver said about itself.
type MatrixColumn struct {
	ID        string          `json:"id"`
	SDK       string          `json:"sdk"`
	Target    string          `json:"target"`
	Version   string          `json:"version"`
	Profile   string          `json:"profile,omitempty"`
	Source    string          `json:"source,omitempty"` // the SDK checkout the column was built from (xdrcheck conform --sdk)
	Kind      string          `json:"kind"`
	Role      string          `json:"role"`
	Required  bool            `json:"required"`
	Describe  json.RawMessage `json:"describe_sdk,omitempty"`
	XDRSchema json.RawMessage `json:"xdr_schema,omitempty"`
}

// MatrixEntry is what the views need to know about an entry.
type MatrixEntry struct {
	ID                 string   `json:"id"`
	Kind               string   `json:"kind"`
	Caps               []int    `json:"caps,omitempty"`
	Negative           bool     `json:"negative,omitempty"`
	Validity           string   `json:"validity,omitempty"` // valid, malformed, invalid, acceptable (docs/manifest.md §9.5)
	Flags              []string `json:"flags,omitempty"`    // the bug classes the entry exercises
	ProtocolIntroduced int      `json:"protocol_introduced"`
	Reference          string   `json:"reference"`
	Expected           string   `json:"expected"` // accept, refuse, exact-or-refuse
	CoreLenient        bool     `json:"core_lenient,omitempty"`
}

// Cell is one judged cell.
type Cell struct {
	Entry           string          `json:"entry"`
	Variant         string          `json:"variant,omitempty"`
	Level           string          `json:"level"`
	Column          string          `json:"column"`
	Outcome         string          `json:"outcome"`
	Reason          string          `json:"reason,omitempty"`
	Source          string          `json:"source"`
	Reference       string          `json:"reference"`
	Verdict         string          `json:"verdict"`
	Check           string          `json:"check"`
	ExpectedVerdict string          `json:"expected_verdict"`
	OutOfReach      bool            `json:"out_of_reach,omitempty"`
	BlockedByL0     bool            `json:"blocked_by_l0,omitempty"`
	Sandbox         string          `json:"sandbox,omitempty"` // the address-space profile the cell ran under, when not the run's default limits
	KnownDivergence *KnownRef       `json:"known_divergence,omitempty"`
	Finding         string          `json:"finding,omitempty"`
	PendingReview   bool            `json:"pending_review,omitempty"` // undeclared, but on the committed list of divergences not yet triaged
	Value           string          `json:"value,omitempty"`          // a fingerprint of what the SDK produced, for cross-SDK comparison
	Evidence        json.RawMessage `json:"evidence,omitempty"`
	Notes           []string        `json:"notes,omitempty"`
}

// Key identifies a cell across matrices.
func (c *Cell) Key() string { return c.Entry + " " + c.Variant + " " + c.Column + " " + c.Level }

// KnownRef is the known divergence a cell matched.
type KnownRef struct {
	Reference string `json:"reference"`
	Status    string `json:"status"`
	FixedIn   string `json:"fixed_in,omitempty"`
	Versions  string `json:"versions"`
	Outcome   string `json:"outcome"`
}

// CrossSDK is "diverges from each other" for one entry, variant and level: the outcome classes of the latest
// column of each SDK.
type CrossSDK struct {
	Entry   string              `json:"entry"`
	Variant string              `json:"variant,omitempty"`
	Level   string              `json:"level"`
	Agree   bool                `json:"agree"`
	Classes map[string][]string `json:"classes"`
}

// NotExercised is a known divergence the run did not assert: no selected column falls inside its range, or
// every cell inside it is n_a (documentation until one is judged).
type NotExercised struct {
	Entry    string `json:"entry"`
	Target   string `json:"target"`
	Versions string `json:"versions"`
	Level    string `json:"level,omitempty"`
	Observed string `json:"observed,omitempty"`
	Why      string `json:"why"`
}

// Reasons a known divergence is not exercised.
const (
	NoColumnInRange = "no selected column inside the range"
	AllCellsNA      = "every cell inside the range is n_a"
)

// Build makes the matrix from a judged result. res.Apply(Engine{}) must have run.
func Build(res *conform.Result, h report.Header, run *report.Run) *Matrix {
	m := &Matrix{Schema: MatrixSchema, Corpus: h.Corpus, Run: run, Summary: map[string]int{},
		Entries: []MatrixEntry{}, Cells: []Cell{}, CrossSDK: []CrossSDK{}, NotExercised: []NotExercised{}, Infrastructure: res.InfraErrors()}
	if m.Infrastructure == nil {
		m.Infrastructure = []string{}
	}
	cols := map[string]*conform.Column{}
	for _, cr := range res.Columns {
		c := cr.Column
		cols[c.ID] = c
		mc := MatrixColumn{ID: c.ID, SDK: c.SDK, Target: c.Target, Version: c.Version, Profile: c.Profile, Kind: c.Kind, Role: c.Role, Required: c.Role == "required", Source: c.Source}
		if d := cr.Describe; d != nil {
			mc.Describe, _ = json.Marshal(d.SDK)
			mc.XDRSchema, _ = json.Marshal(d.XDRSchema)
		}
		m.Columns = append(m.Columns, mc)
	}
	eng := Engine{}
	seen := map[string]bool{}
	m.Expectations = map[string]string{}
	for _, o := range res.Observations {
		if o.Judgement == nil {
			continue
		}
		a := eng.Assess(o)
		e := o.Cell.Entry
		if !seen[e.ID] {
			seen[e.ID] = true
			m.Entries = append(m.Entries, MatrixEntry{ID: e.ID, Kind: e.Kind, Caps: e.Caps, Negative: e.Negative,
				Validity: e.Validity, Flags: e.Flags, ProtocolIntroduced: e.Protocol.Introduced,
				Reference: a.Reference, Expected: a.Expected, CoreLenient: a.CoreLenient})
		}
		if rk := RowKey(e.ID, o.Cell.VariantKey, o.Cell.Level); m.Expectations[rk] == "" {
			m.Expectations[rk] = ExpectedValue(e, o.Cell.Variant, o.Cell.Level)
		}
		cell := Cell{Entry: e.ID, Variant: o.Cell.VariantKey, Level: o.Cell.Level, Column: o.Cell.Column.ID, Outcome: o.Outcome,
			Reason: o.Reason, Source: o.Source, Reference: a.Reference, Verdict: a.Verdict, Check: a.Check,
			ExpectedVerdict: a.ExpectedVerdict, OutOfReach: a.OutOfReach, BlockedByL0: a.BlockedByL0, Sandbox: o.Cell.Sandbox,
			Value: fingerprint(o), Notes: a.Notes, PendingReview: o.Judgement.Expectation == report.ExpectationPending}
		if k := a.Known; k != nil {
			cell.KnownDivergence = &KnownRef{Reference: k.Reference, Status: statusOr(k.Status), FixedIn: k.FixedIn, Versions: k.Versions, Outcome: k.Outcome}
			if findingRe.MatchString(k.Finding) {
				cell.Finding = k.Finding
			}
		}
		if r := o.Response; r != nil && r.Reason != nil && r.Reason.Message != "" {
			cell.Evidence, _ = json.Marshal(map[string]string{"message": r.Reason.Message})
		} else if cr := o.Crash; cr != nil {
			cell.Evidence, _ = json.Marshal(map[string]any{"exit_code": cr.ExitCode, "signal": cr.Signal, "reason": cr.Reason})
		}
		m.Cells = append(m.Cells, cell)
		m.Summary[strings.ReplaceAll(a.Check, "-", "_")]++
	}
	m.CrossSDK = crossSDK(m)
	m.NotExercised = notExercised(res, cols, m.Cells)
	m.Unread = res.Unread()
	return m
}

// fingerprint is a short, canonical rendering of what the SDK produced when it accepted, so that accepting
// columns can be told apart by value. It covers only the facts every SDK reports in the same shape: L0 the
// re-encoding hash; L1 {transactions, operations, tx_hashes, focus.tx_hash, focus.derived} for a ledger and
// {tx_hash, operations, derived} for any other value, where derived keeps only the keys the manifest states for
// the variant (derived.l1; drivers may report more, and an unstated key is not comparable); L2 the pinpoints sorted by path (or the projection);
// L3 {map_entries, bytes_preserved, reencoded_sha256}; L4 {value, xdr_hex}. Values go through canon and the
// result is canonical JSON (sorted keys), so key order and number spelling do not split classes.
func fingerprint(o *conform.Observation) string {
	if o.Outcome != "ok" && o.Outcome != "diverge" || o.Response == nil || o.Response.Actual == nil {
		return ""
	}
	a := o.Response.Actual
	var v any
	switch o.Cell.Level {
	case "L0":
		if a.ReencodedSHA256 != nil {
			v = *a.ReencodedSHA256
		}
	case "L1":
		ob := a.Object
		if ob == nil {
			break
		}
		m := map[string]any{}
		put := func(k string, x any, present bool) {
			if present {
				m[k] = x
			}
		}
		if o.Cell.Variant != nil && o.Cell.Variant.XDRType == conform.LedgerXDRType {
			put("transactions", deref64(ob.Transactions), ob.Transactions != nil)
			put("operations", deref64(ob.Operations), ob.Operations != nil)
			put("tx_hashes", ob.TxHashes, ob.TxHashes != nil)
			if f := ob.Focus; f != nil {
				put("focus.tx_hash", strPtr(f.TxHash), f.TxHash != nil)
				put("focus.derived", statedDerived(f.Derived, o.Cell.Variant), f.Derived != nil)
			}
		} else {
			put("tx_hash", strPtr(ob.TxHash), ob.TxHash != nil)
			put("operations", deref64(ob.Operations), ob.Operations != nil)
			put("derived", statedDerived(ob.Derived, o.Cell.Variant), ob.Derived != nil)
		}
		v = m
	case "L2":
		if a.Projection != nil {
			v = a.Projection
			break
		}
		ps := append([]conform.PinpointResult(nil), a.Pinpoints...)
		sort.Slice(ps, func(i, j int) bool { return deref(ps[i].Path) < deref(ps[j].Path) })
		list := []any{}
		for _, p := range ps {
			var val any
			if p.Value != nil {
				decodeNumber(p.Value, &val)
			}
			list = append(list, map[string]any{"path": deref(p.Path), "found": p.Found != nil && *p.Found, "value": val})
		}
		v = list
	case "L3":
		if n := a.Native; n != nil {
			v = map[string]any{"map_entries": n.MapEntries, "bytes_preserved": n.BytesPreserved, "reencoded_sha256": n.ReencodedSHA256}
		}
	case "spec":
		if s := a.Spec; s != nil {
			v = s.Entries
		}
	case conform.JSONLevel:
		// Canonical JSON (keys sorted, minimal escaping), hashed by the driver: bindings agree when their
		// JSON is the same value.
		if j := a.JSON; j != nil && j.JSONSHA256 != nil {
			v = *j.JSONSHA256
		}
	case "L4":
		if p := a.API; p != nil {
			m := map[string]any{}
			if p.Value != nil {
				var val any
				decodeNumber(p.Value, &val)
				m["value"] = val
			}
			if p.XDRHex != nil {
				m["xdr_hex"] = *p.XDRHex
			}
			v = m
		}
	}
	if v == nil {
		return ""
	}
	b, err := json.Marshal(canon(roundTrip(v)))
	if err != nil {
		return ""
	}
	if len(b) <= 72 {
		return string(b)
	}
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:8])
}

// statedDerived keeps the derived facts whose keys the variant's derived.l1 states.
func statedDerived(d map[string]string, v *manifest.Variant) map[string]string {
	out := map[string]string{}
	if v == nil {
		return out
	}
	l1 := derivedMap(v.Derived, "l1")
	for k, x := range d {
		if _, ok := l1[k]; ok {
			out[k] = x
		}
	}
	return out
}

// roundTrip turns a Go value into its generic JSON form (maps, slices, json.Number), so canon sees one shape.
func roundTrip(v any) any {
	b, err := json.Marshal(v)
	if err != nil {
		return v
	}
	var out any
	if decodeNumber(b, &out) != nil {
		return v
	}
	return out
}

func deref64(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// LatestColumns returns, per SDK and major version line, the highest-version column (all its profiles): the
// latest release of each SDK plus its older lines (the JS 16.x LTS line), as the cross-SDK table and the
// readiness view use them. The stub is not an SDK and is left out.
func LatestColumns(cols []MatrixColumn) map[string]bool {
	best := map[string]string{} // sdk/major -> version
	for _, c := range cols {
		if c.Kind == "selftest" {
			continue
		}
		k := sdkLine(c)
		if b, ok := best[k]; !ok || cmpOrZero(c.Version, b) > 0 {
			best[k] = c.Version
		}
	}
	out := map[string]bool{}
	for _, c := range cols {
		if v, ok := best[sdkLine(c)]; ok && v == c.Version {
			out[c.ID] = true
		}
	}
	return out
}

// sdkLine is a column's SDK and major version line; a source build (build metadata) is a line of its own.
func sdkLine(c MatrixColumn) string {
	k := c.SDK + "/" + majorLine(c.Version)
	if i := strings.IndexByte(c.Version, '+'); i >= 0 {
		k += c.Version[i:]
	}
	return k
}

func majorLine(v string) string {
	p, err := parseVersion(v)
	if err != nil {
		return v
	}
	return fmt.Sprint(p.nums[0])
}

func cmpOrZero(a, b string) int {
	d, _ := CompareVersions(a, b)
	return d
}

// latestPerSDK is one column per SDK line: its highest version, first profile. A version with build metadata
// (a source build, `30.0.0+ebec5fb1c76e` for a crate's main branch) is a line of its own: semver gives build
// metadata no order, so folding the build into its release would leave it out of the comparison and hide a
// difference that only the source build has.
func latestPerSDK(cols []MatrixColumn) map[string]bool {
	best := map[string]MatrixColumn{}
	for _, c := range cols {
		if c.Kind == "selftest" {
			continue
		}
		line := c.SDK
		if i := strings.IndexByte(c.Version, '+'); i >= 0 {
			line += c.Version[i:]
		}
		b, ok := best[line]
		if !ok || cmpOrZero(c.Version, b.Version) > 0 || (c.Version == b.Version && c.ID < b.ID) {
			best[line] = c
		}
	}
	out := map[string]bool{}
	for _, c := range best {
		out[c.ID] = true
	}
	return out
}

func crossSDK(m *Matrix) []CrossSDK {
	latest := latestPerSDK(m.Columns)
	group := map[string]*CrossSDK{}
	var keys []string
	for _, c := range m.Cells {
		if !latest[c.Column] || c.Verdict == "n_a" {
			continue
		}
		k := c.Entry + " " + c.Variant + " " + c.Level
		x := group[k]
		if x == nil {
			x = &CrossSDK{Entry: c.Entry, Variant: c.Variant, Level: c.Level, Classes: map[string][]string{}}
			group[k] = x
			keys = append(keys, k)
		}
		class := c.Outcome
		switch c.Outcome {
		case "ok", "diverge":
			class = "accept"
			if c.Value != "" {
				class = "accept:" + c.Value
			}
		}
		x.Classes[class] = append(x.Classes[class], c.Column)
	}
	sort.Strings(keys)
	out := []CrossSDK{}
	for _, k := range keys {
		x := group[k]
		total := 0
		for _, cs := range x.Classes {
			sort.Strings(cs)
			total += len(cs)
		}
		if total < 2 {
			continue
		}
		// A column that accepts but reports no comparable value (stellar-core at L0 does not re-encode) agrees
		// with a single valued acceptance.
		n := len(x.Classes)
		if _, bare := x.Classes["accept"]; bare && n == 2 {
			for k := range x.Classes {
				if strings.HasPrefix(k, "accept:") {
					n = 1
				}
			}
		}
		x.Agree = n == 1
		out = append(out, *x)
	}
	return out
}

func notExercised(res *conform.Result, cols map[string]*conform.Column, cells []Cell) []NotExercised {
	entries := map[string]bool{}
	var list []NotExercised
	for _, o := range res.Observations {
		e := o.Cell.Entry
		if entries[e.ID] || e.Conformance == nil {
			continue
		}
		entries[e.ID] = true
		for _, k := range e.Conformance.KnownDivergences {
			if k.Level == "replay" {
				continue
			}
			targeted := false
			inside := map[string]bool{}
			for _, c := range cols {
				if c.Target != k.Target {
					continue
				}
				targeted = true
				sandbox, _ := conform.SandboxFor(e, c)
				if ok, err := InRange(c.Version, k.Versions); err == nil && ok && conform.ProfileCovers(k.Profile, c.Profile, sandbox) {
					inside[c.ID] = true
				}
			}
			ne := NotExercised{Entry: e.ID, Target: k.Target, Versions: k.Versions, Level: k.Level, Observed: k.Observed}
			switch {
			case !targeted:
			case len(inside) == 0:
				ne.Why = NoColumnInRange
				list = append(list, ne)
			default:
				judged := false
				for _, c := range cells {
					if c.Entry == e.ID && inside[c.Column] && (k.Level == "" || k.Level == c.Level) && c.Verdict != "n_a" {
						judged = true
						break
					}
				}
				if !judged {
					ne.Why = AllCellsNA
					list = append(list, ne)
				}
			}
		}
	}
	if list == nil {
		list = []NotExercised{}
	}
	return list
}

// Write writes matrix.json, matrix.md and cross-sdk.md into dir.
func (m *Matrix) Write(dir string) error {
	b, err := json.MarshalIndent(m, "", " ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, MatrixFile), append(b, '\n'), 0o644); err != nil {
		return err
	}
	f, err := os.Create(filepath.Join(dir, MarkdownFile))
	if err != nil {
		return err
	}
	m.FullMarkdown(f)
	if err := f.Close(); err != nil {
		return err
	}
	f, err = os.Create(filepath.Join(dir, CrossSDKFile))
	if err != nil {
		return err
	}
	m.CrossSDKMarkdown(f)
	if err := f.Close(); err != nil {
		return err
	}
	f, err = os.Create(filepath.Join(dir, SummaryFile))
	if err != nil {
		return err
	}
	m.SummaryMarkdown(f)
	return f.Close()
}

// ReadMatrix reads a matrix file strictly.
func ReadMatrix(path string) (*Matrix, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m Matrix
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if m.Schema != MatrixSchema {
		return nil, fmt.Errorf("%s: schema %q, want %q", path, m.Schema, MatrixSchema)
	}
	return &m, nil
}

// Failing returns the cells `xdrcheck conform check` fails on.
func (m *Matrix) Failing() []Cell {
	var out []Cell
	for _, c := range m.Cells {
		if FailingCheck(c.Check) {
			out = append(out, c)
		}
	}
	return out
}

// Change is one difference between two matrices.
type Change struct {
	Key       string
	From, To  *Cell // nil when the cell is absent on that side
	WhatMoved string
}

// Diff lists the cells whose verdict (or check) differs between a and b, and cells present on one side only.
func Diff(a, b *Matrix) []Change {
	idx := func(m *Matrix) map[string]*Cell {
		out := map[string]*Cell{}
		for i := range m.Cells {
			out[m.Cells[i].Key()] = &m.Cells[i]
		}
		return out
	}
	ia, ib := idx(a), idx(b)
	keys := map[string]bool{}
	for k := range ia {
		keys[k] = true
	}
	for k := range ib {
		keys[k] = true
	}
	var sorted []string
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	var out []Change
	for _, k := range sorted {
		x, y := ia[k], ib[k]
		switch {
		case x == nil:
			out = append(out, Change{Key: k, To: y, WhatMoved: "added"})
		case y == nil:
			out = append(out, Change{Key: k, From: x, WhatMoved: "removed"})
		case x.Verdict != y.Verdict:
			out = append(out, Change{Key: k, From: x, To: y, WhatMoved: "verdict"})
		case x.Check != y.Check:
			out = append(out, Change{Key: k, From: x, To: y, WhatMoved: "check"})
		}
	}
	return out
}

// Readiness is the matrix restricted to entries introduced at protocol p and to the latest column of each SDK
// major line: the readiness matrix published before a mainnet vote (docs/maintenance.md §5, step 9).
func (m *Matrix) Readiness(p int) *Matrix {
	r := *m
	keep := map[string]bool{}
	r.Entries = nil
	for _, e := range m.Entries {
		if e.ProtocolIntroduced == p {
			keep[e.ID] = true
			r.Entries = append(r.Entries, e)
		}
	}
	latest := LatestColumns(m.Columns)
	r.Columns = nil
	for _, c := range m.Columns {
		if latest[c.ID] {
			r.Columns = append(r.Columns, c)
		}
	}
	r.Cells = nil
	for _, c := range m.Cells {
		if keep[c.Entry] && latest[c.Column] {
			r.Cells = append(r.Cells, c)
		}
	}
	return &r
}

// Label is a cell's Markdown rendering: ok, rej, WRONG, CRASH or n/a, bold when the verdict is a failure,
// with the check when it is not plain.
func Label(c *Cell) string {
	var s string
	switch {
	case c.Verdict == "n_a" && c.BlockedByL0:
		s = "n/a (L0)"
	case c.Verdict == "n_a" && c.OutOfReach:
		s = "–" // refused cleanly: the variant needs XDR newer than the column's SDK (see the legend)
	case c.Verdict == "n_a":
		s = "n/a"
	case c.Verdict == "crash":
		s = "**CRASH**"
	case c.Verdict == "schema_invalid":
		s = "**SCHEMA**"
	case c.Verdict == "roundtrip_changed":
		s = "**ROUNDTRIP**"
	case c.Verdict == "roundtrip_refused":
		s = "**rej (roundtrip)**"
	case c.Verdict == "diverge" || c.Verdict == "accepts_invalid":
		s = "**WRONG**"
	case c.Verdict == "reject_valid":
		s = "**rej**"
	case c.Outcome == "reject":
		s = "rej"
	default:
		s = "ok"
	}
	switch c.Check {
	case "known":
		s += " (known)"
	case "undeclared", "unexpected-conform", "known-changed":
		s += " !" + c.Check
	}
	return s
}

// Markdown renders the matrix: one table per entry group, one row per entry, variant and level, one column
// per conformance column. only, when not nil, limits the columns. Every row is shown; matrix.md itself is
// written by Write, which folds the rows where every column conforms (FullMarkdown).
func (m *Matrix) Markdown(w io.Writer, only map[string]bool) { m.markdown(w, only, false) }

// FullMarkdown renders matrix.md: the full grid, with the rows where every column conforms or is n/a folded
// into a collapsed block under each group's table, so the rows with a wrong answer, a crash or a known
// divergence are the ones in view.
func (m *Matrix) FullMarkdown(w io.Writer) { m.markdown(w, nil, true) }

// plainRow reports whether every cell of a row conforms (with a plain check) or is n/a.
func plainRow(cells map[string]*Cell) bool {
	for _, c := range cells {
		if c.Verdict != "n_a" && (c.Verdict != "conform" || c.Check != "conform") {
			return false
		}
	}
	return true
}

func (m *Matrix) markdown(w io.Writer, only map[string]bool, fold bool) {
	fmt.Fprintf(w, "# Conformance matrix\n\nCorpus %s (manifest sha256 %s). The rows that need a look, with the expected value and a repro command, are in %s.\n\n"+
		"Cells: ok, rej, **WRONG** (accepted with a wrong value or accepted what must be refused), **rej** (refused a valid input), **CRASH**, n/a; \"(known)\" marks a declared known divergence, \"!\" a cell `xdrcheck conform check` fails on. "+
		"\"–\" is a variant that needs XDR newer than the column's SDK has, refused cleanly as an undeclared union arm or enum value: expected, not a failure (%d such cells).\n",
		m.Corpus.Version, short([]byte(m.Corpus.ManifestSHA256)), SummaryFile, m.SchemaGated())
	if fold {
		fmt.Fprintf(w, "\nUnder each group, the rows where every column conforms or is n/a are folded into a collapsed block.\n")
	}
	var cols []string
	for _, c := range m.Columns {
		if only == nil || only[c.ID] {
			cols = append(cols, c.ID)
		}
	}
	ent := map[string]MatrixEntry{}
	for _, e := range m.Entries {
		ent[e.ID] = e
	}
	type rowKey struct{ entry, variant, level string }
	rows := map[rowKey]map[string]*Cell{}
	var order []rowKey
	for i := range m.Cells {
		c := &m.Cells[i]
		if only != nil && !only[c.Column] {
			continue
		}
		k := rowKey{c.Entry, c.Variant, c.Level}
		if rows[k] == nil {
			rows[k] = map[string]*Cell{}
			order = append(order, k)
		}
		rows[k][c.Column] = c
	}
	header := func() {
		fmt.Fprint(w, "\n| entry | variant | level | reference → expected |")
		for _, c := range cols {
			fmt.Fprintf(w, " %s |", c)
		}
		fmt.Fprint(w, "\n|---|---|---|---|")
		for range cols {
			fmt.Fprint(w, "---|")
		}
		fmt.Fprintln(w)
	}
	line := func(k rowKey) {
		e := ent[k.entry]
		ref := e.Reference + " → " + e.Expected
		if e.CoreLenient {
			ref += " (core-lenient)"
		}
		fmt.Fprintf(w, "| `%s` | %s | %s | %s |", k.entry, orDash(k.variant), k.level, ref)
		for _, c := range cols {
			if cell := rows[k][c]; cell != nil {
				fmt.Fprintf(w, " %s |", Label(cell))
			} else {
				fmt.Fprint(w, " |")
			}
		}
		fmt.Fprintln(w)
	}
	// Rows by group, in report order.
	var groups []string
	byGroup := map[string][]rowKey{}
	for _, k := range order {
		g, _, _ := strings.Cut(k.entry, "/")
		if byGroup[g] == nil {
			groups = append(groups, g)
		}
		byGroup[g] = append(byGroup[g], k)
	}
	for _, g := range groups {
		var shown, folded []rowKey
		for _, k := range byGroup[g] {
			if fold && plainRow(rows[k]) {
				folded = append(folded, k)
			} else {
				shown = append(shown, k)
			}
		}
		fmt.Fprintf(w, "\n## %s\n", g)
		if len(shown) > 0 {
			header()
			for _, k := range shown {
				line(k)
			}
		} else {
			fmt.Fprintf(w, "\nEvery row conforms or is n/a.\n")
		}
		if len(folded) > 0 {
			fmt.Fprintf(w, "\n<details><summary>%d rows where every column conforms or is n/a</summary>\n", len(folded))
			header()
			for _, k := range folded {
				line(k)
			}
			fmt.Fprintf(w, "\n</details>\n")
		}
	}
	if len(m.NotExercised) > 0 {
		fmt.Fprintf(w, "\n## Known divergences the run did not assert\n\n| entry | target | versions | level | observed | why |\n|---|---|---|---|---|---|\n")
		for _, n := range m.NotExercised {
			fmt.Fprintf(w, "| `%s` | %s | `%s` | %s | %s | %s |\n", n.Entry, n.Target, n.Versions, orDash(n.Level), orDash(n.Observed), n.Why)
		}
	}
	if len(m.Infrastructure) > 0 {
		fmt.Fprintf(w, "\n## Infrastructure problems\n\n")
		for _, p := range m.Infrastructure {
			fmt.Fprintf(w, "- %s\n", p)
		}
	}
	fmt.Fprintf(w, "\n## Summary\n\n")
	var ks []string
	for k := range m.Summary {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	for _, k := range ks {
		fmt.Fprintf(w, "- %s: %d\n", k, m.Summary[k])
	}
}

// CrossSDKMarkdown renders "diverges from each other": entries where the latest columns disagree, each with what
// the corpus expects, the CAPs, which columns the corpus says are wrong, the declared divergence or finding,
// and a repro command.
func (m *Matrix) CrossSDKMarkdown(w io.Writer) {
	fmt.Fprintf(w, "# Cross-SDK comparison\n\nThe latest column of each SDK, per entry, variant and level, grouped by outcome class (accepting columns by the value they produced). Only disagreements are listed. **Expected** comes from the corpus, never from an SDK; **wrong** names the columns whose answer differs from it; **bug class** is the entry's validity and flags (docs/manifest.md §9.5).\n\n"+
		"| entry | variant | level | CAPs | bug class | expected | classes | wrong | divergence or finding | repro |\n|---|---|---|---|---|---|---|---|---|---|\n")
	caps := map[string][]int{}
	class := map[string]string{}
	for _, e := range m.Entries {
		caps[e.ID] = e.Caps
		class[e.ID] = BugClass(&e)
	}
	cells := map[string]*Cell{}
	for i := range m.Cells {
		c := &m.Cells[i]
		cells[c.Key()] = c
	}
	n := 0
	for _, x := range m.CrossSDK {
		if x.Agree {
			continue
		}
		n++
		var cls []string
		for k := range x.Classes {
			cls = append(cls, k)
		}
		sort.Strings(cls)
		var parts, wrong, all, cites []string
		seen := map[string]bool{}
		for _, k := range cls {
			parts = append(parts, fmt.Sprintf("%s: %s", k, strings.Join(x.Classes[k], ", ")))
			for _, col := range x.Classes[k] {
				all = append(all, col)
				c := cells[(&Cell{Entry: x.Entry, Variant: x.Variant, Column: col, Level: x.Level}).Key()]
				if c == nil || !FailureVerdict(c.Verdict) {
					continue
				}
				wrong = append(wrong, col)
				cite := Status(c)
				if !seen[cite] {
					seen[cite] = true
					cites = append(cites, cite)
				}
			}
		}
		sort.Strings(wrong)
		sort.Strings(all)
		repro := all
		if len(wrong) > 0 {
			repro = wrong
		}
		fmt.Fprintf(w, "| `%s` | %s | %s | %s | %s | %s | %s | %s | %s | `%s` |\n", x.Entry, orDash(x.Variant), x.Level, capList(caps[x.Entry]), cellText(class[x.Entry]),
			cellText(m.Expectations[RowKey(x.Entry, x.Variant, x.Level)]), cellText(strings.Join(parts, "; ")),
			orDash(strings.Join(wrong, ", ")), cellText(orDash(strings.Join(cites, "; "))), Repro(x.Entry, x.Level, repro))
	}
	if n == 0 {
		fmt.Fprintln(w, "| (none) | | | | | | | | | |")
	}
	m.jsonMarkdown(w)
}

// cellText makes text safe inside a Markdown table cell.
func cellText(s string) string {
	if s == "" {
		return "-"
	}
	return strings.ReplaceAll(strings.ReplaceAll(s, "|", "\\|"), "\n", " ")
}

// jsonMarkdown lists the json level's three kinds of difference apart, when the run has json cells:
// schema-invalid (a converter's JSON breaks its own schema), round-trip-changed (its JSON does not come back to
// the input bytes) and cross-binding-different (converters accept the bytes but write different canonical JSON).
// A cell matched by a known divergence is cited with its reference, so it does not read as new.
func (m *Matrix) jsonMarkdown(w io.Writer) {
	has := false
	for _, c := range m.Cells {
		has = has || c.Level == conform.JSONLevel
	}
	if !has {
		return
	}
	list := func(title, verdict string) {
		fmt.Fprintf(w, "\n### %s\n\n", title)
		k := 0
		for _, c := range m.Cells {
			if c.Level != conform.JSONLevel || c.Verdict != verdict {
				continue
			}
			k++
			cite := "**new**"
			if c.KnownDivergence != nil {
				cite = "known: " + c.KnownDivergence.Reference
			}
			fmt.Fprintf(w, "- `%s` %s — %s (%s)\n", c.Entry, orDash(c.Variant), c.Column, cite)
		}
		if k == 0 {
			fmt.Fprintln(w, "(none)")
		}
	}
	fmt.Fprintf(w, "\n## XDR-JSON (json level)\n")
	list("Schema-invalid: the JSON breaks the converter's own schema", "schema_invalid")
	list("Round-trip-changed: the JSON comes back to other bytes", "roundtrip_changed")
	list("Round-trip-refused: the converter refuses the JSON it wrote", "roundtrip_refused")
	fmt.Fprintf(w, "\n### Cross-binding-different: converters write different canonical JSON\n\n")
	k := 0
	for _, x := range m.CrossSDK {
		if x.Level != conform.JSONLevel || x.Agree {
			continue
		}
		k++
		var cls []string
		for c := range x.Classes {
			cls = append(cls, c)
		}
		sort.Strings(cls)
		var parts []string
		for _, c := range cls {
			parts = append(parts, fmt.Sprintf("%s: %s", c, strings.Join(x.Classes[c], ", ")))
		}
		fmt.Fprintf(w, "- `%s` %s — %s\n", x.Entry, orDash(x.Variant), strings.Join(parts, "; "))
	}
	if k == 0 {
		fmt.Fprintln(w, "(none)")
	}
}

// Package siblings looks for a defect found in one SDK in the other SDK families, de-duplicates each hit against
// the target's upstream tracker, and drafts one issue body per affected SDK (`xdrcheck conform siblings`).
//
// The defect's signature is the set of corpus cells (entry, variant, level) on which the original SDK shows a
// failing verdict, with the verdicts it shows there: the cells of a finding record's entries, or the cells
// that cite a known divergence. An SDK family is affected when the latest version in the conformance matrix
// shows one of those verdicts on one of those cells; when only an older version does, the family has already
// fixed it. An SDK the kit has no driver for is checked from manual evidence (Manual), and every draft and
// record made from such evidence says so.
//
// For each affected family the upstream tracker decides the kind of draft (the findings process, section on
// de-duplication): an open item already describing the defect gets an evidence comment; a merged fix that no
// release contains gets a release request; otherwise a new issue. Only items a person has confirmed describe
// the same defect count: those the matrix's known divergences, the finding records and the manual evidence
// cite, and those given with --confirm. Search hits are shown to the reviewer as possible duplicates.
//
// Unreported defects stay private: a new-issue draft (no confirmed open item or unreleased fix tracks the defect
// in that project), and every draft for a defect whose original is not public, is written to the overlay only.
// A public draft or record never names an overlay record.
//
// Nothing here files, comments on or reacts to anything, and nothing starts a process: tracker access is
// unauthenticated HTTP GET (Tracker, GitHub), and the command that would file a draft is returned as text for
// a person to run after the user has approved it.
package siblings

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/tolgayayci/xdrcheck/go/internal/conform/verdict"
	"github.com/tolgayayci/xdrcheck/go/internal/findings"
)

// Family is one SDK family: the sdk name the matrix columns use and its upstream project.
type Family struct {
	SDK       string
	Project   string
	Package   string
	Ecosystem string
	Component string // record component: sdk or xdr-library
	Driver    bool   // the kit has a conformance driver for it
}

// Families are the SDK families the kit knows. A family without a driver is checked only from manual evidence.
var Families = []Family{
	{SDK: "js", Project: "stellar/js-stellar-sdk", Package: "@stellar/stellar-sdk", Ecosystem: "npm", Component: "sdk", Driver: true},
	{SDK: "go", Project: "stellar/go-stellar-sdk", Package: "github.com/stellar/go-stellar-sdk", Ecosystem: "go", Component: "sdk", Driver: true},
	{SDK: "python", Project: "StellarCN/py-stellar-base", Package: "stellar-sdk", Ecosystem: "pypi", Component: "sdk", Driver: true},
	{SDK: "java", Project: "lightsail-network/java-stellar-sdk", Package: "network.lightsail:stellar-sdk", Ecosystem: "maven", Component: "sdk", Driver: true},
	{SDK: "rust", Project: "stellar/rs-stellar-xdr", Package: "stellar-xdr", Ecosystem: "crates", Component: "xdr-library", Driver: true},
	{SDK: "dotnet", Project: "Beans-BV/dotnet-stellar-sdk", Package: "stellar-dotnet-sdk", Ecosystem: "nuget", Component: "sdk"},
}

func familyBySDK(sdk string) (Family, bool) {
	for _, f := range Families {
		if f.SDK == sdk {
			return f, true
		}
	}
	return Family{}, false
}

func familyByProject(project string) (Family, bool) {
	for _, f := range Families {
		if strings.EqualFold(f.Project, project) {
			return f, true
		}
	}
	return Family{}, false
}

// Key is one corpus cell of the signature.
type Key struct{ Entry, Variant, Level string }

func (k Key) String() string {
	v := k.Variant
	if v == "" {
		v = "-"
	}
	return k.Entry + " " + v + " " + k.Level
}

// Signature is the defect as the original SDK shows it.
type Signature struct {
	Original        *findings.Record // nil when started from a known divergence no record cites
	OriginalOverlay bool             // the original record lives in the private overlay
	Reference       string           // the known divergence's upstream reference, when started from one
	Project         string           // the original's upstream project
	SourceSDKs      map[string]bool
	Keys            []Key
	Classes         map[Key][]string // the failing verdicts the original shows on each cell
	Expected        map[Key]string   // the record's expected text per cell, when there is a record
	Public          bool             // the original defect is public upstream
}

// Name is how the signature is referred to in output: the record ID or the reference.
func (s *Signature) Name() string {
	if s.Original != nil {
		return s.Original.ID
	}
	return s.Reference
}

func (s *Signature) has(k Key, verdict string) bool {
	for _, v := range s.Classes[k] {
		if v == verdict {
			return true
		}
	}
	return false
}

func failingVerdict(v string) bool { return v != "" && v != "conform" && v != "n_a" }

// columnSDKs maps column IDs to their sdk name, for SDK columns only.
func columnSDKs(m *verdict.Matrix) map[string]verdict.MatrixColumn {
	out := map[string]verdict.MatrixColumn{}
	for _, c := range m.Columns {
		if c.Kind == "sdk" {
			out[c.ID] = c
		}
	}
	return out
}

// ParseRowID splits a conformance report row ID, conform:<entry>:<variant|->:<column>:<level>; the column may
// itself contain a colon (a profile).
func ParseRowID(row string) (k Key, column string, ok bool) {
	rest, found := strings.CutPrefix(row, "conform:")
	if !found {
		return Key{}, "", false
	}
	parts := strings.Split(rest, ":")
	if len(parts) < 4 {
		return Key{}, "", false
	}
	k = Key{Entry: parts[0], Variant: parts[1], Level: parts[len(parts)-1]}
	if k.Variant == "-" {
		k.Variant = ""
	}
	return k, strings.Join(parts[2:len(parts)-1], ":"), true
}

var levelPattern = regexp.MustCompile(`^L[0-4]$`)

// FromFinding builds the signature of a finding record: the cells of its entries on which its SDK's columns
// fail in the matrix (restricted to the columns its report rows name, when it names any).
func FromFinding(m *verdict.Matrix, l *findings.Loaded) (*Signature, error) {
	rec := l.Record
	fam, ok := familyByProject(rec.Target.Project)
	if !ok || !fam.Driver {
		return nil, fmt.Errorf("%s is about %s, which has no conformance driver; siblings start from an SDK finding", rec.ID, rec.Target.Project)
	}
	sig := &Signature{Original: rec, OriginalOverlay: l.Overlay, Project: rec.Target.Project, SourceSDKs: map[string]bool{fam.SDK: true},
		Classes: map[Key][]string{}, Expected: map[Key]string{}, Public: !l.Overlay && rec.Visibility == "public"}
	only := map[string]bool{}
	if rec.Evidence != nil {
		for _, r := range rec.Evidence.ReportRows {
			if _, col, ok := ParseRowID(r); ok {
				only[col] = true
			}
		}
	}
	cols := columnSDKs(m)
	for _, e := range rec.Entries {
		if !levelPattern.MatchString(e.Scope) {
			continue
		}
		k := Key{Entry: e.ID, Variant: e.Variant, Level: e.Scope}
		if _, dup := sig.Expected[k]; dup {
			continue
		}
		var classes []string
		for _, c := range m.Cells {
			col, isSDK := cols[c.Column]
			if !isSDK || col.SDK != fam.SDK || c.Entry != k.Entry || c.Variant != k.Variant || c.Level != k.Level || !failingVerdict(c.Verdict) {
				continue
			}
			if len(only) > 0 && !only[c.Column] {
				continue
			}
			classes = appendUnique(classes, c.Verdict)
		}
		if len(classes) == 0 {
			continue
		}
		sig.Keys = append(sig.Keys, k)
		sig.Classes[k] = classes
		sig.Expected[k] = e.Expected
	}
	if len(sig.Keys) == 0 {
		return nil, fmt.Errorf("%s: the matrix shows no failing %s cell on any of the record's entries; run the record's columns first", rec.ID, fam.SDK)
	}
	return sig, nil
}

// FromDivergence builds the signature of a known divergence: every failing cell that cites reference.
func FromDivergence(m *verdict.Matrix, reference string) (*Signature, error) {
	sig := &Signature{Reference: reference, SourceSDKs: map[string]bool{}, Classes: map[Key][]string{}, Expected: map[Key]string{},
		Public: strings.HasPrefix(reference, "https://")}
	cols := columnSDKs(m)
	for _, c := range m.Cells {
		col, isSDK := cols[c.Column]
		if !isSDK || c.KnownDivergence == nil || c.KnownDivergence.Reference != reference || !failingVerdict(c.Verdict) {
			continue
		}
		k := Key{Entry: c.Entry, Variant: c.Variant, Level: c.Level}
		if _, seen := sig.Classes[k]; !seen {
			sig.Keys = append(sig.Keys, k)
		}
		sig.Classes[k] = appendUnique(sig.Classes[k], c.Verdict)
		sig.SourceSDKs[col.SDK] = true
	}
	if len(sig.Keys) == 0 {
		return nil, fmt.Errorf("no failing cell in the matrix cites the known divergence %s", reference)
	}
	if repo, _, _, ok := ParseItemURL(reference); ok {
		sig.Project = repo
	}
	return sig, nil
}

func appendUnique(list []string, s string) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}

// Observation is one cell of a sibling family.
type Observation struct {
	Key
	Column    string
	Version   string
	Verdict   string
	Outcome   string
	Reason    string
	Message   string
	Observed  string // manual evidence: what was seen or read
	Reference string // the cell's known divergence reference
	Status    string // the known divergence's status
	Manual    bool
}

// RowID is the report row ID of a matrix cell (manual observations have none).
func (o *Observation) RowID() string {
	if o.Manual {
		return ""
	}
	v := o.Variant
	if v == "" {
		v = "-"
	}
	return fmt.Sprintf("conform:%s:%s:%s:%s", o.Entry, v, o.Column, o.Level)
}

// Statuses of a family.
const (
	Affected     = "affected"      // the latest version shows the defect
	Fixed        = "fixed"         // an older version shows it, the latest does not
	NotAffected  = "not-affected"  // exercised, never shows it
	NotExercised = "not-exercised" // every signature cell is n_a or absent
	NoColumn     = "no-column"     // no column in the matrix and no manual evidence
)

// Result is the state of one sibling family.
type Result struct {
	Family        Family
	Status        string
	Latest        string   // the latest version checked
	LatestColumns []string // its columns (or the manual pseudo column)
	Matches       []Observation
	Earlier       []Observation // older versions showing the defect
	Other         []Observation // latest-version cells failing with a different verdict
	Manual        *Manual
	Record        *findings.Loaded // an existing record for this family and defect
}

// Analyse checks every family other than the original's against the signature.
func Analyse(sig *Signature, m *verdict.Matrix, manual []*Manual, store *findings.Store) ([]*Result, error) {
	bySDK := map[string][]verdict.MatrixColumn{}
	for _, c := range m.Columns {
		if c.Kind == "sdk" {
			bySDK[c.SDK] = append(bySDK[c.SDK], c)
		}
	}
	cells := map[string]*verdict.Cell{}
	for i := range m.Cells {
		c := &m.Cells[i]
		cells[Key{c.Entry, c.Variant, c.Level}.String()+" "+c.Column] = c
	}
	manualBySDK := map[string]*Manual{}
	for _, mv := range manual {
		switch {
		case sig.SourceSDKs[mv.SDK]:
			return nil, fmt.Errorf("%s: manual evidence for %s, the SDK the defect was found in", mv.Path, mv.SDK)
		case len(bySDK[mv.SDK]) > 0:
			return nil, fmt.Errorf("%s: %s has columns in the matrix; the matrix is its evidence", mv.Path, mv.SDK)
		case manualBySDK[mv.SDK] != nil:
			return nil, fmt.Errorf("%s: a second manual evidence file for %s", mv.Path, mv.SDK)
		}
		if f, ok := familyBySDK(mv.SDK); ok && !strings.EqualFold(f.Project, mv.Project) {
			return nil, fmt.Errorf("%s: sdk %s is %s, not %s", mv.Path, mv.SDK, f.Project, mv.Project)
		}
		manualBySDK[mv.SDK] = mv
	}

	var sdks []string
	seen := map[string]bool{}
	for _, f := range Families {
		sdks = append(sdks, f.SDK)
		seen[f.SDK] = true
	}
	var extra []string
	for s := range bySDK {
		if !seen[s] {
			extra = append(extra, s)
			seen[s] = true
		}
	}
	for s := range manualBySDK {
		if !seen[s] {
			extra = append(extra, s)
		}
	}
	sort.Strings(extra)
	sdks = append(sdks, extra...)

	var out []*Result
	for _, sdk := range sdks {
		if sig.SourceSDKs[sdk] {
			continue
		}
		fam, known := familyBySDK(sdk)
		var r *Result
		switch {
		case manualBySDK[sdk] != nil:
			mv := manualBySDK[sdk]
			if !known {
				fam = Family{SDK: sdk, Project: mv.Project, Package: mv.Package, Ecosystem: mv.Ecosystem, Component: "sdk"}
			}
			fam.Package, fam.Ecosystem = mv.Package, mv.Ecosystem
			r = analyseManual(sig, fam, mv)
		case len(bySDK[sdk]) > 0:
			if !known {
				return nil, fmt.Errorf("the matrix has columns for sdk %q, which has no known upstream project", sdk)
			}
			r = analyseColumns(sig, fam, bySDK[sdk], cells)
		default:
			r = &Result{Family: fam, Status: NoColumn}
		}
		if store != nil {
			r.Record = existingRecord(store, sig, r)
		}
		out = append(out, r)
	}
	return out, nil
}

func analyseColumns(sig *Signature, fam Family, cols []verdict.MatrixColumn, cells map[string]*verdict.Cell) *Result {
	latest := cols[0].Version
	for _, c := range cols[1:] {
		if d, err := verdict.CompareVersions(c.Version, latest); err == nil && d > 0 || err != nil && c.Version > latest {
			latest = c.Version
		}
	}
	r := &Result{Family: fam, Latest: latest}
	exercised := false
	sort.Slice(cols, func(i, j int) bool { return cols[i].ID < cols[j].ID })
	for _, c := range cols {
		if c.Version == latest {
			r.LatestColumns = append(r.LatestColumns, c.ID)
		}
	}
	for _, k := range sig.Keys {
		for _, c := range cols {
			cell := cells[k.String()+" "+c.ID]
			if cell == nil {
				continue
			}
			o := Observation{Key: k, Column: c.ID, Version: c.Version, Verdict: cell.Verdict, Outcome: cell.Outcome, Reason: cell.Reason}
			if cell.KnownDivergence != nil {
				o.Reference, o.Status = cell.KnownDivergence.Reference, cell.KnownDivergence.Status
			}
			if len(cell.Evidence) > 0 {
				o.Message = evidenceMessage(cell.Evidence)
			}
			isLatest := c.Version == latest
			switch {
			case sig.has(k, cell.Verdict) && isLatest:
				r.Matches = append(r.Matches, o)
			case sig.has(k, cell.Verdict):
				r.Earlier = append(r.Earlier, o)
			case isLatest && failingVerdict(cell.Verdict):
				r.Other = append(r.Other, o)
			}
			if isLatest && cell.Verdict != "n_a" {
				exercised = true
			}
		}
	}
	r.Status = status(r, exercised)
	return r
}

func analyseManual(sig *Signature, fam Family, mv *Manual) *Result {
	r := &Result{Family: fam, Latest: mv.Version, LatestColumns: []string{mv.Column()}, Manual: mv}
	exercised := false
	for _, k := range sig.Keys {
		for _, c := range mv.Cells {
			if c.Entry != k.Entry || c.Variant != k.Variant || c.Level != k.Level {
				continue
			}
			o := Observation{Key: k, Column: mv.Column(), Version: mv.Version, Verdict: c.Verdict, Observed: c.Observed, Manual: true}
			switch {
			case sig.has(k, c.Verdict):
				r.Matches = append(r.Matches, o)
			case failingVerdict(c.Verdict):
				r.Other = append(r.Other, o)
			}
			if c.Verdict != "n_a" {
				exercised = true
			}
		}
	}
	r.Status = status(r, exercised)
	return r
}

func status(r *Result, exercised bool) string {
	switch {
	case len(r.Matches) > 0:
		return Affected
	case len(r.Earlier) > 0:
		return Fixed
	case exercised:
		return NotAffected
	}
	return NotExercised
}

// existingRecord finds a record for the family's project that covers this defect: one in the original's
// defect group, or else the one whose entries overlap the signature most.
func existingRecord(store *findings.Store, sig *Signature, r *Result) *findings.Loaded {
	group := ""
	if sig.Original != nil {
		group = sig.Original.DefectGroup
	}
	var best *findings.Loaded
	bestN := 0
	for _, id := range store.IDs() {
		l := store.Records[id]
		rec := l.Record
		if sig.Original != nil && rec.ID == sig.Original.ID || !strings.EqualFold(rec.Target.Project, r.Family.Project) {
			continue
		}
		n := overlap(rec, sig)
		if group != "" && rec.DefectGroup == group {
			n += 1000
		}
		if n > bestN {
			best, bestN = l, n
		}
	}
	return best
}

func overlap(rec *findings.Record, sig *Signature) int {
	n := 0
	for _, e := range rec.Entries {
		if _, ok := sig.Classes[Key{e.ID, e.Variant, e.Scope}]; ok {
			n++
		}
	}
	return n
}

// Group is the defect group the siblings share: the original's, else the one the existing sibling records
// share, else one named after the original.
func Group(sig *Signature, results []*Result) string {
	if sig.Original != nil && sig.Original.DefectGroup != "" {
		return sig.Original.DefectGroup
	}
	count := map[string]int{}
	for _, r := range results {
		if r.Record != nil && r.Record.Record.DefectGroup != "" {
			count[r.Record.Record.DefectGroup]++
		}
	}
	best := ""
	for g, n := range count {
		if n > count[best] || n == count[best] && g < best {
			best = g
		}
	}
	if best != "" {
		return best
	}
	name := sig.Name()
	if repo, n, _, ok := ParseItemURL(name); ok {
		name = fmt.Sprintf("%s-%d", repo[strings.Index(repo, "/")+1:], n)
	}
	return "DG-" + strings.Trim(groupInvalid.ReplaceAllString(strings.ToLower(name), "-"), "-")
}

var groupInvalid = regexp.MustCompile(`[^a-z0-9]+`)

// errNoOverlay is returned when a draft must go to the overlay and none was given.
var errNoOverlay = errors.New("no overlay directory")

// evidenceMessage is the SDK's own error message a cell recorded, if any.
func evidenceMessage(raw []byte) string {
	var ev struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(raw, &ev) != nil {
		return ""
	}
	return ev.Message
}

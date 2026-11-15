// Package findings reads, checks and writes finding records (`xcc.finding/v1`,
// corpus/schema/finding-record.schema.json) and maps the failure rows of `xcc.report/v1` reports onto them.
//
// A finding is one defect in one target project. Its record is findings/<id>/finding.json in the public tree,
// or <overlay>/findings/<id>/finding.json in the private overlay while it is embargoed; the overlay's records
// are merged over the public ones in memory and nothing is written back to the public tree from it.
//
// Nothing in this package files, comments on or reports anything upstream, and nothing in it starts a process
// or opens a network connection: the issue command it renders is printed for a person to run.
package findings

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
)

// SchemaID is the record schema ID.
const SchemaID = "xcc.finding/v1"

// RecordFile is the record's file name inside its directory.
const RecordFile = "finding.json"

// IDPattern is the form of a finding ID.
var IDPattern = regexp.MustCompile(`^F-[0-9]{4}$`)

// Terminal reports whether a state ends the lifecycle (filed, duplicate-of, not-a-defect).
func Terminal(state string) bool {
	return state == "filed" || state == "duplicate-of" || state == "not-a-defect"
}

// Record is one finding record. Field order follows the schema, so a record written back keeps its layout.
type Record struct {
	Schema           string          `json:"schema"`
	ID               string          `json:"id"`
	Title            string          `json:"title"`
	DefectGroup      string          `json:"defect_group,omitempty"`
	Target           Target          `json:"target"`
	Component        string          `json:"component"`
	Class            string          `json:"class"`
	Severity         string          `json:"severity"`
	SeverityBasis    string          `json:"severity_basis,omitempty"`
	SecurityRelevant bool            `json:"security_relevant"`
	Visibility       string          `json:"visibility"`
	Caps             []int           `json:"caps,omitempty"`
	CapsNote         string          `json:"caps_note,omitempty"`
	Entries          []Entry         `json:"entries"`
	Location         *Location       `json:"location,omitempty"`
	Evidence         *Evidence       `json:"evidence,omitempty"`
	Reproduction     *Reproduction   `json:"reproduction,omitempty"`
	UpstreamSearch   *UpstreamSearch `json:"upstream_search,omitempty"`
	IssueDraft       *IssueDraft     `json:"issue_draft,omitempty"`
	Approval         *Approval       `json:"approval,omitempty"`
	Upstream         *Upstream       `json:"upstream,omitempty"`
	Embargo          *Embargo        `json:"embargo,omitempty"`
	Resolution       *Resolution     `json:"resolution,omitempty"`
	State            string          `json:"state"`
	History          []HistoryItem   `json:"history"`
	Siblings         []string        `json:"siblings,omitempty"`
	Related          []string        `json:"related,omitempty"`
}

// Target is the project the defect is in.
type Target struct {
	Project          string   `json:"project"`
	Package          string   `json:"package,omitempty"`
	Ecosystem        string   `json:"ecosystem,omitempty"`
	VersionsAffected string   `json:"versions_affected"`
	VersionsTested   []string `json:"versions_tested"`
	FixedIn          string   `json:"fixed_in,omitempty"`
}

// Entry is one corpus entry that demonstrates the defect; the first is the minimal reproducing entry.
type Entry struct {
	ID       string `json:"id"`
	Variant  string `json:"variant,omitempty"`
	Scope    string `json:"scope"`
	Expected string `json:"expected"`
	Observed string `json:"observed"`
}

// Location is where in source code a linter finding is.
type Location struct {
	Commit   string `json:"commit"`
	File     string `json:"file"`
	Lines    string `json:"lines,omitempty"`
	Function string `json:"function,omitempty"`
}

// Evidence is what was observed and why the expectation is right.
type Evidence struct {
	PreFix        string   `json:"pre_fix,omitempty"`
	PostFix       string   `json:"post_fix,omitempty"`
	Transcripts   []string `json:"transcripts,omitempty"`
	ReportRows    []string `json:"report_rows,omitempty"`
	ExpectedBasis string   `json:"expected_basis,omitempty"`
	// Observed is how the defect was seen: "executed", "source-reading" (read from the source, not run) or
	// "private-run" (executed, with rows only in the maintainer's private acceptance run).
	Observed string `json:"observed,omitempty"`
}

// ObservedSourceReading is the evidence.observed value of a defect read from the source and never executed.
const ObservedSourceReading = "source-reading"

// ObservedPrivateRun is the evidence.observed value of a defect executed in the maintainer's private acceptance
// run only, whose rows no public report holds.
const ObservedPrivateRun = "private-run"

// Reproduction is the independent reproduction a record needs before it leaves candidate.
type Reproduction struct {
	By     string `json:"by"`
	Date   string `json:"date"`
	Method string `json:"method,omitempty"`
	Result string `json:"result"`
}

// UpstreamSearch is the de-duplication against the target's tracker.
type UpstreamSearch struct {
	Date     string   `json:"date"`
	Queries  []string `json:"queries"`
	Result   string   `json:"result"`
	Existing string   `json:"existing,omitempty"`
}

// IssueDraft names the draft issue body and the command that would file it.
type IssueDraft struct {
	Path          string `json:"path"`
	Kind          string `json:"kind,omitempty"`
	DryRunCommand string `json:"dry_run_command,omitempty"`
}

// Approval is the user's decision to file one draft on one channel.
type Approval struct {
	By    string `json:"by"`
	Date  string `json:"date"`
	Scope string `json:"scope"`
}

// Upstream is where the defect is recorded upstream.
type Upstream struct {
	URL              string         `json:"url,omitempty"`
	PrivateReference string         `json:"private_reference,omitempty"`
	FiledAt          string         `json:"filed_at,omitempty"`
	State            string         `json:"state,omitempty"`
	CheckedAt        string         `json:"checked_at,omitempty"`
	EvidenceAdded    *EvidenceAdded `json:"evidence_added,omitempty"`
}

// EvidenceAdded says how our evidence reached an existing upstream item.
type EvidenceAdded struct {
	Kind   string `json:"kind"`
	URL    string `json:"url,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// Embargo holds the private-disclosure details of an embargoed record.
type Embargo struct {
	Trigger       string   `json:"trigger"`
	Policy        string   `json:"policy"`
	Channel       string   `json:"channel"`
	ReportedAt    string   `json:"reported_at,omitempty"`
	EmbargoUntil  string   `json:"embargo_until,omitempty"`
	LiftCondition string   `json:"lift_condition,omitempty"`
	Withheld      []string `json:"withheld,omitempty"`
}

// Resolution is a reviewer's reason for not-a-defect.
type Resolution struct {
	Reason         string `json:"reason"`
	Reviewer       string `json:"reviewer"`
	Date           string `json:"date"`
	ManifestAction string `json:"manifest_action,omitempty"`
}

// HistoryItem is one append-only state change.
type HistoryItem struct {
	Date  string `json:"date"`
	State string `json:"state"`
	Note  string `json:"note,omitempty"`
}

// Loaded is a record and where it was read from.
type Loaded struct {
	Record  *Record
	Dir     string // the record's directory
	Overlay bool   // read from the private overlay
}

// Store is every record of the public findings directory with the overlay's merged over it.
type Store struct {
	Schema     *Schema
	PublicDir  string // <root>/findings
	OverlayDir string // <overlay>/findings, or "" without an overlay
	Records    map[string]*Loaded
	// Problems are records that do not validate or sit in the wrong place. They fail every check mode.
	Problems []string
}

// Load reads the records under publicDir and, when overlayDir is set, under overlayDir; a record in the overlay
// replaces the public record with the same ID. A missing directory holds no records. Subdirectories whose name
// does not start with "F-" (for example templates/) are not records.
func Load(schema *Schema, publicDir, overlayDir string) (*Store, error) {
	s := &Store{Schema: schema, PublicDir: publicDir, OverlayDir: overlayDir, Records: map[string]*Loaded{}}
	if err := s.loadDir(publicDir, false); err != nil {
		return nil, err
	}
	if overlayDir != "" {
		if err := s.loadDir(overlayDir, true); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *Store) loadDir(dir string, overlay bool) error {
	ents, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	where := "public tree"
	if overlay {
		where = "overlay"
	}
	for _, e := range ents {
		name := e.Name()
		if !e.IsDir() || len(name) < 2 || name[:2] != "F-" {
			continue
		}
		recDir := filepath.Join(dir, name)
		if !IDPattern.MatchString(name) {
			s.Problems = append(s.Problems, fmt.Sprintf("%s (%s): directory name is not a finding ID F-NNNN", name, where))
			continue
		}
		data, err := os.ReadFile(filepath.Join(recDir, RecordFile))
		if err != nil {
			s.Problems = append(s.Problems, fmt.Sprintf("%s (%s): %v", name, where, err))
			continue
		}
		rec, problems := s.parse(data)
		for _, p := range problems {
			s.Problems = append(s.Problems, fmt.Sprintf("%s (%s): %s", name, where, p))
		}
		if rec == nil {
			continue
		}
		if rec.ID != name {
			s.Problems = append(s.Problems, fmt.Sprintf("%s (%s): record id %q does not match its directory", name, where, rec.ID))
		}
		if overlay && !OverlayRange(name) {
			s.Problems = append(s.Problems, fmt.Sprintf("%s (%s): an overlay record takes an ID above F-%04d, so that it never consumes a public ID", name, where, OverlayIDBase))
		}
		if !overlay && rec.Visibility == "embargoed" {
			s.Problems = append(s.Problems, fmt.Sprintf("%s (%s): an embargoed record must live in the private overlay, never in the public tree", name, where))
		}
		s.Records[name] = &Loaded{Record: rec, Dir: recDir, Overlay: overlay}
	}
	return nil
}

// parse validates data against the schema and decodes it. The record is nil when it does not parse.
func (s *Store) parse(data []byte) (*Record, []string) {
	problems := s.Schema.ValidateBytes(data)
	var rec Record
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, append(problems, "does not decode: "+err.Error())
	}
	return &rec, problems
}

// IDs returns the record IDs in order.
func (s *Store) IDs() []string {
	ids := make([]string, 0, len(s.Records))
	for id := range s.Records {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// OverlayIDBase separates the two ID ranges. Public records are numbered F-0001, F-0002, … in order; records
// created in the private overlay are numbered above F-5000, so creating one never consumes a public ID
// and the public sequence reveals nothing about withheld work. Both ranges keep the F-NNNN form the record and
// report schemas require. When an overlay finding becomes public, a new public record with the next public ID is
// written from the public upstream item; the overlay record keeps its own ID and is retired in the overlay. IDs are
// never reused, so a gap left by a record removed from the public tree is not filled.
const OverlayIDBase = 5000

// IDNumber returns the number of a finding ID (0 if it is not one).
func IDNumber(id string) int {
	if !IDPattern.MatchString(id) {
		return 0
	}
	n, _ := strconv.Atoi(id[2:])
	return n
}

// OverlayRange reports whether id is in the overlay range.
func OverlayRange(id string) bool { return IDNumber(id) > OverlayIDBase }

// NextID returns the next ID of a range: for the public tree, one above the highest public-range ID in use
// (overlay records do not count); for the overlay, one above the highest overlay-range ID in use, starting at
// the first number above F-5000. IDs are never reused, so gaps left by a removed record are not filled.
func (s *Store) NextID(overlay bool) string {
	max := 0
	if overlay {
		max = OverlayIDBase
	}
	seen := func(id string) {
		if n := IDNumber(id); n > max && OverlayRange(id) == overlay {
			max = n
		}
	}
	for _, dir := range []string{s.PublicDir, s.OverlayDir} {
		if dir == "" {
			continue
		}
		ents, _ := os.ReadDir(dir)
		for _, e := range ents {
			seen(e.Name())
		}
	}
	for id := range s.Records {
		seen(id)
	}
	return fmt.Sprintf("F-%04d", max+1)
}

// Encode renders a record as written to disk: two-space indented JSON and a final newline.
func Encode(rec *Record) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rec); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Write validates rec and writes it to <dir>/<id>/finding.json. It refuses an embargoed record outside the
// overlay.
func (s *Store) Write(rec *Record, overlay bool) (string, error) {
	dir := s.PublicDir
	if overlay {
		dir = s.OverlayDir
	}
	if dir == "" {
		return "", errors.New("no overlay directory given")
	}
	if !overlay && rec.Visibility == "embargoed" {
		return "", fmt.Errorf("%s is embargoed: it can only be written to the overlay", rec.ID)
	}
	data, err := Encode(rec)
	if err != nil {
		return "", err
	}
	if problems := s.Schema.ValidateBytes(data); len(problems) > 0 {
		return "", fmt.Errorf("%s does not validate: %v", rec.ID, problems)
	}
	recDir := filepath.Join(dir, rec.ID)
	if err := os.MkdirAll(recDir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(recDir, RecordFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", err
	}
	s.Records[rec.ID] = &Loaded{Record: rec, Dir: recDir, Overlay: overlay}
	return path, nil
}

// Package overlay checks the public tree against a private overlay before anything leaves the machine. The
// first push of the public tree is its publication, so nothing that would exercise an embargoed overlay record
// may be in it, and no public file may be a copy of an overlay file with rows taken out (a file is published
// whole or withheld whole; SECURITY.md states the rule).
//
// Audit reads the overlay's finding records (findings/<id>/finding.json) and, for every record whose visibility
// is "embargoed", looks for its triggers in the public tree:
//
//   - its corpus entries' recipes, and each conformance report row whose entry and column are both public
//     (the entry's manifest file in corpus/manifest/ and the column in drivers/sets.toml);
//   - its replay triggers: an entry with scope "replay", or a replay report row, whose entry is public. Every
//     replay adapter ships in the public tree, so a public entry is all anyone needs to repeat the run;
//   - the columns its rows name that the public tree does not define, which must have neither a pin in
//     pins.toml [conformance.columns] nor a driver directory in the public tree;
//   - (for every overlay column) no column of the overlay's drivers/sets.toml defined by the public one too;
//   - its linter rows: no sink of the overlay's linter profile layer (lint/xdrlint.yml) in a public profile
//     under lint/profiles/, and no public expected, pending or suppressions file for the row's target version
//     that names the row's file and rule;
//   - the files its evidence cites (transcripts), which must not exist in the public tree;
//   - its record ID, and the IDs of its entries the public tree does not hold, which no public file may name
//     (corpus/plan.json included, where a family's members make up entry IDs).
//
// Three checks cover the whole tree: every recipe under corpus/recipes/ has a manifest entry (recipes ship only
// for present entries); no public file is a proper row subset of, or identical to, the overlay file at the
// same relative path; and no public file, at any path, has the git blob id of an overlay file (outside the
// overlay's reports/), unless the id is empty content or listed in the overlay's blob-allow.txt. A record entry
// that is public but whose rows all target columns, rules or drivers that are not is listed as kept, not as a
// problem.
//
// The tree is a directory (Audit) or the tree of each commit in a list, read from git without a checkout
// (AuditRevs). Commits share one cache keyed by blob id, so each blob is read and scanned once.
//
// Results name record IDs, problem kinds and paths only, never a record's title or description.
package overlay

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	pathpkg "path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/tolgayayci/xdrcheck/go/internal/conform"
	"github.com/tolgayayci/xdrcheck/go/internal/findings"
	"github.com/tolgayayci/xdrcheck/go/internal/pins"
)

// Problem is one public trace. Record is the overlay record ID, or empty for a tree-wide check.
type Problem struct {
	Record string
	Kind   string
	Path   string
}

func (p Problem) String() string {
	r := p.Record
	if r == "" {
		r = "-"
	}
	return fmt.Sprintf("%s %s %s", r, p.Kind, p.Path)
}

// Problem kinds.
const (
	KindRecipeWithoutEntry = "recipe-without-entry" // a recipe whose entry has no manifest file
	KindRowSubset          = "row-subset"           // a public file is the overlay file at that path with rows taken out
	KindSameFile           = "same-file"            // a public file is identical to the overlay file at that path
	KindBlobID             = "blob-id"              // a public file, at another path, has the blob id of an overlay file
	KindPublicRow          = "public-row"           // an embargoed record's row: entry and column both public
	KindPublicRecipe       = "public-recipe"        // an embargoed record's entry has a public recipe
	KindColumnPublic       = "column-public"        // a column of the overlay's sets file is also a public column
	KindColumnPinned       = "column-pinned"        // a column only the overlay runs is pinned in pins.toml
	KindColumnDriver       = "column-driver"        // a column only the overlay runs has a public driver directory
	KindLintSink           = "lint-sink"            // an overlay profile sink is in a public linter profile
	KindLintRow            = "lint-row"             // a public expected file names an embargoed linter row
	KindEvidence           = "evidence-file"        // a file an embargoed record cites as evidence is public
	KindRecordID           = "record-id"            // a public file contains an embargoed record's ID
	KindEntryNamed         = "entry-named"          // a public file names an embargoed record's moved entry
	KindPlanned            = "planned"              // corpus/plan.json plans an embargoed record's moved entry
	KindPublicReplay       = "public-replay"        // an embargoed record's replay trigger names a public entry
)

// BlobAllowFile, in the overlay, lists blob ids that may be public although an overlay file has the same
// content (a generic .gitignore, a record the overlay keeps a copy of): one id per line, then the reason.
const BlobAllowFile = "blob-allow.txt"

// Result is the outcome of one audit.
type Result struct {
	Records   int       // overlay records read
	Embargoed []string  // the embargoed record IDs, sorted
	Problems  []Problem // sorted
	Kept      []Problem // public entries of embargoed records with no public target (kind "kept"), sorted
	Notes     []string  // (commits only) tree files the audit could not read strictly, and what it did instead
}

// record is the part of a finding record the audit reads.
type record struct {
	ID         string `json:"id"`
	Visibility string `json:"visibility"`
	State      string `json:"state"`
	Entries    []struct {
		ID    string `json:"id"`
		Scope string `json:"scope"`
	} `json:"entries"`
	Evidence *struct {
		Transcripts []string `json:"transcripts"`
		ReportRows  []string `json:"report_rows"`
	} `json:"evidence"`
	Upstream json.RawMessage `json:"upstream"`
}

// firstOverlayID is the documented start of the overlay ID range. The docs and tests name it as the first
// overlay ID, so a public occurrence of that string cannot be told apart from a reference to the record; the
// record's other triggers are still checked.
var firstOverlayID = fmt.Sprintf("F-%04d", findings.OverlayIDBase+1)

// maxCompare bounds the files compared line by line and scanned for record IDs.
const maxCompare = 32 << 20

// overlayData is everything the audit reads from the overlay, loaded once.
type overlayData struct {
	dir       string
	recs      []*record
	sinks     []string
	columns   map[string]*conform.Column // the overlay sets file's columns
	compare   []string                   // overlay files compared by path (outside findings/ and reports/)
	blobs     map[string]string          // overlay blob id -> one overlay path holding it (outside reports/)
	blobPaths map[string][]string        // overlay blob id -> every overlay path holding it
	allowed   map[string]bool            // blob ids blob-allow.txt lists
}

func loadOverlay(overlayDir string) (*overlayData, error) {
	ov := &overlayData{dir: overlayDir, blobs: map[string]string{}, blobPaths: map[string][]string{}, allowed: map[string]bool{}}
	var err error
	if ov.recs, err = loadRecords(filepath.Join(overlayDir, "findings")); err != nil {
		return nil, err
	}
	ov.sinks = overlaySinks(overlayDir)
	if _, err := os.Stat(conform.OverlaySetsPath(overlayDir)); err == nil {
		if ov.columns, err = conform.OverlayColumns(conform.OverlaySetsPath(overlayDir)); err != nil {
			return nil, err
		}
	}
	if data, err := os.ReadFile(filepath.Join(overlayDir, BlobAllowFile)); err == nil {
		for _, l := range strings.Split(string(data), "\n") {
			if f := strings.Fields(l); len(f) > 0 && !strings.HasPrefix(f[0], "#") {
				ov.allowed[f[0]] = true
			}
		}
	}
	err = filepath.WalkDir(overlayDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(overlayDir, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel == "reports" || d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		id := HashObject(data)
		if _, ok := ov.blobs[id]; !ok {
			ov.blobs[id] = rel
		}
		ov.blobPaths[id] = append(ov.blobPaths[id], rel)
		if !strings.HasPrefix(rel, "findings/") {
			ov.compare = append(ov.compare, rel)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(ov.compare)
	return ov, nil
}

// cache holds what the audit learned about blobs, shared by every commit of one AuditRevs run.
type cache struct {
	recipeEntry map[string]string   // blob id -> the recipe's entry ("" when unreadable)
	needles     map[string][]string // blob id -> the needles it contains
	subset      map[string]string   // overlay path + blob id -> the row-subset verdict ("", same-file, row-subset)
	lint        map[string]bool     // blob id + file + rule -> the blob names both
	sinks       map[string][]string // blob id -> the overlay sinks it names
	sets        map[string]setsInfo // blob id -> the public sets file's columns
	pins        map[string]pinsInfo // blob id -> the pins file's conformance columns
}

type setsInfo struct {
	columns map[string]bool
	note    string
}

type pinsInfo struct {
	pinned map[string]map[string]bool
	note   string
}

func newCache() *cache {
	return &cache{recipeEntry: map[string]string{}, needles: map[string][]string{}, subset: map[string]string{},
		lint: map[string]bool{}, sinks: map[string][]string{}, sets: map[string]setsInfo{}, pins: map[string]pinsInfo{}}
}

// Audit checks the public tree at root against the overlay directory.
func Audit(root, overlayDir string) (*Result, error) {
	root, overlayDir, err := absPair(root, overlayDir)
	if err != nil {
		return nil, err
	}
	ov, err := loadOverlay(overlayDir)
	if err != nil {
		return nil, err
	}
	public, err := publicFiles(root)
	if err != nil {
		return nil, err
	}
	return auditTree(&dirTree{root: root, public: public}, ov, nil, true)
}

// AuditRevs checks the tree of every commit in revs (full or abbreviated ids, or any revision git resolves)
// in the repository at repo, without a checkout, and calls each with the commit's id and result. Files a
// commit holds in an older format than the audit reads strictly (sets file, pins file, recipes) are read
// leniently, and the result's Notes say so.
func AuditRevs(repo, overlayDir string, revs []string, each func(rev string, res *Result) error) error {
	repo, overlayDir, err := absPair(repo, overlayDir)
	if err != nil {
		return err
	}
	ov, err := loadOverlay(overlayDir)
	if err != nil {
		return err
	}
	cat, err := newCatFile(repo)
	if err != nil {
		return err
	}
	defer cat.close()
	c := newCache()
	for _, rev := range revs {
		t, err := readTree(repo, rev, cat)
		if err != nil {
			return err
		}
		res, err := auditTree(t, ov, c, false)
		if err != nil {
			return fmt.Errorf("%s: %w", rev, err)
		}
		if err := each(rev, res); err != nil {
			return err
		}
	}
	return nil
}

func absPair(root, overlayDir string) (string, string, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return "", "", err
	}
	overlayDir, err = filepath.Abs(overlayDir)
	if err != nil {
		return "", "", err
	}
	if rel, err := filepath.Rel(root, overlayDir); err == nil && !strings.HasPrefix(rel, "..") {
		return "", "", fmt.Errorf("the overlay %s is inside the tree %s", overlayDir, root)
	}
	return root, overlayDir, nil
}

func auditTree(t tree, ov *overlayData, c *cache, strict bool) (*Result, error) {
	a := &auditor{t: t, public: t.files(), ov: ov, c: c, strict: strict, res: &Result{Records: len(ov.recs)}}
	if err := a.loadTree(); err != nil {
		return nil, err
	}
	a.recipes()
	if err := a.rowSubsets(); err != nil {
		return nil, err
	}
	if err := a.blobIDs(); err != nil {
		return nil, err
	}
	for _, r := range ov.recs {
		if r.Visibility != "embargoed" {
			continue
		}
		a.res.Embargoed = append(a.res.Embargoed, r.ID)
		if err := a.record(r); err != nil {
			return nil, err
		}
	}
	if err := a.textScan(ov.recs); err != nil {
		return nil, err
	}
	sortProblems(a.res.Problems)
	sortProblems(a.res.Kept)
	sort.Strings(a.res.Embargoed)
	return a.res, nil
}

type auditor struct {
	t      tree
	public map[string]bool // public paths, slash-separated, relative to the tree's root
	ov     *overlayData
	c      *cache // nil: no cache (a single directory)
	strict bool   // a directory: unreadable tree files are errors, not notes
	res    *Result

	manifest   map[string]bool            // public entry IDs (corpus/manifest/<id>.json)
	recipesOf  map[string][]string        // entry ID -> public recipe paths
	pubColumns map[string]bool            // columns of the repository's drivers/sets.toml
	ovColumns  map[string]*conform.Column // columns only the overlay's sets file defines
	pinned     map[string]map[string]bool // pins.toml [conformance.columns]: sdk -> version
	seen       map[Problem]bool
}

func (a *auditor) add(p Problem) {
	if a.seen == nil {
		a.seen = map[Problem]bool{}
	}
	if !a.seen[p] {
		a.seen[p] = true
		a.res.Problems = append(a.res.Problems, p)
	}
}

func (a *auditor) note(format string, args ...any) {
	a.res.Notes = append(a.res.Notes, fmt.Sprintf(format, args...))
}

// blobKey is the cache key of a public file: its blob id, or "" without a cache.
func (a *auditor) blobKey(rel string) string {
	if a.c == nil {
		return ""
	}
	id, err := a.t.blobID(rel)
	if err != nil {
		return ""
	}
	return id
}

func loadRecords(dir string) ([]*record, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*", "finding.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	var out []*record
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		var r record
		if err := json.Unmarshal(data, &r); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		if r.ID == "" {
			r.ID = filepath.Base(filepath.Dir(p))
		}
		out = append(out, &r)
	}
	return out, nil
}

// publicFiles lists what a commit of the tree would contain: in a git work tree the tracked files and the
// untracked ones that are not ignored (deleted files dropped); elsewhere every file below root.
func publicFiles(root string) (map[string]bool, error) {
	out := map[string]bool{}
	cmd := exec.Command("git", "-C", root, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
	if data, err := cmd.Output(); err == nil {
		if top, err := exec.Command("git", "-C", root, "rev-parse", "--show-toplevel").Output(); err == nil {
			if t, _ := filepath.EvalSymlinks(strings.TrimSpace(string(top))); t != "" {
				if r, _ := filepath.EvalSymlinks(root); r == t {
					for _, f := range strings.Split(string(data), "\x00") {
						if f == "" {
							continue
						}
						if st, err := os.Lstat(filepath.Join(root, f)); err == nil && st.Mode().IsRegular() {
							out[f] = true
						}
					}
					return out, nil
				}
			}
		}
	}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == ".git" {
			return filepath.SkipDir
		}
		if d.Type().IsRegular() {
			rel, _ := filepath.Rel(root, p)
			out[filepath.ToSlash(rel)] = true
		}
		return nil
	})
	return out, err
}

func (a *auditor) loadTree() error {
	a.manifest = map[string]bool{}
	a.recipesOf = map[string][]string{}
	for f := range a.public {
		if id, ok := strings.CutPrefix(f, "corpus/manifest/"); ok && strings.HasSuffix(id, ".json") {
			a.manifest[strings.TrimSuffix(id, ".json")] = true
		}
	}
	for f := range a.public {
		if !strings.HasPrefix(f, "corpus/recipes/") || !strings.HasSuffix(f, ".json") {
			continue
		}
		entry, err := a.recipeEntry(f)
		if err != nil {
			return err
		}
		if entry == "" {
			a.note("%s: not a recipe with an entry; named by its path", f)
			entry = strings.TrimSuffix(strings.TrimPrefix(f, "corpus/recipes/"), ".json")
		}
		a.recipesOf[entry] = append(a.recipesOf[entry], f)
	}
	sets, err := a.publicSets()
	if err != nil {
		return err
	}
	a.pubColumns = sets.columns
	if sets.note != "" {
		a.note("%s", sets.note)
	}
	a.ovColumns = map[string]*conform.Column{}
	ids := make([]string, 0, len(a.ov.columns))
	for id := range a.ov.columns {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if a.pubColumns[id] {
			a.add(Problem{Kind: KindColumnPublic, Path: "drivers/sets.toml " + id})
			continue
		}
		a.ovColumns[id] = a.ov.columns[id]
	}
	p, err := a.publicPins()
	if err != nil {
		return err
	}
	a.pinned = p.pinned
	if p.note != "" {
		a.note("%s", p.note)
	}
	return nil
}

// recipeEntry is the entry a public recipe names, or "" (with no error) when a commit's recipe is unreadable.
func (a *auditor) recipeEntry(f string) (string, error) {
	key := a.blobKey(f)
	if key != "" {
		if e, ok := a.c.recipeEntry[key]; ok {
			return e, nil
		}
	}
	var r struct {
		Entry string `json:"entry"`
	}
	data, err := a.t.read(f)
	if err != nil {
		return "", err
	}
	if err := json.Unmarshal(data, &r); err != nil || r.Entry == "" {
		if a.strict {
			return "", fmt.Errorf("%s: not a recipe with an entry", f)
		}
		r.Entry = ""
	}
	if key != "" {
		a.c.recipeEntry[key] = r.Entry
	}
	return r.Entry, nil
}

var columnHeader = regexp.MustCompile(`(?m)^\[columns\."([^"]+)"\]`)

// publicSets reads the columns of the public drivers/sets.toml and its fragments in drivers/sets.d/. A
// commit's files that the current schema refuses are read for their column IDs only.
func (a *auditor) publicSets() (setsInfo, error) {
	const path = "drivers/sets.toml"
	if !a.public[path] {
		return setsInfo{columns: map[string]bool{}}, nil
	}
	var fragPaths []string
	for p := range a.public {
		if dir, name := pathpkg.Split(p); dir == "drivers/sets.d/" && strings.HasSuffix(name, ".toml") {
			fragPaths = append(fragPaths, p)
		}
	}
	sort.Strings(fragPaths)
	key := a.blobKey(path)
	for _, fp := range fragPaths {
		if key == "" {
			break
		}
		if k := a.blobKey(fp); k != "" {
			key += "+" + fp + "=" + k
		} else {
			key = ""
		}
	}
	if key != "" {
		if s, ok := a.c.sets[key]; ok {
			return s, nil
		}
	}
	data, err := a.t.read(path)
	if err != nil {
		return setsInfo{}, err
	}
	info := setsInfo{columns: map[string]bool{}}
	root := ""
	if d, ok := a.t.(*dirTree); ok {
		root = d.root
	}
	frags := make([]conform.Fragment, 0, len(fragPaths))
	for _, fp := range fragPaths {
		b, err := a.t.read(fp)
		if err != nil {
			return setsInfo{}, err
		}
		frags = append(frags, conform.Fragment{Path: fp, Data: b})
	}
	s, err := conform.ParseSetsFiles(data, frags, path, root)
	switch {
	case err == nil:
		for id := range s.Columns {
			info.columns[id] = true
		}
	case a.strict:
		return setsInfo{}, err
	default:
		for _, d := range append([][]byte{data}, fragData(frags)...) {
			for _, m := range columnHeader.FindAllSubmatch(d, -1) {
				info.columns[string(m[1])] = true
			}
		}
		info.note = fmt.Sprintf("%s: not readable as today's sets file (%v); its column IDs were read from the table headers", path, err)
	}
	if key != "" {
		a.c.sets[key] = info
	}
	return info, nil
}

func fragData(frags []conform.Fragment) [][]byte {
	out := make([][]byte, len(frags))
	for i, f := range frags {
		out[i] = f.Data
	}
	return out
}

// publicPins reads pins.toml [conformance.columns]. A commit's file that the current schema refuses is read
// leniently for that table only.
func (a *auditor) publicPins() (pinsInfo, error) {
	const path = "pins.toml"
	info := pinsInfo{pinned: map[string]map[string]bool{}}
	if !a.public[path] {
		return info, nil
	}
	key := a.blobKey(path)
	if key != "" {
		if p, ok := a.c.pins[key]; ok {
			return p, nil
		}
	}
	data, err := a.t.read(path)
	if err != nil {
		return info, err
	}
	var cols map[string][]string
	p, err := pins.Parse(data)
	switch {
	case err == nil:
		cols = p.Conformance.Columns
	case a.strict:
		return info, fmt.Errorf("%s: %w", path, err)
	default:
		var loose struct {
			Conformance struct {
				Columns map[string][]string `toml:"columns"`
			} `toml:"conformance"`
		}
		if _, lerr := toml.Decode(string(data), &loose); lerr != nil {
			info.note = fmt.Sprintf("%s: unreadable (%v); no column counts as pinned", path, lerr)
		} else {
			info.note = fmt.Sprintf("%s: not readable as today's pins file (%v); [conformance.columns] read leniently", path, err)
		}
		cols = loose.Conformance.Columns
	}
	for sdk, vs := range cols {
		info.pinned[sdk] = map[string]bool{}
		for _, v := range vs {
			info.pinned[sdk][v] = true
		}
	}
	if key != "" {
		a.c.pins[key] = info
	}
	return info, nil
}

// recipes: every public recipe belongs to a public manifest entry.
func (a *auditor) recipes() {
	for entry, paths := range a.recipesOf {
		if a.manifest[entry] {
			continue
		}
		for _, p := range paths {
			a.add(Problem{Kind: KindRecipeWithoutEntry, Path: p})
		}
	}
}

// rowSubsets compares every overlay file (outside the overlay's own findings/ and reports/) with the public
// file at the same relative path.
func (a *auditor) rowSubsets() error {
	for _, rel := range a.ov.compare {
		if !a.public[rel] {
			continue
		}
		key := a.blobKey(rel)
		if key != "" {
			if v, ok := a.c.subset[rel+"\x00"+key]; ok {
				if v != "" {
					a.add(Problem{Kind: v, Path: rel})
				}
				continue
			}
		}
		v, err := a.subsetVerdict(rel)
		if err != nil {
			return err
		}
		if key != "" {
			a.c.subset[rel+"\x00"+key] = v
		}
		if v != "" {
			a.add(Problem{Kind: v, Path: rel})
		}
	}
	return nil
}

func (a *auditor) subsetVerdict(rel string) (string, error) {
	ov, err := readBounded(filepath.Join(a.ov.dir, filepath.FromSlash(rel)))
	if err != nil || ov == nil {
		return "", err
	}
	pub, err := a.t.read(rel)
	if err != nil || pub == nil {
		return "", err
	}
	switch {
	case bytes.Equal(ov, pub):
		return KindSameFile, nil
	case properSubset(lines(pub), lines(ov)):
		return KindRowSubset, nil
	}
	return "", nil
}

// blobIDs: no public file has the content of an overlay file, at any path (the same path is the same-file
// check's). Empty content and the ids blob-allow.txt lists are not leaks.
func (a *auditor) blobIDs() error {
	for f := range a.public {
		id, err := a.t.blobID(f)
		if err != nil {
			return err
		}
		if _, ok := a.ov.blobs[id]; !ok || id == EmptyBlob || a.ov.allowed[id] {
			continue
		}
		samePath := false
		for _, p := range a.ov.blobPaths[id] {
			if p == f && !strings.HasPrefix(p, "findings/") {
				samePath = true
			}
		}
		if !samePath {
			a.add(Problem{Kind: KindBlobID, Path: f + " = overlay " + a.ov.blobs[id]})
		}
	}
	return nil
}

func readBounded(p string) ([]byte, error) {
	st, err := os.Stat(p)
	if err != nil || st.Size() > maxCompare {
		return nil, err
	}
	return os.ReadFile(p)
}

func lines(b []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 1<<20), maxCompare)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// properSubset reports whether every line of sub occurs in super, counted with multiplicity, and super has
// more lines.
func properSubset(sub, super []string) bool {
	if len(sub) == 0 || len(sub) >= len(super) {
		return false
	}
	count := map[string]int{}
	for _, l := range super {
		count[l]++
	}
	for _, l := range sub {
		if count[l] == 0 {
			return false
		}
		count[l]--
	}
	return true
}

// overlaySinks lists the names the overlay's linter profile layer adds (every list item of lint/xdrlint.yml).
func overlaySinks(overlayDir string) []string {
	data, err := os.ReadFile(filepath.Join(overlayDir, "lint", "xdrlint.yml"))
	if err != nil {
		return nil
	}
	var out []string
	item := regexp.MustCompile(`^\s*-\s+["']?([^"'#\s]+)`)
	for _, l := range strings.Split(string(data), "\n") {
		if m := item.FindStringSubmatch(l); m != nil {
			out = append(out, m[1])
		}
	}
	return out
}

// conformRow splits "conform:<entry>:<variant>:<column>:<level>"; the column may hold a ":profile".
func conformRow(row string) (entry, column string, ok bool) {
	rest, ok := strings.CutPrefix(row, "conform:")
	if !ok {
		return "", "", false
	}
	i := strings.LastIndex(rest, ":")
	if i < 0 {
		return "", "", false
	}
	parts := strings.SplitN(rest[:i], ":", 3)
	if len(parts) != 3 {
		return "", "", false
	}
	return parts[0], parts[2], true
}

// replayRow returns the entry of "replay:<target>@<version>:<entry>:<variant>:<unit>".
func replayRow(row string) (entry string, ok bool) {
	rest, ok := strings.CutPrefix(row, "replay:")
	if !ok {
		return "", false
	}
	parts := strings.Split(rest, ":")
	if len(parts) != 4 || parts[1] == "" {
		return "", false
	}
	return parts[1], true
}

// lintRow splits "lint:<module>@<version>:<rule>:<file>:<function>".
func lintRow(row string) (version, rule, file string, ok bool) {
	rest, ok := strings.CutPrefix(row, "lint:")
	if !ok {
		return "", "", "", false
	}
	parts := strings.SplitN(rest, ":", 4)
	if len(parts) < 3 {
		return "", "", "", false
	}
	at := strings.LastIndex(parts[0], "@")
	if at < 0 {
		return "", "", "", false
	}
	return parts[0][at+1:], parts[1], parts[2], true
}

// sortedPublic is the public paths in order, so problems come out the same way every run.
func (a *auditor) sortedPublic() []string {
	out := make([]string, 0, len(a.public))
	for f := range a.public {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

func (a *auditor) record(r *record) error {
	var rows, transcripts []string
	if r.Evidence != nil {
		rows, transcripts = r.Evidence.ReportRows, r.Evidence.Transcripts
	}
	// Entries: recipes, and rows whose entry and column are both public.
	targeted := map[string]bool{}
	for _, row := range rows {
		entry, column, ok := conformRow(row)
		if !ok {
			continue
		}
		if a.pubColumns[column] {
			targeted[entry] = true
			if a.manifest[entry] {
				a.add(Problem{Record: r.ID, Kind: KindPublicRow, Path: "corpus/manifest/" + entry + ".json × " + column})
			}
			continue
		}
		a.privateColumn(r.ID, column)
	}
	// Replay triggers: the replay adapters are public, so an entry replayed for the record must not be.
	replayed := map[string]bool{}
	for _, e := range r.Entries {
		if e.Scope == "replay" {
			replayed[e.ID] = true
		}
	}
	for _, row := range rows {
		if entry, ok := replayRow(row); ok {
			replayed[entry] = true
		}
	}
	for entry := range replayed {
		targeted[entry] = true
		if a.manifest[entry] {
			a.add(Problem{Record: r.ID, Kind: KindPublicReplay, Path: "corpus/manifest/" + entry + ".json"})
		}
	}
	// A recipe goes with its entry: a public entry's recipe is covered by the row check (or kept with it); a
	// recipe whose entry is not public would rebuild the entry's bytes.
	kept := map[string]bool{}
	for _, e := range r.Entries {
		if !a.manifest[e.ID] {
			for _, p := range a.recipesOf[e.ID] {
				a.add(Problem{Record: r.ID, Kind: KindPublicRecipe, Path: p})
			}
			continue
		}
		if !targeted[e.ID] && !kept[e.ID] {
			kept[e.ID] = true
			a.res.Kept = append(a.res.Kept, Problem{Record: r.ID, Kind: "kept", Path: "corpus/manifest/" + e.ID + ".json"})
		}
	}
	// Linter rows.
	lintRows := false
	files := a.sortedPublic()
	for _, row := range rows {
		version, rule, file, ok := lintRow(row)
		if !ok {
			continue
		}
		lintRows = true
		for _, f := range files {
			if !strings.HasPrefix(f, "lint/expected/") || !strings.HasPrefix(filepath.Base(f), version) {
				continue
			}
			hit, err := a.namesBoth(f, file, rule)
			if err != nil {
				return err
			}
			if hit {
				a.add(Problem{Record: r.ID, Kind: KindLintRow, Path: f})
			}
		}
	}
	if lintRows {
		for _, f := range files {
			if !strings.HasPrefix(f, "lint/profiles/") || !strings.HasSuffix(f, ".yml") {
				continue
			}
			named, err := a.sinksIn(f)
			if err != nil {
				return err
			}
			if len(named) > 0 {
				a.add(Problem{Record: r.ID, Kind: KindLintSink, Path: f})
			}
		}
	}
	// Evidence files.
	for _, t := range transcripts {
		t = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(t), "overlay:"))
		t = strings.TrimSuffix(filepath.ToSlash(filepath.Clean(t)), "/")
		if t == "" || t == "." || strings.HasPrefix(t, "..") || filepath.IsAbs(t) {
			continue
		}
		if a.public[t] {
			a.add(Problem{Record: r.ID, Kind: KindEvidence, Path: t})
			continue
		}
		for _, f := range files {
			if strings.HasPrefix(f, t+"/") {
				a.add(Problem{Record: r.ID, Kind: KindEvidence, Path: t + "/"})
				break
			}
		}
	}
	return nil
}

// namesBoth reports whether public file f contains both file and rule.
func (a *auditor) namesBoth(f, file, rule string) (bool, error) {
	key := a.blobKey(f)
	ck := key + "\x00" + file + "\x00" + rule
	if key != "" {
		if v, ok := a.c.lint[ck]; ok {
			return v, nil
		}
	}
	data, err := a.t.read(f)
	if err != nil {
		return false, nil
	}
	v := bytes.Contains(data, []byte(file)) && bytes.Contains(data, []byte(rule))
	if key != "" {
		a.c.lint[ck] = v
	}
	return v, nil
}

// sinksIn lists the overlay sinks public profile f names.
func (a *auditor) sinksIn(f string) ([]string, error) {
	key := a.blobKey(f)
	if key != "" {
		if v, ok := a.c.sinks[key]; ok {
			return v, nil
		}
	}
	data, err := a.t.read(f)
	if err != nil {
		return nil, nil
	}
	var out []string
	for _, s := range a.ov.sinks {
		if bytes.Contains(data, []byte(s)) {
			out = append(out, s)
		}
	}
	if key != "" {
		a.c.sinks[key] = out
	}
	return out, nil
}

// privateColumn: a column the public sets file does not define must not be pinned or driven publicly.
func (a *auditor) privateColumn(id, column string) {
	m := regexp.MustCompile(`^([a-z0-9-]+)@([A-Za-z0-9.+-]+)(?::[a-z0-9-]+)?$`).FindStringSubmatch(column)
	if m == nil {
		return
	}
	if a.pinned[m[1]][m[2]] {
		a.add(Problem{Record: id, Kind: KindColumnPinned, Path: "pins.toml [conformance.columns] " + m[1] + " " + m[2]})
	}
	if c := a.ovColumns[column]; c != nil {
		dir := strings.TrimSuffix(filepath.ToSlash(filepath.Clean(c.Dir)), "/")
		for f := range a.public {
			if strings.HasPrefix(f, dir+"/") {
				a.add(Problem{Record: id, Kind: KindColumnDriver, Path: dir + "/"})
				break
			}
		}
	}
}

// textScan: no public file contains an embargoed record's ID, or the ID of one of its entries that the public
// tree does not hold (a moved entry); corpus/plan.json does not plan such an entry, as an ID or as a member of
// a planned family. IDs match as whole words.
func (a *auditor) textScan(recs []*record) error {
	owner := map[string]Problem{} // needle -> record and kind
	var needles []string
	addNeedle := func(n string, p Problem) {
		if _, ok := owner[n]; !ok {
			owner[n] = p
			needles = append(needles, regexp.QuoteMeta(n))
		}
	}
	moved := map[string]string{} // moved entry ID -> record
	for _, r := range recs {
		if r.Visibility != "embargoed" {
			continue
		}
		if r.ID != firstOverlayID {
			addNeedle(r.ID, Problem{Record: r.ID, Kind: KindRecordID})
		}
		for _, e := range r.Entries {
			if e.ID != "" && !a.manifest[e.ID] {
				addNeedle(e.ID, Problem{Record: r.ID, Kind: KindEntryNamed})
				moved[e.ID] = r.ID
			}
		}
	}
	if err := a.planned(moved); err != nil {
		return err
	}
	if len(needles) == 0 {
		return nil
	}
	sort.Strings(needles)
	pattern := `(?:^|[^\w.-])(` + strings.Join(needles, "|") + `)(?:$|[^\w-])`
	re := regexp.MustCompile(pattern)
	for _, f := range a.sortedPublic() {
		found, err := a.needlesIn(f, pattern, re)
		if err != nil {
			return err
		}
		for _, n := range found {
			p := owner[n]
			p.Path = f
			a.add(p)
		}
	}
	return nil
}

// needlesIn lists the needles public file f contains. The cache key includes the pattern: the moved entries,
// and so the needles, depend on the commit's manifest.
func (a *auditor) needlesIn(f, pattern string, re *regexp.Regexp) ([]string, error) {
	key := a.blobKey(f)
	ck := key + "\x00" + pattern
	if key != "" {
		if v, ok := a.c.needles[ck]; ok {
			return v, nil
		}
	}
	data, err := a.t.read(f)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, m := range re.FindAllSubmatch(data, -1) {
		out = append(out, string(m[1]))
	}
	if key != "" {
		a.c.needles[ck] = out
	}
	return out, nil
}

// planned: corpus/plan.json, a list of planned entries each with an "id" and optional "members" (the entry
// IDs are id.member), must not plan a moved entry.
func (a *auditor) planned(moved map[string]string) error {
	const path = "corpus/plan.json"
	if !a.public[path] || len(moved) == 0 {
		return nil
	}
	data, err := a.t.read(path)
	if err != nil {
		return err
	}
	var plan []struct {
		ID      string   `json:"id"`
		Members []string `json:"members"`
	}
	if err := json.Unmarshal(data, &plan); err != nil {
		if a.strict {
			return fmt.Errorf("%s: %w", path, err)
		}
		a.note("%s: not a list of planned entries (%v); not checked", path, err)
		return nil
	}
	for _, it := range plan {
		ids := []string{it.ID}
		for _, m := range it.Members {
			ids = append(ids, it.ID+"."+m)
		}
		for _, id := range ids {
			if rec, ok := moved[id]; ok {
				a.add(Problem{Record: rec, Kind: KindPlanned, Path: path + " " + id})
			}
		}
	}
	return nil
}

func sortProblems(ps []Problem) {
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].Record != ps[j].Record {
			return ps[i].Record < ps[j].Record
		}
		if ps[i].Kind != ps[j].Kind {
			return ps[i].Kind < ps[j].Kind
		}
		return ps[i].Path < ps[j].Path
	})
}

package conform

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/tolgayayci/xdrcheck/go/internal/pins"
)

// Column is one conformance column: one SDK at one pinned version, optionally under one decode profile, driven
// by the driver program in Dir.
type Column struct {
	ID        string   `toml:"-"`         // "<sdk>@<version>" or "<sdk>@<version>:<profile>", the TOML key
	SDK       string   `toml:"sdk"`       // the key under pins.toml [conformance.columns] (js, go, rust, python, java), or core, stub
	Kind      string   `toml:"kind"`      // report target kind: sdk, core, selftest
	Ecosystem string   `toml:"ecosystem"` // describe sdk.ecosystem the driver must report
	Package   string   `toml:"package"`   // describe sdk.package the driver must report
	Target    string   `toml:"target"`    // the name manifest known divergences use for this SDK
	Version   string   `toml:"version"`   // pinned version; describe sdk.version must equal it
	Profile   string   `toml:"profile"`   // decode profile sent with every run request
	Role      string   `toml:"role"`      // required, historical, extra, selftest
	Dir       string   `toml:"dir"`       // driver directory, relative to the repository root (or to Base)
	Run       []string `toml:"run"`       // driver command; a first word with a slash is relative to Dir
	Levels    []string `toml:"levels"`    // the only levels the column runs (json for the XDR-JSON converters); empty: every level

	// Floor is the column's judged-cell floor per level (`floor = {L0 = 0.95}`): the fraction of the selected
	// variants the driver declares it can read that must be judged. Read and kept, not enforced yet; nil: the
	// default for the column's kind.
	Floor map[string]float64 `toml:"floor"`
	// Limits are the column's own resource limits for its driver process. Read and kept, not applied yet; nil:
	// the runtime defaults.
	Limits *ColumnLimits `toml:"limits"`

	// Base is the directory Dir is relative to for a column read from an overlay's sets file; empty for a
	// column of the repository's own sets file.
	Base string `toml:"-"`

	// Source is the SDK checkout the column is built from instead of its pinned package (xdrcheck conform --sdk), and
	// SourceDir the private copy of its driver directory that builds it; both empty for the pinned package.
	Source    string `toml:"-"`
	SourceDir string `toml:"-"`
}

// ColumnLimits is a column's `limits` table: resource limits for its driver process. A zero field means the
// runtime default.
type ColumnLimits struct {
	Memory     string `toml:"memory" json:"memory,omitempty"`           // memory.max or RLIMIT_AS size, e.g. "1G"
	Tasks      int    `toml:"tasks" json:"tasks,omitempty"`             // processes and threads
	CPUSeconds int    `toml:"cpu_seconds" json:"cpu_seconds,omitempty"` // RLIMIT_CPU
	NoFile     int    `toml:"nofile" json:"nofile,omitempty"`           // RLIMIT_NOFILE
	FSize      string `toml:"fsize" json:"fsize,omitempty"`             // RLIMIT_FSIZE size, e.g. "64M"
	AS         string `toml:"as" json:"as,omitempty"`                   // RLIMIT_AS size, or "off"
}

// Sets is drivers/sets.toml with the fragments in drivers/sets.d/: the columns and the named column sets.
type Sets struct {
	Columns map[string]*Column  `toml:"columns"`
	Sets    map[string][]string `toml:"sets"`

	// Root is the repository root the column directories are relative to.
	Root string `toml:"-"`

	// What MergeOverlay added: the versions the overlay pins for its own columns, and the sets it defines.
	overlayPins map[string][]string
	overlaySets map[string]bool
}

// overlaySetsFile is the sets file a private overlay may keep at drivers/sets.toml: more columns, whose
// directories are relative to the overlay, the versions they pin, new sets, and members added to the
// repository's sets.
type overlaySetsFile struct {
	Columns map[string]*Column  `toml:"columns"`
	Sets    map[string][]string `toml:"sets"`
	Extend  map[string][]string `toml:"extend"`
	Pins    map[string][]string `toml:"pins"`
}

var (
	columnIDRe = regexp.MustCompile(`^([a-z0-9-]+)@([A-Za-z0-9.+-]+)(?::([a-z0-9-]+))?$`)
	kinds      = set("sdk", "core", "selftest")
	roles      = set("required", "historical", "extra", "selftest")
)

// LoadSets reads a sets file and the fragments in the sets.d directory beside it (FragmentDir), in name order.
// Column directories are resolved against root.
func LoadSets(path, root string) (*Sets, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	names, err := filepath.Glob(filepath.Join(FragmentDir(path), "*.toml"))
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	frags := make([]Fragment, 0, len(names))
	for _, n := range names {
		b, err := os.ReadFile(n)
		if err != nil {
			return nil, err
		}
		frags = append(frags, Fragment{Path: n, Data: b})
	}
	return ParseSetsFiles(data, frags, path, root)
}

// FragmentDir is the directory of a sets file's fragments: sets.d beside it (drivers/sets.d/ for
// drivers/sets.toml).
func FragmentDir(path string) string {
	return filepath.Join(filepath.Dir(path), "sets.d")
}

// Fragment is one file of a sets file's sets.d directory: more columns (one family per file) and, under
// [extend], members it appends to the sets the main file defines. Path names it in errors.
type Fragment struct {
	Path string
	Data []byte
}

type fragmentFile struct {
	Columns map[string]*Column  `toml:"columns"`
	Extend  map[string][]string `toml:"extend"`
}

// ParseSets decodes sets-file content read from elsewhere (a commit's tree, say), without fragments; path names
// it in errors.
func ParseSets(data []byte, path, root string) (*Sets, error) {
	return ParseSetsFiles(data, nil, path, root)
}

// ParseSetsFiles decodes a sets file and its fragments, given in name order. The main file holds the sets (and
// may hold columns); a fragment holds columns and [extend]. A column defined twice, an unknown key, or an
// [extend] of a set the main file does not define is refused. The [extend] members are appended in fragment
// order, after every column is read.
func ParseSetsFiles(data []byte, frags []Fragment, path, root string) (*Sets, error) {
	var s Sets
	md, err := toml.Decode(string(data), &s)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := undecoded(path, md); err != nil {
		return nil, err
	}
	s.Root = root
	if s.Columns == nil {
		s.Columns = map[string]*Column{}
	}
	for id, c := range s.Columns {
		c.ID = id
	}
	var extends []fragmentFile
	var extendPaths []string
	for _, f := range frags {
		var ff fragmentFile
		fmd, err := toml.Decode(string(f.Data), &ff)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f.Path, err)
		}
		if err := undecoded(f.Path, fmd); err != nil {
			return nil, err
		}
		for id, c := range ff.Columns {
			if s.Columns[id] != nil {
				return nil, fmt.Errorf("%s: column %q is defined twice", f.Path, id)
			}
			c.ID = id
			s.Columns[id] = c
		}
		extends, extendPaths = append(extends, ff), append(extendPaths, f.Path)
	}
	for i, ff := range extends {
		names := make([]string, 0, len(ff.Extend))
		for name := range ff.Extend {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if _, ok := s.Sets[name]; !ok {
				return nil, fmt.Errorf("%s: [extend] %q: no such set in %s", extendPaths[i], name, path)
			}
			s.Sets[name] = append(append([]string{}, s.Sets[name]...), ff.Extend[name]...)
		}
	}
	if err := s.check(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &s, nil
}

func undecoded(path string, md toml.MetaData) error {
	if und := md.Undecoded(); len(und) > 0 {
		keys := make([]string, len(und))
		for i, k := range und {
			keys[i] = k.String()
		}
		sort.Strings(keys)
		return fmt.Errorf("%s: unknown keys: %s", path, strings.Join(keys, ", "))
	}
	return nil
}

// OverlaySetsPath is where an overlay directory keeps its sets file.
func OverlaySetsPath(overlay string) string {
	return filepath.Join(overlay, "drivers", "sets.toml")
}

// LoadSetsWithOverlay reads the repository's sets file and, when overlay names a directory that holds a sets
// file, merges that file over it (MergeOverlay). An empty overlay, or one without a sets file, changes nothing.
func LoadSetsWithOverlay(path, root, overlay string) (*Sets, error) {
	s, err := LoadSets(path, root)
	if err != nil || overlay == "" {
		return s, err
	}
	op := OverlaySetsPath(overlay)
	if _, err := os.Stat(op); err != nil {
		return s, nil
	}
	if err := s.MergeOverlay(op, overlay); err != nil {
		return nil, err
	}
	return s, nil
}

// readOverlaySets decodes an overlay's sets file, refusing unknown keys.
func readOverlaySets(path string) (*overlaySetsFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var o overlaySetsFile
	md, err := toml.Decode(string(data), &o)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if und := md.Undecoded(); len(und) > 0 {
		keys := make([]string, len(und))
		for i, k := range und {
			keys[i] = k.String()
		}
		sort.Strings(keys)
		return nil, fmt.Errorf("%s: unknown keys: %s", path, strings.Join(keys, ", "))
	}
	for id, c := range o.Columns {
		c.ID = id
	}
	return &o, nil
}

// OverlayColumns reads the columns of an overlay's sets file without merging them; Dir is relative to the
// overlay.
func OverlayColumns(path string) (map[string]*Column, error) {
	o, err := readOverlaySets(path)
	if err != nil {
		return nil, err
	}
	return o.Columns, nil
}

// MergeOverlay adds an overlay's sets file: its columns (directories relative to base), its sets, the members
// its [extend] table adds to the repository's sets, and the versions its [pins] table pins for its own
// columns. An overlay may not redefine a column or a set of the repository.
func (s *Sets) MergeOverlay(path, base string) error {
	o, err := readOverlaySets(path)
	if err != nil {
		return err
	}
	absBase, err := filepath.Abs(base)
	if err != nil {
		return err
	}
	var errs []string
	if s.Columns == nil {
		s.Columns = map[string]*Column{}
	}
	if s.Sets == nil {
		s.Sets = map[string][]string{}
	}
	for id, c := range o.Columns {
		if s.Columns[id] != nil {
			errs = append(errs, fmt.Sprintf("column %q is already defined by the repository", id))
			continue
		}
		c.ID, c.Base = id, absBase
		s.Columns[id] = c
	}
	s.overlaySets = map[string]bool{}
	for name, members := range o.Sets {
		if _, ok := s.Sets[name]; ok {
			errs = append(errs, fmt.Sprintf("set %q is already defined by the repository (add members with [extend])", name))
			continue
		}
		s.Sets[name] = members
		s.overlaySets[name] = true
	}
	for name, members := range o.Extend {
		if _, ok := s.Sets[name]; !ok || s.overlaySets[name] {
			errs = append(errs, fmt.Sprintf("[extend] %q: no such set in the repository", name))
			continue
		}
		s.Sets[name] = append(append([]string{}, s.Sets[name]...), members...)
	}
	s.overlayPins = o.Pins
	if len(errs) == 0 {
		if err := s.check(); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s: %s", path, strings.Join(errs, "; "))
	}
	return nil
}

func (s *Sets) check() error {
	var errs []string
	for _, id := range s.columnIDs() {
		c := s.Columns[id]
		m := columnIDRe.FindStringSubmatch(id)
		switch {
		case m == nil:
			errs = append(errs, fmt.Sprintf("column %q: the ID is not <sdk>@<version>[:<profile>]", id))
			continue
		case m[1] != c.SDK || m[2] != c.Version || m[3] != c.Profile:
			errs = append(errs, fmt.Sprintf("column %q: the ID disagrees with sdk %q, version %q, profile %q", id, c.SDK, c.Version, c.Profile))
		}
		if !kinds[c.Kind] {
			errs = append(errs, fmt.Sprintf("column %q: kind %q is not sdk, core or selftest", id, c.Kind))
		}
		if !roles[c.Role] {
			errs = append(errs, fmt.Sprintf("column %q: role %q is not required, historical, extra or selftest", id, c.Role))
		}
		if !ecosystems[c.Ecosystem] {
			errs = append(errs, fmt.Sprintf("column %q: ecosystem %q is not in the driver protocol's enum", id, c.Ecosystem))
		}
		if c.Package == "" || c.Target == "" || c.Dir == "" || len(c.Run) == 0 {
			errs = append(errs, fmt.Sprintf("column %q: package, target, dir and run are required", id))
		}
		for _, l := range c.Levels {
			if !levelSet[l] {
				errs = append(errs, fmt.Sprintf("column %q: level %q is not a conformance level", id, l))
			}
		}
		if filepath.IsAbs(c.Dir) || strings.Contains(filepath.ToSlash(c.Dir), "..") {
			errs = append(errs, fmt.Sprintf("column %q: dir %q must be a relative path inside its tree", id, c.Dir))
		}
	}
	for _, name := range s.SetNames() {
		if _, err := s.Resolve(name); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// CheckPins checks every column's version against the pins file: an sdk column's version must be listed under
// [conformance.columns] for its SDK (an overlay column's may instead be listed in the overlay's [pins]), a core
// column's version must be the pinned stellar-core version. Selftest columns are the kit's own and are not
// pinned.
func (s *Sets) CheckPins(p *pins.Pins) error {
	var errs []string
	for _, id := range s.columnIDs() {
		c := s.Columns[id]
		switch c.Kind {
		case "sdk":
			allowed, ok := p.Conformance.Columns[c.SDK]
			if c.Base != "" {
				extra, has := s.overlayPins[c.SDK]
				allowed, ok = append(append([]string{}, allowed...), extra...), ok || has
			}
			if !ok {
				errs = append(errs, fmt.Sprintf("column %s: pins.toml [conformance.columns] has no %q list", id, c.SDK))
				continue
			}
			found := false
			for _, v := range allowed {
				found = found || v == c.Version
			}
			if !found {
				errs = append(errs, fmt.Sprintf("column %s: version %s is not in pins.toml conformance.columns.%s %v", id, c.Version, c.SDK, allowed))
			}
		case "core":
			if c.Version != p.StellarCore.Version {
				errs = append(errs, fmt.Sprintf("column %s: version %s is not the pinned stellar-core %s", id, c.Version, p.StellarCore.Version))
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

func (s *Sets) columnIDs() []string {
	ids := make([]string, 0, len(s.Columns))
	for id := range s.Columns {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// SetNames returns the set names, sorted.
func (s *Sets) SetNames() []string {
	names := make([]string, 0, len(s.Sets))
	for n := range s.Sets {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Resolve returns the columns of a named set, sorted by ID. A member "@other" includes the set "other".
func (s *Sets) Resolve(name string) ([]*Column, error) {
	ids := map[string]bool{}
	if err := s.resolve(name, ids, map[string]bool{}); err != nil {
		return nil, err
	}
	return s.byIDs(ids), nil
}

func (s *Sets) resolve(name string, out, visiting map[string]bool) error {
	members, ok := s.Sets[name]
	if !ok {
		return fmt.Errorf("unknown column set %q (sets: %s)", name, strings.Join(s.SetNames(), ", "))
	}
	if visiting[name] {
		return fmt.Errorf("column set %q includes itself", name)
	}
	visiting[name] = true
	defer delete(visiting, name)
	for _, m := range members {
		if inc, ok := strings.CutPrefix(m, "@"); ok {
			if err := s.resolve(inc, out, visiting); err != nil {
				return fmt.Errorf("set %s: %w", name, err)
			}
			continue
		}
		if s.Columns[m] == nil {
			return fmt.Errorf("set %s: unknown column %q", name, m)
		}
		out[m] = true
	}
	return nil
}

// Match returns the columns whose ID matches any of the comma-separated globs, sorted by ID.
func (s *Sets) Match(globs string) ([]*Column, error) {
	g, err := CompileGlobs(globs)
	if err != nil {
		return nil, err
	}
	ids := map[string]bool{}
	for id := range s.Columns {
		if g.Match(id) {
			ids[id] = true
		}
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("--columns %q matches no column", globs)
	}
	return s.byIDs(ids), nil
}

// Select picks columns by --set or --columns; with neither, the default set "pr".
func (s *Sets) Select(setName, globs string) ([]*Column, error) {
	switch {
	case setName != "" && globs != "":
		return nil, fmt.Errorf("--set and --columns are exclusive")
	case globs != "":
		return s.Match(globs)
	case setName != "":
		return s.Resolve(setName)
	}
	return s.Resolve(DefaultSet)
}

// DefaultSet is the column set used when neither --set nor --columns is given.
const DefaultSet = "pr"

// PrivateColumns returns the IDs of the columns an overlay's sets file added, sorted.
func (s *Sets) PrivateColumns() []string {
	var out []string
	for _, id := range s.columnIDs() {
		if s.Columns[id].Base != "" {
			out = append(out, id)
		}
	}
	return out
}

// CheckOverlay refuses a selection that includes a column of the overlay's sets file when the run is not given
// the overlay (with it, the report must be written outside the working tree). setName is the --set value, for
// the message.
func (s *Sets) CheckOverlay(setName string, cols []*Column, haveOverlay bool) error {
	if haveOverlay {
		return nil
	}
	for _, c := range cols {
		if c.Base != "" {
			if setName != "" {
				return fmt.Errorf("set %q includes %s from the overlay's sets file; pass --overlay", setName, c.ID)
			}
			return fmt.Errorf("column %s comes from the overlay's sets file; pass --overlay", c.ID)
		}
	}
	return nil
}

func (s *Sets) byIDs(ids map[string]bool) []*Column {
	out := make([]*Column, 0, len(ids))
	for _, id := range s.columnIDs() {
		if ids[id] {
			out = append(out, s.Columns[id])
		}
	}
	return out
}

// AbsDir returns the column's driver directory.
func (s *Sets) AbsDir(c *Column) string {
	if c.SourceDir != "" {
		return c.SourceDir
	}
	if filepath.IsAbs(c.Dir) {
		return c.Dir
	}
	if c.Base != "" {
		return filepath.Join(c.Base, filepath.FromSlash(c.Dir))
	}
	return filepath.Join(s.Root, filepath.FromSlash(c.Dir))
}

// Globs is a list of shell-style patterns where '*' matches any run of characters, slashes included, and '?'
// one character.
type Globs []*regexp.Regexp

// CompileGlobs compiles comma-separated globs. An empty string matches everything.
func CompileGlobs(s string) (Globs, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var g Globs
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		var b strings.Builder
		b.WriteByte('^')
		for _, r := range p {
			switch r {
			case '*':
				b.WriteString(".*")
			case '?':
				b.WriteByte('.')
			default:
				b.WriteString(regexp.QuoteMeta(string(r)))
			}
		}
		b.WriteByte('$')
		re, err := regexp.Compile(b.String())
		if err != nil {
			return nil, fmt.Errorf("glob %q: %w", p, err)
		}
		g = append(g, re)
	}
	return g, nil
}

// Match reports whether s matches any glob; an empty list matches everything.
func (g Globs) Match(s string) bool {
	if len(g) == 0 {
		return true
	}
	for _, re := range g {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

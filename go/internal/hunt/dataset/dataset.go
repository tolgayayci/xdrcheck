// Package dataset reads the dataset manifest: which version of the derived data is present (census, covers,
// tokens, leads, the kept-ledger index, the locate index, value tags, corpus entries, findings), where each
// table's files are and their sha256, and the named ledger sets that ship with it.
//
// The manifest never copies large files: it points at them through named roots ("${derived}/tokens/…"), and a
// root can be moved with an environment variable (<TOOL>_DATASET_ROOT_<NAME>), so one manifest serves two
// machines whose data lives under different paths. docs/data.md describes the format.
package dataset

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/tolgayayci/xdrcheck/go/internal/hunt"
)

// ManifestFile is the dataset manifest's file name inside the dataset directory.
const ManifestFile = "manifest.json"

// Manifest is the dataset manifest.
type Manifest struct {
	Schema    string            `json:"schema"`
	Version   string            `json:"version"`
	Network   string            `json:"network"`
	TipLedger uint32            `json:"tip_ledger"`
	Created   string            `json:"created,omitempty"`
	Roots     map[string]string `json:"roots"`
	Lakes     []string          `json:"lakes,omitempty"`
	Tables    map[string]*Table `json:"tables"`
	Sets      map[string]*Set   `json:"sets"`

	dir string // the dataset directory (relative paths resolve against it)
}

// Table is one queryable table.
type Table struct {
	Description string `json:"description"`
	// Format is tsv (tab-separated, header line, optionally zstd-compressed) or parquet.
	Format string `json:"format"`
	Files  []File `json:"files,omitempty"`
	// Glob replaces Files for very large file sets (the scan's per-block Parquet files); their checksums are the
	// scan's own MANIFEST.json files, named by ChecksumGlob, and are not recomputed.
	Glob         string `json:"glob,omitempty"`
	ChecksumGlob string `json:"checksum_glob,omitempty"`
	// FilenameColumns adds columns whose value is the first group of a regular expression on the file name.
	FilenameColumns map[string]string `json:"filename_columns,omitempty"`
	// Missing says why a table the dataset format defines has no files yet (its producer has not run).
	Missing string `json:"missing,omitempty"`
}

// File is one file of a table or a set.
type File struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

// Set is one named ledger set: a file of ledger sequences, or of ledger and transaction index pairs.
type Set struct {
	Description string `json:"description"`
	File        *File  `json:"file,omitempty"`
	// Unit is ledger (one sequence per line) or tx (ledger<TAB>tx_index per line).
	Unit    string `json:"unit"`
	Count   int    `json:"count,omitempty"`
	Missing string `json:"missing,omitempty"`
}

// Dir returns the dataset directory: --dataset, else $<TOOL>_DATASET, else <data dir>/dataset.
func Dir(flag string) string {
	if flag != "" {
		return flag
	}
	if d := hunt.Env("DATASET"); d != "" {
		return d
	}
	return filepath.Join(hunt.DataDir(), "dataset")
}

// Load reads the manifest of a dataset directory.
func Load(dir string) (*Manifest, error) {
	b, err := os.ReadFile(filepath.Join(dir, ManifestFile))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, hunt.Missing("dataset manifest "+filepath.Join(dir, ManifestFile), "give --dataset DIR or set "+hunt.EnvName("DATASET")+"; `"+hunt.Tool+" data manifest` writes one")
		}
		return nil, err
	}
	m := &Manifest{}
	if err := json.Unmarshal(b, m); err != nil {
		return nil, fmt.Errorf("%s: %v", filepath.Join(dir, ManifestFile), err)
	}
	if m.Schema != hunt.SchemaID("dataset") {
		return nil, fmt.Errorf("%s: schema %q, want %q", filepath.Join(dir, ManifestFile), m.Schema, hunt.SchemaID("dataset"))
	}
	m.dir = dir
	if m.Tables == nil {
		m.Tables = map[string]*Table{}
	}
	if m.Sets == nil {
		m.Sets = map[string]*Set{}
	}
	return m, nil
}

// Path returns the manifest's own path.
func (m *Manifest) Path() string { return filepath.Join(m.dir, ManifestFile) }

// DirPath returns the dataset directory.
func (m *Manifest) DirPath() string { return m.dir }

var rootRef = regexp.MustCompile(`\$\{([a-z0-9_]+)\}`)

// Root returns a root's path, after the environment override <TOOL>_DATASET_ROOT_<NAME>.
func (m *Manifest) Root(name string) string {
	if v := hunt.Env("DATASET_ROOT_" + strings.ToUpper(name)); v != "" {
		return v
	}
	return m.Roots[name]
}

// Resolve expands ${root} references and makes a relative path relative to the dataset directory.
func (m *Manifest) Resolve(p string) string {
	p = rootRef.ReplaceAllStringFunc(p, func(s string) string {
		return m.Root(rootRef.FindStringSubmatch(s)[1])
	})
	if !filepath.IsAbs(p) {
		p = filepath.Join(m.dir, p)
	}
	return p
}

// TableNames returns the table names in order.
func (m *Manifest) TableNames() []string {
	var out []string
	for n := range m.Tables {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// SetNames returns the set names in order.
func (m *Manifest) SetNames() []string {
	var out []string
	for n := range m.Sets {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// TablePaths returns the resolved file paths (or the resolved glob) of a table.
func (m *Manifest) TablePaths(name string) ([]string, error) {
	t := m.Tables[name]
	if t == nil {
		return nil, fmt.Errorf("no table %q in dataset %s (tables: %s)", name, m.Version, strings.Join(m.TableNames(), ", "))
	}
	if t.Missing != "" {
		return nil, hunt.Missing("table "+name, t.Missing)
	}
	if t.Glob != "" {
		return []string{m.Resolve(t.Glob)}, nil
	}
	var out []string
	for _, f := range t.Files {
		out = append(out, m.Resolve(f.Path))
	}
	return out, nil
}

// FileOf describes a file on disk: its sha256 and size.
func FileOf(path string) (File, error) {
	f, err := os.Open(path)
	if err != nil {
		return File{}, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return File{}, err
	}
	return File{Path: path, SHA256: hex.EncodeToString(h.Sum(nil)), Bytes: n}, nil
}

// Check is the state of one file against the manifest.
type Check struct {
	Table, Path string
	State       string // ok, missing, size-differs, sha256-differs, not-checked
}

// Verify checks every file of every table and set: present and of the recorded size, and with deep the
// recorded sha256.
func (m *Manifest) Verify(deep bool) []Check {
	var out []Check
	one := func(owner string, f File) {
		p := m.Resolve(f.Path)
		c := Check{Table: owner, Path: p}
		st, err := os.Stat(p)
		switch {
		case err != nil:
			c.State = "missing"
		case st.Size() != f.Bytes:
			c.State = "size-differs"
		case deep:
			g, err := FileOf(p)
			if err != nil || g.SHA256 != f.SHA256 {
				c.State = "sha256-differs"
			} else {
				c.State = "ok"
			}
		default:
			c.State = "size-ok"
		}
		out = append(out, c)
	}
	for _, n := range m.TableNames() {
		t := m.Tables[n]
		for _, f := range t.Files {
			one(n, f)
		}
		if t.Glob != "" {
			matches, _ := filepath.Glob(m.Resolve(t.Glob))
			st := "not-checked"
			if len(matches) == 0 {
				st = "missing"
			}
			out = append(out, Check{Table: n, Path: fmt.Sprintf("%s (%d files)", m.Resolve(t.Glob), len(matches)), State: st})
		}
	}
	for _, n := range m.SetNames() {
		if s := m.Sets[n]; s.File != nil {
			one("set:"+n, *s.File)
		}
	}
	return out
}

// Save writes the manifest into dir.
func (m *Manifest) Save(dir string) error {
	m.Schema = hunt.SchemaID("dataset")
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp := filepath.Join(dir, ManifestFile+".tmp")
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		return err
	}
	m.dir = dir
	return os.Rename(tmp, filepath.Join(dir, ManifestFile))
}

// SetDir sets the directory relative paths resolve against (for a manifest built in memory).
func (m *Manifest) SetDir(dir string) { m.dir = dir }

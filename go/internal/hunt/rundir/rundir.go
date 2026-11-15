// Package rundir writes and reads a run directory, the data contract between a run (replay, xcheck) and
// whatever reads it (the dashboard, repro, a CI job):
//
//	manifest.json   what ran, on what, how and where (schemas/run-manifest.schema.json)
//	verdicts.jsonl  one row per result that is not a pass (schemas/run-verdict.schema.json)
//	clusters.json   rows grouped by check and class, with disposition (schemas/run-clusters.schema.json)
//	summary.json    status, counts, cost (schemas/run-summary.schema.json)
//	work/           the target's raw output and logs (not part of the contract)
//
// docs/run-directory.md describes the layout.
package rundir

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"

	"github.com/tolgayayci/xdrcheck/go/internal/hunt"
)

// File names inside a run directory.
const (
	ManifestFile = "manifest.json"
	VerdictsFile = "verdicts.jsonl"
	ClustersFile = "clusters.json"
	SummaryFile  = "summary.json"
	WorkDir      = "work"
)

// Manifest is manifest.json.
type Manifest struct {
	Schema    string      `json:"schema"`
	Tool      ToolInfo    `json:"tool"`
	Dataset   *DatasetRef `json:"dataset"`
	Target    string      `json:"target"`
	Version   VersionInfo `json:"version"`
	Network   string      `json:"network"`
	Selection Selection   `json:"selection"`
	Inputs    []Input     `json:"inputs"`
	Command   []string    `json:"command"`
	Host      Host        `json:"host"`
	Started   string      `json:"started"`
	Finished  string      `json:"finished"`
}

// ToolInfo names the tool that wrote the run.
type ToolInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Commit  string `json:"commit,omitempty"`
}

// DatasetRef names the dataset version a selection was resolved through.
type DatasetRef struct {
	Version        string `json:"version"`
	TipLedger      uint32 `json:"tip_ledger,omitempty"`
	ManifestSHA256 string `json:"manifest_sha256,omitempty"`
}

// VersionInfo is the target version as asked for and as built.
type VersionInfo struct {
	Requested string `json:"requested"`
	Resolved  string `json:"resolved"`
	Source    string `json:"source,omitempty"`
}

// Selection is what the command line selected.
type Selection struct {
	Ledgers     []uint32 `json:"ledgers,omitempty"`
	Txs         []string `json:"txs,omitempty"`
	Set         string   `json:"set,omitempty"`
	Cap         int      `json:"cap,omitempty"`
	Issue       string   `json:"issue,omitempty"`
	LedgerFiles []string `json:"ledger_files,omitempty"`
}

// Input is one ledger the run read.
type Input struct {
	Kind   string `json:"kind"`
	Ledger uint32 `json:"ledger"`
	Object string `json:"object,omitempty"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

// Host is where the run ran. The host name is written only when <TOOL>_REPORT_HOST=1.
type Host struct {
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	CPUs     int    `json:"cpus,omitempty"`
	Hostname string `json:"hostname,omitempty"`
}

// ThisHost describes the running machine.
func ThisHost() Host {
	h := Host{OS: runtime.GOOS, Arch: runtime.GOARCH, CPUs: runtime.NumCPU()}
	if hunt.Env("REPORT_HOST") == "1" {
		h.Hostname, _ = os.Hostname()
	}
	return h
}

// Verdict is one line of verdicts.jsonl.
type Verdict struct {
	Ledger   uint32         `json:"ledger"`
	Tx       *int           `json:"tx"`
	TxHash   string         `json:"tx_hash,omitempty"`
	Op       *int           `json:"op"`
	OpType   string         `json:"op_type,omitempty"`
	Check    string         `json:"check"`
	Class    string         `json:"class"`
	Verdict  string         `json:"verdict"`
	Evidence map[string]any `json:"evidence,omitempty"`
}

// TxKey returns "ledger:tx", or "ledger" for a ledger-level row.
func (v Verdict) TxKey() string {
	if v.Tx == nil {
		return fmt.Sprint(v.Ledger)
	}
	return fmt.Sprintf("%d:%d", v.Ledger, *v.Tx)
}

// Clusters is clusters.json.
type Clusters struct {
	Schema   string    `json:"schema"`
	Target   string    `json:"target"`
	Version  string    `json:"version"`
	Clusters []Cluster `json:"clusters"`
}

// Cluster is one group of verdict rows with the same check and class.
type Cluster struct {
	Key         string         `json:"key"`
	Check       string         `json:"check"`
	Class       string         `json:"class"`
	Count       int            `json:"count"`
	Txs         int            `json:"txs"`
	Ledgers     int            `json:"ledgers"`
	FirstLedger uint32         `json:"first_ledger"`
	LastLedger  uint32         `json:"last_ledger"`
	OpTypes     map[string]int `json:"op_types,omitempty"`
	Strata      map[string]int `json:"strata"`
	Examples    []Example      `json:"examples"`
	Disposition string         `json:"disposition"`
	Note        string         `json:"note,omitempty"`
	Finding     *string        `json:"finding"`
}

// Example is one row of a cluster, enough to cut a bundle from.
type Example struct {
	Ledger uint32 `json:"ledger"`
	Tx     *int   `json:"tx"`
	Op     *int   `json:"op,omitempty"`
	TxHash string `json:"tx_hash,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// Summary is summary.json.
type Summary struct {
	Schema   string                `json:"schema"`
	Status   string                `json:"status"`
	Message  string                `json:"message,omitempty"`
	Verdicts map[string]int        `json:"verdicts"`
	Checks   map[string]CheckCount `json:"checks"`
	Clusters map[string]int        `json:"clusters"`
	Cost     Cost                  `json:"cost"`
}

// CheckCount is how often a check ran and how often it did not pass.
type CheckCount struct {
	Tested int64 `json:"tested"`
	Failed int64 `json:"failed"`
}

// Cost is what the run took.
type Cost struct {
	WallS   float64 `json:"wall_s"`
	CPUS    float64 `json:"cpu_s,omitempty"`
	BuildS  float64 `json:"build_s,omitempty"`
	Ledgers int     `json:"ledgers"`
	Txs     int64   `json:"txs"`
}

// Statuses of a run.
const (
	StatusComplete    = "complete"
	StatusPartial     = "partial"
	StatusUnavailable = "unavailable"
	StatusFailed      = "failed"
)

// ClusterKey is the key of a (check, class) pair. It leaves out the target version on purpose.
func ClusterKey(check, class string) string { return check + "|" + class }

// WriteJSON writes v as indented JSON, atomically.
func WriteJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ReadJSON reads a JSON file into v.
func ReadJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// WriteVerdicts writes verdicts.jsonl, sorted by ledger, transaction, operation, check and class.
func WriteVerdicts(path string, rows []Verdict) error {
	SortVerdicts(rows)
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	for _, r := range rows {
		if err := enc.Encode(r); err != nil {
			f.Close()
			return err
		}
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// ReadVerdicts reads verdicts.jsonl.
func ReadVerdicts(path string) ([]Verdict, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Verdict
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for n := 1; sc.Scan(); n++ {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var v Verdict
		if err := json.Unmarshal(sc.Bytes(), &v); err != nil {
			return nil, fmt.Errorf("%s:%d: %v", path, n, err)
		}
		out = append(out, v)
	}
	return out, sc.Err()
}

func intOr(p *int, d int) int {
	if p == nil {
		return d
	}
	return *p
}

// SortVerdicts orders rows by ledger, transaction, operation, check and class.
func SortVerdicts(rows []Verdict) {
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.Ledger != b.Ledger {
			return a.Ledger < b.Ledger
		}
		if x, y := intOr(a.Tx, -1), intOr(b.Tx, -1); x != y {
			return x < y
		}
		if x, y := intOr(a.Op, -1), intOr(b.Op, -1); x != y {
			return x < y
		}
		if a.Check != b.Check {
			return a.Check < b.Check
		}
		return a.Class < b.Class
	})
}

// Dir is an open run directory.
type Dir struct{ Path string }

// Create makes a run directory (and its work/ subdirectory). An existing directory must not hold a manifest.
func Create(path string, overwrite bool) (*Dir, error) {
	if _, err := os.Stat(filepath.Join(path, ManifestFile)); err == nil && !overwrite {
		return nil, fmt.Errorf("%s already holds a run (pass --force to replace it)", path)
	}
	if overwrite {
		for _, f := range []string{ManifestFile, VerdictsFile, ClustersFile, SummaryFile} {
			os.Remove(filepath.Join(path, f))
		}
	}
	if err := os.MkdirAll(filepath.Join(path, WorkDir), 0o755); err != nil {
		return nil, err
	}
	return &Dir{Path: path}, nil
}

// File returns the path of a file in the run directory.
func (d *Dir) File(name string) string { return filepath.Join(d.Path, name) }

// Work returns the path of a file or directory under work/.
func (d *Dir) Work(name ...string) string {
	return filepath.Join(append([]string{d.Path, WorkDir}, name...)...)
}

// Run is a whole run directory in memory.
type Run struct {
	Manifest Manifest
	Verdicts []Verdict
	Clusters Clusters
	Summary  Summary
}

// Load reads a run directory.
func Load(path string) (*Run, error) {
	r := &Run{}
	if err := ReadJSON(filepath.Join(path, ManifestFile), &r.Manifest); err != nil {
		return nil, err
	}
	v, err := ReadVerdicts(filepath.Join(path, VerdictsFile))
	if err != nil {
		return nil, err
	}
	r.Verdicts = v
	if err := ReadJSON(filepath.Join(path, ClustersFile), &r.Clusters); err != nil {
		return nil, err
	}
	if err := ReadJSON(filepath.Join(path, SummaryFile), &r.Summary); err != nil {
		return nil, err
	}
	return r, nil
}

// Save writes every contract file of r into the directory.
func (d *Dir) Save(r *Run) error {
	r.Manifest.Schema = hunt.SchemaID("run")
	r.Clusters.Schema = hunt.SchemaID("run.clusters")
	r.Summary.Schema = hunt.SchemaID("run.summary")
	if r.Manifest.Inputs == nil {
		r.Manifest.Inputs = []Input{}
	}
	if r.Clusters.Clusters == nil {
		r.Clusters.Clusters = []Cluster{}
	}
	if r.Summary.Verdicts == nil {
		r.Summary.Verdicts = map[string]int{}
	}
	if r.Summary.Checks == nil {
		r.Summary.Checks = map[string]CheckCount{}
	}
	if r.Summary.Clusters == nil {
		r.Summary.Clusters = map[string]int{}
	}
	if err := WriteVerdicts(d.File(VerdictsFile), r.Verdicts); err != nil {
		return err
	}
	if err := WriteJSON(d.File(ClustersFile), r.Clusters); err != nil {
		return err
	}
	if err := WriteJSON(d.File(SummaryFile), r.Summary); err != nil {
		return err
	}
	return WriteJSON(d.File(ManifestFile), r.Manifest)
}

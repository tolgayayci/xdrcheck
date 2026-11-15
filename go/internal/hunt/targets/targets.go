// Package targets builds a target at any version and runs it over ledgers.
//
// SDK targets (go, js, python, rust) are the kit's sweep programs, embedded in the binary (_sweep/), written
// into a cache directory per target and version, and built against that version of the SDK: a release tag, a
// commit, a branch such as main, or a local checkout. Pipeline targets (wallet-backend, stellar-etl, horizon)
// are run through a rig program, and their rows are judged by the judge program; both are separate tools,
// found on PATH or through an environment variable (docs/replay.md, "Pipeline targets"). A target whose tool is
// missing returns a hunt.Unavailable error and no result.
package targets

import (
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/tolgayayci/xdrcheck/go/internal/hunt"
	"github.com/tolgayayci/xdrcheck/go/internal/hunt/rundir"
)

//go:embed all:_sweep
var sweepFS embed.FS

// Names lists every target.
var Names = []string{"go", "js", "rust", "python", "wallet-backend", "stellar-etl", "horizon"}

// SDK reports whether a target is an SDK (built from the embedded sweep programs).
func SDK(name string) bool {
	switch name {
	case "go", "js", "rust", "python":
		return true
	}
	return false
}

// Options configure a build and a run.
type Options struct {
	Version    string    // tag, commit, branch or local path
	Passphrase string    // network passphrase of the inputs
	Offline    bool      // never touch the network: use what the cache holds
	Rebuild    bool      // rebuild even when the cache holds a build of an immutable version
	Log        io.Writer // build and run logs
	RigArgs    []string  // pipeline targets: extra rig flags, after the fixed ones (last one wins)
	Scope      string    // pipeline targets: the judge's scope file (verdict --scope)
	JudgeJobs  int       // pipeline targets: judge facts threads (0: the judge's default)
}

// Built is a target built at one version.
type Built struct {
	Target   string
	Dir      string // cache directory of this build
	Resolved string // what was built (tag, pseudo-version, commit)
	Source   string // where from
	BuildS   float64
	// run is the command line that runs the sweep; set by Build
	run []string
	env []string
}

// Input is one ledger object.
type Input struct {
	Seq  uint32
	Path string
}

// Result is what a run produced.
type Result struct {
	Rows    []rundir.Verdict
	Tested  map[string]int64
	Ledgers int
	Txs     int64
	CPUS    float64
	// LedgerStatus: pipeline targets, the rig's per-ledger statuses (ingested, halted, skipped, …) by count.
	LedgerStatus map[string]int
}

// Target is one buildable, runnable target.
type Target interface {
	Build(ctx context.Context, o Options) (*Built, error)
	Run(ctx context.Context, b *Built, inputs []Input, work string, o Options) (*Result, error)
}

// Get returns a target by name.
func Get(name string) (Target, error) {
	switch name {
	case "go":
		return goTarget{}, nil
	case "js":
		return jsTarget{}, nil
	case "python":
		return pyTarget{}, nil
	case "rust":
		return rustTarget{}, nil
	case "wallet-backend", "stellar-etl", "horizon":
		return pipeTarget{name: name}, nil
	}
	return nil, fmt.Errorf("unknown target %q (one of %s)", name, strings.Join(Names, ", "))
}

// ---- helpers shared by the SDK targets

var (
	shaRe = regexp.MustCompile(`^[0-9a-f]{7,40}$`)
	tagRe = regexp.MustCompile(`^v?\d+\.\d+\.\d+([-+][0-9A-Za-z.-]+)?$`)
)

// VersionKind classifies a version string: path (an existing directory), tag, commit or branch.
func VersionKind(v string) string {
	if st, err := os.Stat(v); err == nil && st.IsDir() && (strings.Contains(v, "/") || strings.HasPrefix(v, ".")) {
		return "path"
	}
	switch {
	case tagRe.MatchString(v):
		return "tag"
	case shaRe.MatchString(v):
		return "commit"
	}
	return "branch"
}

// immutable reports whether a cached build of v can be reused without checking the source again.
func immutable(v string) bool {
	k := VersionKind(v)
	return k == "tag" || k == "commit" && len(v) == 40
}

func slug(v string) string {
	if VersionKind(v) == "path" {
		abs, _ := filepath.Abs(v)
		s := sha256.Sum256([]byte(abs))
		return "path-" + hex.EncodeToString(s[:6])
	}
	return regexp.MustCompile(`[^A-Za-z0-9._-]+`).ReplaceAllString(v, "_")
}

func cacheDir(target, version string) string {
	return filepath.Join(hunt.CacheDir(), "targets", target, slug(version))
}

// materialise writes the embedded sweep program of a target into dir. Files named *.tmpl lose the suffix
// unless a file of that name already exists (a go.mod or Cargo.toml already rewritten for the version).
func materialise(target, dir string) error {
	root := "_sweep/" + target
	return fs.WalkDir(sweepFS, root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel := strings.TrimPrefix(p, root)
		dst := filepath.Join(dir, rel)
		if d.IsDir() {
			return os.MkdirAll(dst, 0o755)
		}
		b, err := sweepFS.ReadFile(p)
		if err != nil {
			return err
		}
		if strings.HasSuffix(dst, ".tmpl") {
			dst = strings.TrimSuffix(dst, ".tmpl")
			if _, err := os.Stat(dst); err == nil {
				return nil
			}
		}
		if old, err := os.ReadFile(dst); err == nil && bytes.Equal(old, b) {
			return nil
		}
		return os.WriteFile(dst, b, 0o644)
	})
}

// programHash is the sha256 of a target's embedded sweep source: a cached build of other source is rebuilt.
func programHash(target string) string {
	src, err := SweepSource(target)
	if err != nil {
		return ""
	}
	h := sha256.New()
	for _, k := range sortedKeys(src) {
		h.Write([]byte(k + "\x00"))
		h.Write(src[k])
	}
	return hex.EncodeToString(h.Sum(nil))
}

// SweepSource returns the embedded source of one target's sweep program (for bundles and docs).
func SweepSource(target string) (map[string][]byte, error) {
	out := map[string][]byte{}
	root := "_sweep/" + target
	err := fs.WalkDir(sweepFS, root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := sweepFS.ReadFile(p)
		out[strings.TrimPrefix(p, root+"/")] = b
		return err
	})
	return out, err
}

func need(tool, hint string) (string, error) {
	p, err := exec.LookPath(tool)
	if err != nil {
		return "", hunt.Missing(tool, hint)
	}
	return p, nil
}

func run(ctx context.Context, dir string, env []string, log io.Writer, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	var tail bytes.Buffer
	w := io.Writer(&tail)
	if log != nil {
		w = io.MultiWriter(log, &tail)
	}
	cmd.Stdout, cmd.Stderr = w, w
	if err := cmd.Run(); err != nil {
		t := tail.String()
		if len(t) > 2000 {
			t = t[len(t)-2000:]
		}
		return fmt.Errorf("%s %s: %v\n%s", name, strings.Join(args, " "), err, t)
	}
	return nil
}

func output(ctx context.Context, dir string, env []string, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	b, err := cmd.Output()
	return strings.TrimSpace(string(b)), err
}

// stamp records a finished build: the resolved version and source, read back by a cached build.
type stamp struct {
	Program  string `json:"program"` // sha256 of the embedded sweep source it was built from
	Resolved string `json:"resolved"`
	Source   string `json:"source"`
	Built    string `json:"built"`
}

func readStamp(dir string) *stamp {
	var s stamp
	if rundir.ReadJSON(filepath.Join(dir, "build.json"), &s) != nil || s.Resolved == "" {
		return nil
	}
	return &s
}

func writeStamp(dir string, s stamp) error {
	s.Built = time.Now().UTC().Format(time.RFC3339)
	return rundir.WriteJSON(filepath.Join(dir, "build.json"), s)
}

// WriteList writes the list file the sweeps read: seq<TAB>absolute path.
func WriteList(path string, inputs []Input) error {
	var b strings.Builder
	for _, in := range inputs {
		abs, _ := filepath.Abs(in.Path)
		fmt.Fprintf(&b, "%d\t%s\n", in.Seq, abs)
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

// sweepRow is one failure row as every sweep program writes it (rows.jsonl).
type sweepRow struct {
	Check  string          `json:"check"`
	Class  string          `json:"class"`
	Ledger uint32          `json:"ledger"`
	Tx     json.Number     `json:"tx"`
	Hash   string          `json:"hash"`
	Op     json.RawMessage `json:"op"`
	OpType string          `json:"op_type"`
	Detail string          `json:"detail"`
}

// ReadSweepRows converts a sweep's rows.jsonl into verdict rows.
func ReadSweepRows(path string) ([]rundir.Verdict, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []rundir.Verdict
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	for dec.More() {
		var r sweepRow
		if err := dec.Decode(&r); err != nil {
			return nil, fmt.Errorf("%s: %v", path, err)
		}
		v := rundir.Verdict{Ledger: r.Ledger, Check: r.Check, Class: r.Class, Verdict: "fail", OpType: r.OpType}
		if v.OpType == "-" {
			v.OpType = ""
		}
		if v.Class == "" {
			v.Class = "unclassified"
		}
		if n, err := strconv.Atoi(string(r.Tx)); err == nil && n >= 0 {
			v.Tx = &n
		}
		if len(r.Hash) == 64 {
			v.TxHash = r.Hash
		}
		var op string
		if json.Unmarshal(r.Op, &op) != nil {
			op = strings.Trim(string(r.Op), `"`)
		}
		if n, err := strconv.Atoi(op); err == nil && n >= 0 {
			v.Op = &n
		}
		if r.Detail != "" {
			v.Evidence = map[string]any{"detail": r.Detail}
		}
		out = append(out, v)
	}
	return out, nil
}

// ---- the stats every SDK sweep writes

type sweepStats struct {
	Version string           `json:"version"`
	Ledgers int              `json:"ledgers"`
	Txs     int64            `json:"txs"`
	Tested  map[string]int64 `json:"tested"`
}

func sortedKeys[V any](m map[string]V) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

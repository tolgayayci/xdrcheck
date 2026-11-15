package targets

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/tolgayayci/xdrcheck/go/internal/hunt"
	"github.com/tolgayayci/xdrcheck/go/internal/hunt/ledger"
	"github.com/tolgayayci/xdrcheck/go/internal/hunt/rundir"
)

// buildCached runs build unless dir holds a stamp of an immutable version.
func buildCached(target, dir string, o Options, build func() (stamp, error)) (*stamp, float64, error) {
	prog := programHash(target)
	if s := readStamp(dir); s != nil && s.Program == prog && (o.Offline || immutable(o.Version) && !o.Rebuild) {
		return s, 0, nil
	}
	if o.Offline {
		return nil, 0, fmt.Errorf("offline and no cached build in %s", dir)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, 0, err
	}
	// one build per directory at a time: parallel runs of a branch would otherwise clone into the same place
	waited := time.Now().UTC().Truncate(time.Second)
	unlock, err := lockDir(dir)
	if err != nil {
		return nil, 0, err
	}
	defer unlock()
	if s := readStamp(dir); s != nil && s.Program == prog {
		if b, err := time.Parse(time.RFC3339, s.Built); err == nil && !b.Before(waited) {
			return s, 0, nil // built by another run while this one waited
		}
	}
	t := time.Now()
	s, err := build()
	if err != nil {
		os.Remove(filepath.Join(dir, "build.json"))
		return nil, 0, err
	}
	s.Program = prog
	return &s, time.Since(t).Seconds(), writeStamp(dir, s)
}

// lockDir takes an exclusive advisory lock on dir/.build.lock until the returned function is called.
func lockDir(dir string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(dir, ".build.lock"), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() { syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}

// ---- go: github.com/stellar/go-stellar-sdk

const goModule = "github.com/stellar/go-stellar-sdk"

type goTarget struct{}

func (goTarget) Build(ctx context.Context, o Options) (*Built, error) {
	if _, err := need("go", "install Go to build the go target"); err != nil {
		return nil, err
	}
	dir := cacheDir("go", o.Version)
	target := "go"
	env := []string{"GOFLAGS=-mod=mod", "GOWORK=off"}
	s, secs, err := buildCached(target, dir, o, func() (stamp, error) {
		os.Remove(filepath.Join(dir, "go.mod"))
		os.Remove(filepath.Join(dir, "go.sum"))
		if err := materialise("go", dir); err != nil {
			return stamp{}, err
		}
		source := "https://" + goModule
		if VersionKind(o.Version) == "path" {
			abs, _ := filepath.Abs(o.Version)
			source = abs
			if err := run(ctx, dir, env, o.Log, "go", "mod", "edit", "-replace", goModule+"="+abs); err != nil {
				return stamp{}, err
			}
			if err := run(ctx, dir, env, o.Log, "go", "mod", "tidy"); err != nil {
				return stamp{}, err
			}
		} else if err := run(ctx, dir, env, o.Log, "go", "get", goModule+"@"+o.Version); err != nil {
			return stamp{}, err
		}
		if err := run(ctx, dir, env, o.Log, "go", "build", "-o", "sweep", "."); err != nil {
			return stamp{}, err
		}
		res, err := output(ctx, dir, env, "go", "list", "-m", "-f", "{{.Version}}{{with .Replace}} => {{.Path}}{{end}}", goModule)
		if err != nil {
			return stamp{}, err
		}
		return stamp{Resolved: res, Source: source}, nil
	})
	if err != nil {
		return nil, err
	}
	return &Built{Target: "go", Dir: dir, Resolved: s.Resolved, Source: s.Source, BuildS: secs}, nil
}

func (goTarget) Run(ctx context.Context, b *Built, inputs []Input, work string, o Options) (*Result, error) {
	idx := filepath.Join(work, "index.tsv")
	if err := WriteList(idx, inputs); err != nil {
		return nil, err
	}
	out := filepath.Join(work, "out")
	os.RemoveAll(out)
	rows := filepath.Join(work, "rows.jsonl")
	log, _ := os.Create(filepath.Join(work, "sweep.log"))
	defer log.Close()
	t := time.Now()
	err := run(ctx, work, nil, log, filepath.Join(b.Dir, "sweep"), "-index", idx, "-root", "/", "-out", out, "-rows", rows, "-passphrase", o.Passphrase)
	if err != nil {
		return nil, err
	}
	vs, err := ReadSweepRows(rows)
	if err != nil {
		return nil, err
	}
	var st struct {
		Tested  map[string]int64 `json:"tested"`
		Ledgers int              `json:"ledgers"`
		Txs     int64            `json:"txs"`
		CPU     float64          `json:"cpu_s"`
	}
	if err := rundir.ReadJSON(filepath.Join(out, "state.json"), &st); err != nil {
		return nil, err
	}
	_ = t
	return &Result{Rows: vs, Tested: st.Tested, Ledgers: st.Ledgers, Txs: st.Txs, CPUS: st.CPU}, nil
}

// ---- js: @stellar/stellar-sdk

type jsTarget struct{}

func (jsTarget) Build(ctx context.Context, o Options) (*Built, error) {
	if _, err := need("node", "install Node.js 22.15 or newer (zstd in node:zlib) to run the js target"); err != nil {
		return nil, err
	}
	if _, err := need("npm", "install npm to fetch the js target"); err != nil {
		return nil, err
	}
	dir := cacheDir("js", o.Version)
	target := "js"
	s, secs, err := buildCached(target, dir, o, func() (stamp, error) {
		if err := materialise("js", dir); err != nil {
			return stamp{}, err
		}
		if _, err := os.Stat(filepath.Join(dir, "package.json")); err != nil {
			os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"sweep","private":true,"type":"module"}`+"\n"), 0o644)
		}
		spec, source := o.Version, "npm"
		switch VersionKind(o.Version) {
		case "path":
			abs, _ := filepath.Abs(o.Version)
			spec, source = "file:"+abs, abs
		case "commit", "branch":
			// a git ref has no built lib/: clone it, build it, install the build
			src, err := buildJSRef(ctx, dir, o)
			if err != nil {
				return stamp{}, err
			}
			spec, source = "file:"+src, "https://github.com/stellar/js-stellar-sdk"
		}
		if err := run(ctx, dir, nil, o.Log, "npm", "install", "--no-audit", "--no-fund", "--install-links", "@stellar/stellar-sdk@"+spec); err != nil {
			return stamp{}, err
		}
		var pkg struct {
			Version string `json:"version"`
		}
		if err := rundir.ReadJSON(filepath.Join(dir, "node_modules/@stellar/stellar-sdk/package.json"), &pkg); err != nil {
			return stamp{}, err
		}
		res := pkg.Version
		if VersionKind(o.Version) != "tag" {
			res += " (" + o.Version + ")"
		}
		return stamp{Resolved: res, Source: source}, nil
	})
	if err != nil {
		return nil, err
	}
	return &Built{Target: "js", Dir: dir, Resolved: s.Resolved, Source: s.Source, BuildS: secs}, nil
}

// cut writes the reference cut of every input into work/txs.
func cut(inputs []Input, work, passphrase string) (string, error) {
	txs := filepath.Join(work, "txs")
	for _, in := range inputs {
		if err := ledger.WriteCut(in.Path, passphrase, txs, in.Seq); err != nil {
			return "", fmt.Errorf("reference cut of ledger %d: %v", in.Seq, err)
		}
	}
	return txs, nil
}

func runSweep(ctx context.Context, work string, inputs []Input, o Options, env []string, name string, args func(list, txs, out string) []string) (*Result, error) {
	list := filepath.Join(work, "list.tsv")
	if err := WriteList(list, inputs); err != nil {
		return nil, err
	}
	txs, err := cut(inputs, work, o.Passphrase)
	if err != nil {
		return nil, err
	}
	out := filepath.Join(work, "out")
	os.RemoveAll(out)
	log, _ := os.Create(filepath.Join(work, "sweep.log"))
	defer log.Close()
	env = append(env, "SWEEP_PASSPHRASE="+o.Passphrase)
	if err := run(ctx, work, env, log, name, args(list, txs, out)...); err != nil {
		return nil, err
	}
	vs, err := ReadSweepRows(filepath.Join(out, "rows.jsonl"))
	if err != nil {
		return nil, err
	}
	var st sweepStats
	if err := rundir.ReadJSON(filepath.Join(out, "stats.json"), &st); err != nil {
		return nil, err
	}
	return &Result{Rows: vs, Tested: st.Tested, Ledgers: st.Ledgers, Txs: st.Txs}, nil
}

func (jsTarget) Run(ctx context.Context, b *Built, inputs []Input, work string, o Options) (*Result, error) {
	return runSweep(ctx, work, inputs, o, nil, "node", func(list, txs, out string) []string {
		return []string{"--max-old-space-size=2048", filepath.Join(b.Dir, "sweep.mjs"), b.Dir, list, txs, out}
	})
}

// ---- python: stellar-sdk (py-stellar-base)

type pyTarget struct{}

func (pyTarget) Build(ctx context.Context, o Options) (*Built, error) {
	py, err := need("python3", "install Python 3.10 or newer to run the python target")
	if err != nil {
		return nil, err
	}
	if _, err := need("zstd", "the python sweep reads ledgers through the zstd command"); err != nil {
		return nil, err
	}
	dir := cacheDir("python", o.Version)
	target := "python"
	s, secs, err := buildCached(target, dir, o, func() (stamp, error) {
		if err := materialise("python", dir); err != nil {
			return stamp{}, err
		}
		if err := run(ctx, dir, nil, o.Log, py, "-m", "venv", "venv"); err != nil {
			return stamp{}, err
		}
		spec, source := "stellar-sdk=="+o.Version, "pypi"
		switch VersionKind(o.Version) {
		case "path":
			abs, _ := filepath.Abs(o.Version)
			spec, source = abs, abs
		case "commit", "branch":
			spec, source = "git+https://github.com/StellarCN/py-stellar-base@"+o.Version, "https://github.com/StellarCN/py-stellar-base"
		}
		if err := run(ctx, dir, nil, o.Log, filepath.Join(dir, "venv/bin/pip"), "install", "--quiet", spec); err != nil {
			return stamp{}, err
		}
		v, err := output(ctx, dir, nil, filepath.Join(dir, "venv/bin/python"), "-c", "import stellar_sdk; print(stellar_sdk.__version__)")
		if err != nil {
			return stamp{}, err
		}
		if VersionKind(o.Version) != "tag" {
			v += " (" + o.Version + ")"
		}
		return stamp{Resolved: v, Source: source}, nil
	})
	if err != nil {
		return nil, err
	}
	return &Built{Target: "python", Dir: dir, Resolved: s.Resolved, Source: s.Source, BuildS: secs}, nil
}

func (pyTarget) Run(ctx context.Context, b *Built, inputs []Input, work string, o Options) (*Result, error) {
	return runSweep(ctx, work, inputs, o, nil, filepath.Join(b.Dir, "venv/bin/python"), func(list, txs, out string) []string {
		return []string{"-I", filepath.Join(b.Dir, "sweep.py"), list, txs, out}
	})
}

// ---- rust: stellar-xdr (rs-stellar-xdr)

type rustTarget struct{}

func (rustTarget) Build(ctx context.Context, o Options) (*Built, error) {
	if _, err := need("cargo", "install Rust to build the rust target"); err != nil {
		return nil, err
	}
	dir := cacheDir("rust", o.Version)
	target := "rust"
	s, secs, err := buildCached(target, dir, o, func() (stamp, error) {
		os.Remove(filepath.Join(dir, "Cargo.toml"))
		if err := materialise("rust", dir); err != nil {
			return stamp{}, err
		}
		b, err := os.ReadFile(filepath.Join(dir, "Cargo.toml"))
		if err != nil {
			return stamp{}, err
		}
		dep, source := `version = "=`+strings.TrimPrefix(o.Version, "v")+`"`, "crates.io"
		switch VersionKind(o.Version) {
		case "path":
			abs, _ := filepath.Abs(o.Version)
			dep, source = `path = "`+abs+`"`, abs
			os.Remove(filepath.Join(dir, "Cargo.lock"))
		case "commit":
			dep, source = `git = "https://github.com/stellar/rs-stellar-xdr", rev = "`+o.Version+`"`, "https://github.com/stellar/rs-stellar-xdr"
			os.Remove(filepath.Join(dir, "Cargo.lock"))
		case "branch":
			dep, source = `git = "https://github.com/stellar/rs-stellar-xdr", branch = "`+o.Version+`"`, "https://github.com/stellar/rs-stellar-xdr"
			os.Remove(filepath.Join(dir, "Cargo.lock"))
		}
		toml := strings.Replace(string(b), `version = "=@VERSION@"`, dep, 1)
		if err := os.WriteFile(filepath.Join(dir, "Cargo.toml"), []byte(toml), 0o644); err != nil {
			return stamp{}, err
		}
		if err := run(ctx, dir, []string{"CARGO_TARGET_DIR=" + filepath.Join(dir, "target")}, o.Log, "cargo", "build", "--release", "--quiet"); err != nil {
			return stamp{}, err
		}
		return stamp{Resolved: lockVersion(filepath.Join(dir, "Cargo.lock"), "stellar-xdr"), Source: source}, nil
	})
	if err != nil {
		return nil, err
	}
	return &Built{Target: "rust", Dir: dir, Resolved: s.Resolved, Source: s.Source, BuildS: secs}, nil
}

// lockVersion returns "version (source)" of a package in a Cargo.lock.
func lockVersion(lock, pkg string) string {
	f, err := os.Open(lock)
	if err != nil {
		return "unknown"
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	in := false
	ver, src := "", ""
	for sc.Scan() {
		l := sc.Text()
		switch {
		case l == "[[package]]":
			if in {
				break
			}
		case l == `name = "`+pkg+`"`:
			in = true
		case in && strings.HasPrefix(l, "version = "):
			ver = strings.Trim(strings.TrimPrefix(l, "version = "), `"`)
		case in && strings.HasPrefix(l, "source = "):
			src = strings.Trim(strings.TrimPrefix(l, "source = "), `"`)
		case in && l == "":
			in = false
		}
		if ver != "" && !in {
			break
		}
	}
	if strings.HasPrefix(src, "git+") {
		if i := strings.LastIndex(src, "#"); i > 0 {
			return ver + " (" + src[i+1:] + ")"
		}
	}
	if ver == "" {
		return "unknown"
	}
	return ver
}

func (rustTarget) Run(ctx context.Context, b *Built, inputs []Input, work string, o Options) (*Result, error) {
	list := filepath.Join(work, "list.tsv")
	if err := WriteList(list, inputs); err != nil {
		return nil, err
	}
	out := filepath.Join(work, "out")
	os.RemoveAll(out)
	log, _ := os.Create(filepath.Join(work, "sweep.log"))
	defer log.Close()
	env := []string{"SWEEP_PASSPHRASE=" + o.Passphrase, "SWEEP_VERSION=" + b.Resolved}
	if err := run(ctx, work, env, log, filepath.Join(b.Dir, "target/release/sweep"), "run", list, "/", out); err != nil {
		return nil, err
	}
	vs, err := ReadSweepRows(filepath.Join(out, "rows.jsonl"))
	if err != nil {
		return nil, err
	}
	res := &Result{Rows: vs, Tested: map[string]int64{}}
	// the last stats line is the final one
	if data, err := os.ReadFile(filepath.Join(out, "stats.jsonl")); err == nil {
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		var st struct {
			Ledgers int   `json:"ledgers"`
			Txs     int64 `json:"txs"`
		}
		if json.Unmarshal([]byte(lines[len(lines)-1]), &st) == nil {
			res.Ledgers, res.Txs = st.Ledgers, st.Txs
			res.Tested["codec"] = int64(len(inputs))
			res.Tested["extract"] = int64(st.Ledgers)
			res.Tested["json-roundtrip"] = 3 * st.Txs
		}
	}
	return res, nil
}

var _ = hunt.Tool

// ---- fields (xcheck): each SDK target's view of every transaction, as JSONL

// Fielder is a target that can write the fields xcheck compares.
type Fielder interface {
	Fields(ctx context.Context, b *Built, inputs []Input, work string, o Options) (string, error)
}

func fieldsPrep(inputs []Input, work, passphrase string) (list, txs, out string, err error) {
	if err = os.MkdirAll(work, 0o755); err != nil {
		return
	}
	list = filepath.Join(work, "list.tsv")
	if err = WriteList(list, inputs); err != nil {
		return
	}
	txs, err = cut(inputs, work, passphrase)
	out = filepath.Join(work, "fields.jsonl")
	return
}

func (goTarget) Fields(ctx context.Context, b *Built, inputs []Input, work string, o Options) (string, error) {
	list, txs, out, err := fieldsPrep(inputs, work, o.Passphrase)
	if err != nil {
		return "", err
	}
	return out, run(ctx, work, nil, nil, filepath.Join(b.Dir, "sweep"), "-fields", out, "-cut", txs, "-list", list, "-passphrase", o.Passphrase)
}

func (jsTarget) Fields(ctx context.Context, b *Built, inputs []Input, work string, o Options) (string, error) {
	list, txs, out, err := fieldsPrep(inputs, work, o.Passphrase)
	if err != nil {
		return "", err
	}
	return out, run(ctx, work, []string{"SWEEP_PASSPHRASE=" + o.Passphrase}, nil, "node", filepath.Join(b.Dir, "fields.mjs"), b.Dir, list, txs, out)
}

func (pyTarget) Fields(ctx context.Context, b *Built, inputs []Input, work string, o Options) (string, error) {
	list, txs, out, err := fieldsPrep(inputs, work, o.Passphrase)
	if err != nil {
		return "", err
	}
	return out, run(ctx, work, []string{"SWEEP_PASSPHRASE=" + o.Passphrase}, nil, filepath.Join(b.Dir, "venv/bin/python"), "-I", filepath.Join(b.Dir, "fields.py"), list, txs, out)
}

func (rustTarget) Fields(ctx context.Context, b *Built, inputs []Input, work string, o Options) (string, error) {
	list, txs, out, err := fieldsPrep(inputs, work, o.Passphrase)
	if err != nil {
		return "", err
	}
	return out, run(ctx, work, []string{"SWEEP_PASSPHRASE=" + o.Passphrase}, nil, filepath.Join(b.Dir, "target/release/sweep"), "fields", list, txs, out)
}

// buildJSRef clones js-stellar-sdk at a branch or commit into dir/src and builds it.
func buildJSRef(ctx context.Context, dir string, o Options) (string, error) {
	src := filepath.Join(dir, "src")
	os.RemoveAll(src)
	env := []string{"GIT_TERMINAL_PROMPT=0"}
	if err := run(ctx, dir, env, o.Log, "git", "clone", "--quiet", "--filter=blob:none", "https://github.com/stellar/js-stellar-sdk.git", src); err != nil {
		return "", err
	}
	if err := run(ctx, src, env, o.Log, "git", "checkout", "--quiet", o.Version); err != nil {
		return "", err
	}
	if err := run(ctx, src, nil, o.Log, "npm", "install", "--no-audit", "--no-fund", "--ignore-scripts"); err != nil {
		return "", err
	}
	if err := run(ctx, src, nil, o.Log, "npm", "run", "build:prod"); err != nil {
		if err2 := run(ctx, src, nil, o.Log, "npm", "run", "build"); err2 != nil {
			return "", err2
		}
	}
	return src, nil
}

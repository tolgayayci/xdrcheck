package xdrdef

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/tolgayayci/xdrcheck/go/internal/userdir"
)

// DefaultRepoURL is the XDR definitions repository.
const DefaultRepoURL = "https://github.com/stellar/stellar-xdr.git"

// Repo is a blobless bare clone of a git repository in a cache directory, read with plain git commands.
// Only fetches touch the network; a full commit hash already in the clone is read without one.
type Repo struct {
	URL string
	Dir string
	// Shallow fetches only the tip of a ref, with its files (for a repository read whole at one commit),
	// instead of the full history without file contents.
	Shallow bool
}

// CacheDir is $XDRCHECK_CACHE (default ~/.cache/xdrcheck).
func CacheDir() string {
	if d := os.Getenv("XDRCHECK_CACHE"); d != "" {
		return d
	}
	if d, ok := userdir.HomeCache(); ok {
		return d
	}
	return ".cache/xdrcheck"
}

// NewRepo is a clone of url kept under $XDRCHECK_CACHE/src/<name>.
func NewRepo(url, name string) *Repo {
	return &Repo{URL: url, Dir: filepath.Join(CacheDir(), "src", name+".git")}
}

func (r *Repo) git(args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", r.Dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}

func (r *Repo) ensure() error {
	if _, err := os.Stat(filepath.Join(r.Dir, "HEAD")); err == nil {
		_, err := r.git("remote", "set-url", "origin", r.URL)
		return err
	}
	if err := os.MkdirAll(r.Dir, 0o755); err != nil {
		return err
	}
	steps := [][]string{{"init", "--quiet", "--bare"}, {"remote", "add", "origin", r.URL}}
	if !r.Shallow {
		steps = append(steps, []string{"config", "remote.origin.promisor", "true"},
			[]string{"config", "remote.origin.partialclonefilter", "blob:none"})
	}
	for _, a := range steps {
		if _, err := r.git(a...); err != nil {
			return err
		}
	}
	return nil
}

var fullHash = regexp.MustCompile(`^[0-9a-f]{40}$`)

// Resolve fetches a ref (branch, tag, `refs/pull/N/head`, or commit) and returns its commit. A full commit
// hash the clone already holds is returned without a fetch.
func (r *Repo) Resolve(ref string) (string, error) {
	if err := r.ensure(); err != nil {
		return "", err
	}
	if fullHash.MatchString(ref) {
		if _, err := r.git("cat-file", "-e", ref+"^{commit}"); err == nil {
			return ref, nil
		}
	}
	args := []string{"fetch", "--quiet", "--filter=blob:none", "--no-tags", "origin", ref}
	if r.Shallow {
		args = []string{"fetch", "--quiet", "--depth", "1", "--no-tags", "origin", ref}
	}
	if _, err := r.git(args...); err != nil {
		return "", err
	}
	out, err := r.git("rev-parse", "FETCH_HEAD")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// ReadFiles returns the files of a commit whose top-level names match the suffix (".x"), by name.
func (r *Repo) ReadFiles(commit, suffix string) (map[string]string, error) {
	out, err := r.git("ls-tree", "--name-only", commit)
	if err != nil {
		return nil, err
	}
	files := map[string]string{}
	for _, n := range strings.Fields(out) {
		if !strings.HasSuffix(n, suffix) {
			continue
		}
		b, err := r.git("show", commit+":"+n)
		if err != nil {
			return nil, err
		}
		files[n] = b
	}
	return files, nil
}

// ReadFile returns one file at a commit.
func (r *Repo) ReadFile(commit, path string) (string, error) {
	return r.git("show", commit+":"+path)
}

// Heads lists the remote's branches (name → commit).
func (r *Repo) Heads() (map[string]string, error) {
	if err := r.ensure(); err != nil {
		return nil, err
	}
	out, err := r.git("ls-remote", "--heads", "origin")
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 {
			m[strings.TrimPrefix(f[1], "refs/heads/")] = f[0]
		}
	}
	return m, nil
}

// MergeBase is the best common ancestor of two commits the clone holds. Blobless clones are full-depth, so
// the history is there.
func (r *Repo) MergeBase(a, b string) (string, error) {
	out, err := r.git("merge-base", a, b)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// ParseFiles parses .x texts by file name into a set, in name order.
func ParseFiles(files map[string]string) (*Set, error) {
	if len(files) == 0 {
		return nil, fmt.Errorf("no .x files")
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var all []*Def
	for _, n := range names {
		defs, err := ParseFile(n, files[n])
		if err != nil {
			return nil, err
		}
		all = append(all, defs...)
	}
	return NewSet(all)
}

// Input is a definition set as given on the command line, before features are chosen.
type Input struct {
	Set  *Set
	Side Side
}

// LoadInput reads one diff input: a directory of .x files, a definitions JSON file (.json or .json.zst), or
// a git ref of repo (`pinned` is the pinned commit).
func LoadInput(arg string, repo *Repo, pinned string) (*Input, error) {
	if st, err := os.Stat(arg); err == nil {
		if st.IsDir() {
			s, err := ParseDir(arg)
			if err != nil {
				return nil, err
			}
			return &Input{s, Side{Label: arg, Gates: s.Features()}}, nil
		}
		if strings.HasSuffix(arg, ".json") || strings.HasSuffix(arg, ".json.zst") {
			s, err := LoadIR(arg)
			if err != nil {
				return nil, err
			}
			return &Input{s, Side{Label: filepath.Base(arg), Gates: []string{}}}, nil
		}
		return nil, fmt.Errorf("%s: not a directory of .x files or a definitions .json(.zst) file", arg)
	}
	ref := arg
	if arg == "pinned" {
		if pinned == "" {
			return nil, fmt.Errorf("pinned: no pinned commit")
		}
		ref = pinned
	}
	commit, err := repo.Resolve(ref)
	if err != nil {
		return nil, err
	}
	files, err := repo.ReadFiles(commit, ".x")
	if err != nil {
		return nil, err
	}
	s, err := ParseFiles(files)
	if err != nil {
		return nil, fmt.Errorf("%s at %s: %w", arg, short(commit), err)
	}
	return &Input{s, Side{Label: arg, Commit: commit, Gates: s.Features()}}, nil
}

// Features turns a features flag (`none`, `all`, or a comma-separated list) into the enabled set for an
// input; unknown names are kept (enabling a feature the source does not mention changes nothing).
func Features(spec string, s *Set) (map[string]bool, error) {
	switch spec {
	case "", "none":
		return map[string]bool{}, nil
	case "all":
		return s.EnableAll(), nil
	}
	m := map[string]bool{}
	for _, f := range strings.Split(spec, ",") {
		f = strings.TrimSpace(f)
		if f == "" || strings.ContainsAny(f, " !") {
			return nil, fmt.Errorf("bad feature name %q", f)
		}
		m[f] = true
	}
	return m, nil
}

// DiffInputs resolves both inputs for their features and diffs them.
func DiffInputs(base, head *Input, baseFeatures, headFeatures string, o DiffOptions) (*Report, error) {
	bf, err := Features(baseFeatures, base.Set)
	if err != nil {
		return nil, err
	}
	hf, err := Features(headFeatures, head.Set)
	if err != nil {
		return nil, err
	}
	bs, hs := base.Side, head.Side
	bs.Features, hs.Features = sortedKeys(bf), sortedKeys(hf)
	if bs.Gates == nil {
		bs.Gates = []string{}
	}
	if hs.Gates == nil {
		hs.Gates = []string{}
	}
	r := Diff(base.Set.Resolve(bf), head.Set.Resolve(hf), bs, hs, o)
	r.SortChanges()
	return r, nil
}

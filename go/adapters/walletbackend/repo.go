package walletbackend

// The source repository and the per-commit builds.
//
// wallet-backend has no tags, no releases and no per-commit images, so the adapter builds the binary from
// source at the requested commit. It keeps a bare clone of the repository in its cache directory, exports the
// commit's tree with `git archive` into a temporary directory (no worktree is registered, so none can be left
// behind), and builds it with the Go toolchain pinned in pins.toml ([pipelines.wallet_backend] go_toolchain)
// into bin/wallet-backend-<commit>. Builds are cached by commit; a cached binary is reused as is and its sha256
// is reported. The module cache, build cache and toolchain live under the same cache directory. Runs are
// offline (GOPROXY=off): `fetch` is the only step that downloads anything.

import (
	"archive/tar"
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// repo is the bare clone plus the build cache, rooted at dir.
type repo struct {
	dir       string // <cachedir>/wallet-backend
	toolchain string // Go toolchain version for builds, e.g. 1.25.9
	online    bool   // fetch mode: the module proxy may be used
}

func (r *repo) gitDir() string { return filepath.Join(r.dir, "repo.git") }

func (r *repo) git(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"--git-dir", r.gitDir()}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	var out, errb strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s: %v: %s", args[0], err, strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}

// present reports whether the clone exists.
func (r *repo) present() bool {
	_, err := os.Stat(filepath.Join(r.gitDir(), "HEAD"))
	return err == nil
}

// clone makes or updates the bare clone from url (network).
func (r *repo) clone(ctx context.Context, url string) error {
	if r.present() {
		_, err := r.git(ctx, "fetch", "--quiet", url, "+refs/heads/*:refs/heads/*")
		return err
	}
	if err := os.MkdirAll(r.dir, 0o755); err != nil {
		return err
	}
	tmp := r.gitDir() + ".part"
	os.RemoveAll(tmp)
	cmd := exec.CommandContext(ctx, "git", "clone", "--bare", "--quiet", url, tmp)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		os.RemoveAll(tmp)
		return fmt.Errorf("git clone %s: %v: %s", url, err, strings.TrimSpace(string(out)))
	}
	return os.Rename(tmp, r.gitDir())
}

var hexRe = regexp.MustCompile(`^[0-9a-f]{4,40}$`)

// resolve returns the full commit for a commit name (full or abbreviated).
func (r *repo) resolve(ctx context.Context, name string) (string, error) {
	if !hexRe.MatchString(name) {
		return "", fmt.Errorf("%q is not a commit (wallet-backend has no tags; give a commit)", name)
	}
	out, err := r.git(ctx, "rev-parse", "--verify", "--quiet", name+"^{commit}")
	if err != nil {
		return "", fmt.Errorf("commit %s is not in the clone at %s (run the adapter's fetch first): %v", name, r.gitDir(), err)
	}
	return strings.TrimSpace(out), nil
}

// firstParents lists the first-parent history of a commit, newest first.
func (r *repo) firstParents(ctx context.Context, commit string) ([]string, error) {
	out, err := r.git(ctx, "rev-list", "--first-parent", commit)
	if err != nil {
		return nil, err
	}
	return strings.Fields(out), nil
}

// contains evaluates a commit range of a known divergence for version v (a full commit): `A..B` holds every
// commit from A to B inclusive on B's first-parent history, `..B` everything up to and including B.
func (r *repo) contains(ctx context.Context, rng, v string) (bool, error) {
	a, b, ok := strings.Cut(rng, "..")
	if !ok || b == "" {
		return false, fmt.Errorf("range %q is not A..B or ..B", rng)
	}
	bFull, err := r.resolve(ctx, b)
	if err != nil {
		return false, err
	}
	aFull := ""
	if a != "" {
		if aFull, err = r.resolve(ctx, a); err != nil {
			return false, err
		}
	}
	hist, err := r.firstParents(ctx, bFull)
	if err != nil {
		return false, err
	}
	return inFirstParentRange(hist, aFull, v), nil
}

// inFirstParentRange decides containment on a first-parent history listed newest first.
func inFirstParentRange(hist []string, a, v string) bool {
	iv, ia := -1, -1
	for i, c := range hist {
		if c == v {
			iv = i
		}
		if a != "" && c == a {
			ia = i
		}
	}
	if iv < 0 {
		return false
	}
	if a == "" {
		return true
	}
	return ia >= iv // A is V itself or older than V
}

// isAncestor reports whether a is an ancestor of (or equal to) b.
func (r *repo) isAncestor(ctx context.Context, a, b string) (bool, error) {
	cmd := exec.CommandContext(ctx, "git", "--git-dir", r.gitDir(), "merge-base", "--is-ancestor", a, b)
	err := cmd.Run()
	if err == nil {
		return true, nil
	}
	var xe *exec.ExitError
	if errors.As(err, &xe) && xe.ExitCode() == 1 {
		return false, nil
	}
	return false, err
}

// file returns a file's content at a commit.
func (r *repo) file(ctx context.Context, commit, path string) (string, error) {
	return r.git(ctx, "show", commit+":"+path)
}

var sdkRe = regexp.MustCompile(`(?m)^\s*(?:require\s+)?(github\.com/stellar/go-stellar-sdk|github\.com/stellar/go)\s+(v\S+)`)

// sdkVersion reads the go-stellar-sdk (or, at old commits, github.com/stellar/go) requirement from go.mod.
func sdkVersion(gomod string) (module, version string) {
	for _, m := range sdkRe.FindAllStringSubmatch(gomod, -1) {
		if m[1] == "github.com/stellar/go-stellar-sdk" {
			return m[1], m[2]
		}
		module, version = m[1], m[2]
	}
	return module, version
}

// semverAtLeast compares the release part of a module version (pseudo-versions count as their base).
func semverAtLeast(v string, major, minor, patch int) bool {
	v = strings.TrimPrefix(v, "v")
	core, _, _ := strings.Cut(v, "-")
	p := strings.Split(core, ".")
	if len(p) != 3 {
		return false
	}
	n := [3]int{}
	for i := range p {
		x, err := strconv.Atoi(p[i])
		if err != nil {
			return false
		}
		n[i] = x
	}
	want := [3]int{major, minor, patch}
	for i := range n {
		if n[i] != want[i] {
			return n[i] > want[i]
		}
	}
	return true
}

// binPath is the cached binary of a commit.
func (r *repo) binPath(commit string) string {
	return filepath.Join(r.dir, "bin", "wallet-backend-"+commit)
}

// buildResult describes a build.
type buildResult struct {
	Path   string
	SHA256 string
	Cached bool
	Wall   time.Duration
	Flags  map[string]bool // flags of `ingest --help`
}

// build returns the binary for a commit, building it when it is not cached.
func (r *repo) build(ctx context.Context, commit string, log io.Writer) (*buildResult, error) {
	start := time.Now()
	bin := r.binPath(commit)
	res := &buildResult{Path: bin, Cached: true}
	if _, err := os.Stat(bin); err != nil {
		res.Cached = false
		if err := r.compile(ctx, commit, bin, log); err != nil {
			return nil, err
		}
	}
	sum, err := fileSHA256(bin)
	if err != nil {
		return nil, err
	}
	res.SHA256 = sum
	flags, err := r.flags(ctx, bin)
	if err != nil {
		return nil, err
	}
	res.Flags = flags
	res.Wall = time.Since(start)
	return res, nil
}

func (r *repo) goEnv() []string {
	env := []string{
		"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"),
		"GOTOOLCHAIN=go" + r.toolchain,
		"GOMODCACHE=" + filepath.Join(r.dir, "go", "mod"),
		"GOCACHE=" + filepath.Join(r.dir, "go", "build"),
		"GOPATH=" + filepath.Join(r.dir, "go", "path"),
		"CGO_ENABLED=0", "GOFLAGS=-mod=readonly", "GOWORK=off",
	}
	if tmp := os.Getenv("TMPDIR"); tmp != "" {
		env = append(env, "TMPDIR="+tmp)
	}
	if r.online {
		if p := os.Getenv("GOPROXY"); p != "" {
			env = append(env, "GOPROXY="+p)
		}
	} else {
		env = append(env, "GOPROXY=off", "GOSUMDB=off")
	}
	return env
}

// compile exports the commit's tree and builds it.
func (r *repo) compile(ctx context.Context, commit, bin string, log io.Writer) error {
	work := filepath.Join(r.dir, "work")
	if err := os.MkdirAll(work, 0o755); err != nil {
		return err
	}
	src, err := os.MkdirTemp(work, "src-"+commit[:12]+"-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(src)
	if err := r.export(ctx, commit, src); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
		return err
	}
	part := bin + ".part"
	cmd := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", part, ".")
	cmd.Dir, cmd.Env = src, r.goEnv()
	out, err := cmd.CombinedOutput()
	if log != nil && len(out) > 0 {
		log.Write(out)
	}
	if err != nil {
		os.Remove(part)
		return fmt.Errorf("go build at %s (toolchain go%s): %v: %s", commit, r.toolchain, err, lastLines(string(out), 15))
	}
	return os.Rename(part, bin)
}

// export writes a commit's tree into dir with `git archive`, read through archive/tar.
func (r *repo) export(ctx context.Context, commit, dir string) error {
	cmd := exec.CommandContext(ctx, "git", "--git-dir", r.gitDir(), "archive", "--format=tar", commit)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	var errb strings.Builder
	cmd.Stderr = &errb
	if err := cmd.Start(); err != nil {
		return err
	}
	terr := untar(bufio.NewReader(stdout), dir)
	io.Copy(io.Discard, stdout)
	werr := cmd.Wait()
	if terr != nil {
		return terr
	}
	if werr != nil {
		return fmt.Errorf("git archive %s: %v: %s", commit, werr, errb.String())
	}
	return nil
}

func untar(r io.Reader, dir string) error {
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		name := filepath.Clean(h.Name)
		if name == "." || strings.HasPrefix(name, "..") || filepath.IsAbs(name) {
			continue
		}
		p := filepath.Join(dir, name)
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(p, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				return err
			}
			f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(h.Mode)&0o777|0o600)
			if err != nil {
				return err
			}
			_, err = io.Copy(f, tr)
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return err
			}
		case tar.TypeSymlink:
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				return err
			}
			os.Symlink(h.Linkname, p)
		}
	}
}

var flagRe = regexp.MustCompile(`(?m)^\s*(?:-\w, )?--([a-z0-9-]+)`)

// flags reads the flag table of `ingest --help`, cached beside the binary.
func (r *repo) flags(ctx context.Context, bin string) (map[string]bool, error) {
	cache := bin + ".ingest-help"
	text, err := os.ReadFile(cache)
	if err != nil {
		cmd := exec.CommandContext(ctx, bin, "ingest", "--help")
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
		out, err := cmd.CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("%s ingest --help: %v: %s", bin, err, lastLines(string(out), 5))
		}
		text = out
		os.WriteFile(cache, out, 0o644)
	}
	return parseFlags(string(text)), nil
}

func parseFlags(help string) map[string]bool {
	m := map[string]bool{}
	for _, x := range flagRe.FindAllStringSubmatch(help, -1) {
		m[x[1]] = true
	}
	return m
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

package stellaretl

import (
	"bufio"
	"bytes"
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
	"slices"
	"strings"
	"time"
)

// UpstreamRepo is where the adapter clones stellar-etl from when its cache holds no clone yet.
const UpstreamRepo = "https://github.com/stellar/stellar-etl"

// cache is the adapter's directory under the harness's cachedir:
//
//	repo.git/           a bare, blob-less clone of stellar-etl (tags included)
//	src/<commit>/       a checkout of one commit, made with `git worktree add`
//	bin/stellar-etl-<commit>
//	tmp/                the Go toolchain's temporary files (never /tmp)
type cache struct {
	dir     string
	repo    string // the clone; may be an existing clone given with --repo
	binary  string // --etl-binary: a prebuilt binary used for every target (tests, CI)
	offline bool   // --offline: never clone or fetch
}

func (c *cache) git(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"--git-dir", c.repo}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return strings.TrimSpace(out.String()), nil
}

// haveRepo reports whether the clone exists.
func (c *cache) haveRepo() bool {
	_, err := os.Stat(filepath.Join(c.repo, "HEAD"))
	return err == nil
}

// ensureRepo clones stellar-etl into the cache when there is no clone yet.
func (c *cache) ensureRepo(ctx context.Context) error {
	if c.haveRepo() {
		return nil
	}
	if c.offline {
		return fmt.Errorf("no stellar-etl clone at %s and --offline is set", c.repo)
	}
	if err := os.MkdirAll(filepath.Dir(c.repo), 0o755); err != nil {
		return err
	}
	// Clone beside the final path and rename, so adapter processes preparing at once never see half a clone.
	tmp := fmt.Sprintf("%s.part-%d", c.repo, os.Getpid())
	os.RemoveAll(tmp)
	cmd := exec.CommandContext(ctx, "git", "clone", "--bare", "--filter=blob:none", UpstreamRepo, tmp)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		os.RemoveAll(tmp)
		return fmt.Errorf("clone %s: %v: %s", UpstreamRepo, err, strings.TrimSpace(string(out)))
	}
	if err := os.Rename(tmp, c.repo); err != nil {
		os.RemoveAll(tmp)
		if !c.haveRepo() {
			return err
		}
	}
	return nil
}

var fullCommit = regexp.MustCompile(`^[0-9a-f]{40}$`)

// resolve turns a tag, branch or commit into a full commit of the clone, fetching once when it is unknown.
func (c *cache) resolve(ctx context.Context, version string) (string, error) {
	if version == "" {
		return "", errors.New("empty version")
	}
	commit, err := c.git(ctx, "rev-parse", "--verify", "--quiet", version+"^{commit}")
	if err == nil && fullCommit.MatchString(commit) {
		return commit, nil
	}
	if c.offline {
		return "", fmt.Errorf("version %s is not in the clone and --offline is set", version)
	}
	if _, ferr := c.git(ctx, "fetch", "--quiet", "--tags", "origin", "+refs/heads/*:refs/heads/*"); ferr != nil {
		return "", ferr
	}
	commit, err = c.git(ctx, "rev-parse", "--verify", "--quiet", version+"^{commit}")
	if err != nil || !fullCommit.MatchString(commit) {
		return "", fmt.Errorf("version %s is not a stellar-etl tag or commit", version)
	}
	return commit, nil
}

// defaultBranch is the clone's HEAD branch (master for stellar-etl).
func (c *cache) defaultBranch(ctx context.Context) string {
	if b, err := c.git(ctx, "symbolic-ref", "--short", "HEAD"); err == nil && b != "" {
		return b
	}
	return "master"
}

// inRange evaluates a commit range of a known divergence: `A..B` is every commit from A to B inclusive on B's
// first-parent history, `..B` everything up to and including B (docs/manifest.md §7). The target is in the
// range when it is on B's first-parent history at or after A.
func (c *cache) inRange(ctx context.Context, rng, target string) (bool, error) {
	from, to, ok := strings.Cut(rng, "..")
	if !ok || to == "" {
		return false, fmt.Errorf("range %q is not A..B or ..B", rng)
	}
	toC, err := c.resolve(ctx, to)
	if err != nil {
		return false, err
	}
	list, err := c.git(ctx, "rev-list", "--first-parent", toC)
	if err != nil {
		return false, err
	}
	commits := strings.Fields(list)
	ti := slices.Index(commits, target)
	if ti < 0 {
		return false, nil
	}
	if from == "" {
		return true, nil
	}
	fromC, err := c.resolve(ctx, from)
	if err != nil {
		return false, err
	}
	fi := slices.Index(commits, fromC)
	if fi < 0 {
		return false, fmt.Errorf("range %q: %s is not on the first-parent history of %s", rng, from, to)
	}
	return ti <= fi, nil // rev-list lists the newest first
}

// goMod reads the target commit's go.mod from the clone.
func (c *cache) goMod(ctx context.Context, commit string) (string, error) {
	return c.git(ctx, "show", commit+":go.mod")
}

var (
	goDirective   = regexp.MustCompile(`(?m)^go\s+(\S+)`)
	toolchainLine = regexp.MustCompile(`(?m)^toolchain\s+(go\S+)`)
	sdkRequire    = regexp.MustCompile(`(?m)^\s*(?:require\s+)?github\.com/stellar/go-stellar-sdk\s+(v\S+)`)
)

// toolchainOf is the Go toolchain a go.mod asks for: its toolchain line, else go<go directive>.
func toolchainOf(gomod string) string {
	if m := toolchainLine.FindStringSubmatch(gomod); m != nil {
		return m[1]
	}
	if m := goDirective.FindStringSubmatch(gomod); m != nil {
		return "go" + m[1]
	}
	return ""
}

// sdkVersionOf is the go-stellar-sdk version a go.mod pins ("" when it pins the older stellar/go monorepo).
func sdkVersionOf(gomod string) string {
	if m := sdkRequire.FindStringSubmatch(gomod); m != nil {
		return m[1]
	}
	return ""
}

// sdkMaxProtocol is the highest protocol whose ledgers a go-stellar-sdk version can decode: v0.8.x (and the
// v0.8.1 pseudo-versions stellar-etl v2.8.33+ pins) carry the Protocol 30 XDR; v0.7.x was generated from
// Protocol 28 XDR, and Protocol 29 changed no XDR. Older versions are not classified (0).
func sdkMaxProtocol(v string) int {
	switch {
	case strings.HasPrefix(v, "v0.8."):
		return 30
	case strings.HasPrefix(v, "v0.7."):
		return 29
	}
	return 0
}

// checkout makes src/<commit> with the commit's files.
func (c *cache) checkout(ctx context.Context, commit string) (string, error) {
	src := filepath.Join(c.dir, "src", commit)
	if _, err := os.Stat(filepath.Join(src, "go.mod")); err == nil {
		return src, nil
	}
	os.RemoveAll(src)
	c.git(ctx, "worktree", "prune")
	if err := os.MkdirAll(filepath.Dir(src), 0o755); err != nil {
		return "", err
	}
	if _, err := c.git(ctx, "worktree", "add", "--detach", src, commit); err != nil {
		return "", err
	}
	return src, nil
}

// buildResult says where the binary is and how it was obtained.
type buildResult struct {
	binary string
	sha256 string
	cached bool
	wall   time.Duration
	notes  []string
}

// build returns the binary for a commit, building it with the toolchain the commit's go.mod names. stellar-etl
// links go-stellar-xdr-json, a cgo wrapper around a Rust library, so cgo is on.
func (c *cache) build(ctx context.Context, commit string, log io.Writer) (*buildResult, error) {
	start := time.Now()
	if c.binary != "" {
		sum, err := fileSHA256(c.binary)
		if err != nil {
			return nil, err
		}
		return &buildResult{binary: c.binary, sha256: sum, cached: true, notes: []string{"prebuilt binary given with --etl-binary; not built from the target"}}, nil
	}
	bin := filepath.Join(c.dir, "bin", "stellar-etl-"+commit)
	if _, err := os.Stat(bin); err == nil {
		sum, err := fileSHA256(bin)
		if err != nil {
			return nil, err
		}
		return &buildResult{binary: bin, sha256: sum, cached: true, wall: time.Since(start)}, nil
	}
	if c.offline {
		return nil, fmt.Errorf("no cached binary for %s and --offline is set", commit)
	}
	src, err := c.checkout(ctx, commit)
	if err != nil {
		return nil, err
	}
	gomod, err := os.ReadFile(filepath.Join(src, "go.mod"))
	if err != nil {
		return nil, err
	}
	tc := toolchainOf(string(gomod))
	if tc == "" {
		return nil, fmt.Errorf("%s: go.mod names no Go version", commit)
	}
	tmp := filepath.Join(c.dir, "tmp")
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
		return nil, err
	}
	part := fmt.Sprintf("%s.part-%d", bin, os.Getpid())
	cmd := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", part, ".")
	cmd.Dir = src
	cmd.Env = append(scrub(os.Environ(), "GOTOOLCHAIN", "CGO_ENABLED", "TMPDIR", "GOTMPDIR", "GOFLAGS"),
		"GOTOOLCHAIN="+tc, "CGO_ENABLED=1", "TMPDIR="+tmp, "GOTMPDIR="+tmp)
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Run(); err != nil {
		os.Remove(part)
		return nil, fmt.Errorf("go build at %s with %s: %v", commit, tc, err)
	}
	if err := os.Rename(part, bin); err != nil {
		return nil, err
	}
	sum, err := fileSHA256(bin)
	if err != nil {
		return nil, err
	}
	return &buildResult{binary: bin, sha256: sum, wall: time.Since(start), notes: []string{"built with " + tc}}, nil
}

// scrub drops the named variables from an environment.
func scrub(env []string, names ...string) []string {
	var out []string
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		if !slices.Contains(names, k) {
			out = append(out, kv)
		}
	}
	return out
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, bufio.NewReader(f)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

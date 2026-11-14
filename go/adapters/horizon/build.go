package horizon

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Build resolves version (tag, branch or commit) in a stellar-horizon clone and builds a static binary
// `<binDir>/stellar-horizon-<commit>` once, with the version string the release builds set. It returns the
// binary path and the full commit. The clone must already hold the version (fetching is the caller's step).
func Build(ctx context.Context, src, version, binDir string) (string, string, error) {
	out, err := exec.CommandContext(ctx, "git", "-C", src, "rev-parse", "--verify", version+"^{commit}").Output()
	if err != nil {
		return "", "", fmt.Errorf("resolve %s in %s: %v", version, src, err)
	}
	commit := strings.TrimSpace(string(out))
	bin := filepath.Join(binDir, "stellar-horizon-"+commit)
	if _, err := os.Stat(bin); err == nil {
		return bin, commit, nil
	}
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return "", "", err
	}
	wt, err := os.MkdirTemp(binDir, ".wt-")
	if err != nil {
		return "", "", err
	}
	defer func() {
		exec.Command("git", "-C", src, "worktree", "remove", "--force", wt).Run()
		os.RemoveAll(wt)
	}()
	if b, err := exec.CommandContext(ctx, "git", "-C", src, "worktree", "add", "--force", "--detach", wt, commit).CombinedOutput(); err != nil {
		return "", "", fmt.Errorf("worktree: %v: %s", err, b)
	}
	cmd := exec.CommandContext(ctx, "go", "build", "-trimpath",
		"-ldflags", "-X=github.com/stellar/go-stellar-sdk/support/app.version=horizon-"+version+"-"+commit,
		"-o", bin+".tmp", ".")
	cmd.Dir = wt
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		return "", "", fmt.Errorf("go build %s: %v: %s", commit, err, tail(string(b), 10))
	}
	return bin, commit, os.Rename(bin+".tmp", bin)
}

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/tolgayayci/xdrcheck/go/adapters/horizon"
	"github.com/tolgayayci/xdrcheck/go/internal/rig"
)

const horizonRepo = "https://github.com/stellar/stellar-horizon.git"

type horizonRigArgs struct {
	ledgers                                         []uint32
	commit, out, lake, passphrase, cachedir, prefix string
	shards                                          int
}

// replayRigHorizon runs `--rig horizon`: stellar-horizon built from source at --commit (a blob-less clone under
// <cachedir>/stellar-horizon, binaries cached per commit), fed by `db reingest range` from a Filesystem datastore
// over --lake. The run lands in <out>/shard-0 (the rig shards internally, one database per shard); status and
// rows are merged into <out> like the other rigs.
func replayRigHorizon(ctx context.Context, a horizonRigArgs, stdout, stderr io.Writer) int {
	base := filepath.Join(a.cachedir, "stellar-horizon")
	repo := filepath.Join(base, "repo.git")
	if _, err := os.Stat(repo); err != nil {
		if b, err := exec.CommandContext(ctx, "git", "clone", "--quiet", "--bare", "--filter=blob:none", horizonRepo, repo).CombinedOutput(); err != nil {
			fmt.Fprintf(stderr, "xdrcheck replay: clone stellar-horizon: %v: %s\n", err, b)
			return 2
		}
	}
	if exec.CommandContext(ctx, "git", "-C", repo, "rev-parse", "--verify", "--quiet", a.commit+"^{commit}").Run() != nil {
		if b, err := exec.CommandContext(ctx, "git", "-C", repo, "fetch", "--quiet", "--tags", "origin",
			"+refs/heads/*:refs/heads/*").CombinedOutput(); err != nil {
			fmt.Fprintf(stderr, "xdrcheck replay: fetch stellar-horizon: %v: %s\n", err, b)
			return 2
		}
	}
	bin, commit, err := horizon.Build(ctx, repo, a.commit, filepath.Join(base, "bin"))
	if err != nil {
		fmt.Fprintln(stderr, "xdrcheck replay:", err)
		return 2
	}
	// Horizon reads the lake inside a container, which cannot follow a symbolic link to a path outside it.
	lakeDir, links, err := containerLake(a.lake, filepath.Join(a.out, "lake"))
	if err != nil {
		fmt.Fprintln(stderr, "xdrcheck replay: --lake:", err)
		return 2
	}
	if links > 0 {
		fmt.Fprintf(stderr, "xdrcheck replay: --lake holds %d symbolic links, which a container cannot follow; Horizon reads a resolved copy in %s\n", links, lakeDir)
	}
	start := time.Now()
	sum, err := horizon.Run(ctx, horizon.Config{Lake: lakeDir, Ledgers: a.ledgers, Binary: bin, Version: a.commit,
		Commit: commit, Out: filepath.Join(a.out, "shard-0"), Shards: a.shards, GroupMode: "contiguous", MaxGroup: 64,
		Passphrase: a.passphrase, Timeout: 5 * time.Minute,
		PGImage:  "timescale/timescaledb:2.28.2-pg17@sha256:909e2c7577c074517c8936b6d8799294b33f25fb5bad978a2199250665f1ce1a",
		HZImage:  "ubuntu:noble@sha256:2198e4c65076e9cb0b3d695219df667c0e3b0072da64ca3c2648aca17dcecaf5",
		PGMemory: "32g", HZMemory: "32g", Name: a.prefix}, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "xdrcheck replay:", err)
		return 2
	}
	counts := map[string]int{}
	if err := mergeRows(a.out, 1, counts); err != nil {
		fmt.Fprintln(stderr, "xdrcheck replay:", err)
		return 2
	}
	n, err := mergeShards(a.out, 1, "status.jsonl", counts, true)
	if err != nil {
		fmt.Fprintln(stderr, "xdrcheck replay:", err)
		return 2
	}
	counts["lines:status.jsonl"] = n
	wall := time.Since(start).Milliseconds()
	man := rigManifest{Schema: "xcc.rig/v1", Rig: "horizon", Commit: commit, Requested: a.commit, Network: a.passphrase,
		Lake: a.lake, Ledgers: len(a.ledgers), Segments: sum.Segments, Shards: a.shards,
		Started: start.UTC().Format(time.RFC3339), WallMS: wall, Host: map[string]any{}, ShardsInfo: []any{sum}}
	rig.WriteJSON(filepath.Join(a.out, "manifest.json"), man)
	rig.WriteJSON(filepath.Join(a.out, "summary.json"), map[string]any{"ledgers": len(a.ledgers), "wall_ms": wall,
		"counts": counts, "ms_per_ledger": float64(wall) / float64(max(1, len(a.ledgers))), "horizon": sum})
	fmt.Fprintf(stdout, "horizon %s: %d ledgers in %d segments, %d shards, %.0f ms/ledger; %s\n", shortCommit(commit),
		len(a.ledgers), sum.Segments, a.shards, float64(wall)/float64(max(1, len(a.ledgers))), statusCounts(counts))
	switch {
	case len(sum.HarnessFaults) > 0 || counts["status:"+rig.StatusHarnessFault] > 0:
		return 2
	case counts["status:"+rig.StatusHalted]+counts["status:"+rig.StatusSkipped] > 0:
		return 1
	}
	return 0
}

// containerLake returns a lake directory that a container can read whole, and how many symbolic links the
// given one holds. With none, it is the lake itself. Otherwise dst (which must not exist) receives the same tree
// with every link resolved: each file a hard link to the link's target, or a copy across filesystems. A link
// that does not resolve, or that points at a directory, is an error naming it; nothing is passed on unresolved.
func containerLake(lake, dst string) (string, int, error) {
	root, err := filepath.EvalSymlinks(lake)
	if err != nil {
		return "", 0, err
	}
	links := 0
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.Type()&fs.ModeSymlink != 0 {
			links++
		}
		return err
	})
	if err != nil || links == 0 {
		return root, 0, err
	}
	if _, err := os.Lstat(dst); err == nil {
		return "", links, fmt.Errorf("%s already exists; remove it or use another --out", dst)
	}
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		to := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(to, 0o755)
		}
		from := p
		if d.Type()&fs.ModeSymlink != 0 {
			if from, err = filepath.EvalSymlinks(p); err != nil {
				return fmt.Errorf("%s is a symbolic link that does not resolve: %v", p, err)
			}
		}
		st, err := os.Stat(from)
		if err != nil {
			return err
		}
		if !st.Mode().IsRegular() {
			return fmt.Errorf("%s resolves to %s, which is not a regular file", p, from)
		}
		if err := os.Link(from, to); err == nil {
			return nil
		} else if !errors.Is(err, fs.ErrExist) {
			return copyLakeFile(from, to)
		}
		return fmt.Errorf("%s exists twice in the resolved lake", to)
	})
	if err != nil {
		return "", links, err
	}
	return dst, links, nil
}

func copyLakeFile(from, to string) error {
	in, err := os.Open(from)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(to)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

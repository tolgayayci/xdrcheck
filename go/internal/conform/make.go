package conform

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// MakeOptions configure Fetch and Build.
type MakeOptions struct {
	Sets     *Sets
	Columns  []*Column
	PinsPath string
	Stdout   io.Writer
	Stderr   io.Writer
	// Prefix is put in front of every make command, for example a wrapper that removes the network.
	Prefix []string
}

// DirJob is one driver directory and the columns it serves.
type DirJob struct {
	Dir     string // relative to the repository root
	Columns []*Column
}

// DirJobs groups columns by driver directory, sorted by directory. Columns that share a directory (Rust's two
// profiles) are fetched and built once.
func DirJobs(cols []*Column) []DirJob {
	byDir := map[string][]*Column{}
	for _, c := range cols {
		byDir[c.Dir] = append(byDir[c.Dir], c)
	}
	var out []DirJob
	for d, cs := range byDir {
		out = append(out, DirJob{Dir: d, Columns: cs})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Dir < out[j].Dir })
	return out
}

// Fetch runs `make fetch` in every selected driver directory: the only networked conformance step.
func Fetch(ctx context.Context, o MakeOptions) error { return runMake(ctx, o, "fetch", nil) }

// Build runs `make build` in every selected driver directory, with the package managers told to stay offline.
func Build(ctx context.Context, o MakeOptions) error {
	return runMake(ctx, o, "build", []string{
		"XDRCHECK_OFFLINE=1",
		"GOPROXY=off", "GOFLAGS=-mod=readonly", "GOTOOLCHAIN=local",
		"CARGO_NET_OFFLINE=true",
		"npm_config_offline=true",
		"PIP_NO_INDEX=1",
	})
}

func runMake(ctx context.Context, o MakeOptions, target string, extra []string) error {
	pinsAbs, err := filepath.Abs(o.PinsPath)
	if err != nil {
		return err
	}
	root, err := filepath.Abs(o.Sets.Root)
	if err != nil {
		return err
	}
	var failed []string
	for _, j := range DirJobs(o.Columns) {
		ids := make([]string, len(j.Columns))
		for i, c := range j.Columns {
			ids[i] = c.ID
		}
		col := j.Columns[0]
		dir := o.Sets.AbsDir(col)
		source := []string{SourceVariable + "="} // never inherited from the caller's environment
		if col.Source != "" {
			// Built from an SDK checkout: fetch makes the private copy of the driver directory afresh, build uses it.
			if target == "fetch" {
				if err := o.Sets.PrepareSource(col); err != nil {
					return err
				}
			} else if _, err := os.Stat(dir); err != nil {
				msg := fmt.Sprintf("%s: no copy for %s yet; run xdrcheck conform fetch --sdk %s first", j.Dir, col.Source, col.Source)
				fmt.Fprintf(o.Stderr, "conform %s: %s\n", target, msg)
				failed = append(failed, msg)
				continue
			}
			source = []string{SourceVariable + "=" + col.Source}
			fmt.Fprintf(o.Stderr, "conform %s: %s from the checkout %s, in %s\n", target, j.Dir, col.Source, dir)
		}
		if _, err := os.Stat(filepath.Join(dir, "Makefile")); err != nil {
			msg := fmt.Sprintf("%s: no Makefile: the driver for %s is not written yet", j.Dir, strings.Join(ids, ", "))
			fmt.Fprintf(o.Stderr, "conform %s: %s\n", target, msg)
			failed = append(failed, msg)
			continue
		}
		cache := CacheDir(col)
		if err := os.MkdirAll(cache, 0o755); err != nil {
			return err
		}
		argv := append(append([]string{}, o.Prefix...), "make", "-C", dir, target)
		cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
		cmd.Env = append(os.Environ(),
			"XDRCHECK_COLUMNS="+strings.Join(ids, " "),
			"XDRCHECK_SDK_VERSION="+col.Version,
			"XDRCHECK_CACHE_DIR="+cache,
			"XDRCHECK_PINS="+pinsAbs,
			"XDRCHECK_ROOT="+root,
		)
		cmd.Env = append(cmd.Env, extra...)
		cmd.Env = append(cmd.Env, source...)
		cmd.Stdout, cmd.Stderr = o.Stdout, o.Stderr
		fmt.Fprintf(o.Stderr, "conform %s: %s (%s)\n", target, j.Dir, strings.Join(ids, ", "))
		if err := cmd.Run(); err != nil {
			msg := fmt.Sprintf("%s: make %s: %v", j.Dir, target, err)
			fmt.Fprintf(o.Stderr, "conform %s: %s\n", target, msg)
			failed = append(failed, msg)
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("%d of %d driver directories failed: %s", len(failed), len(DirJobs(o.Columns)), strings.Join(failed, "; "))
	}
	return nil
}

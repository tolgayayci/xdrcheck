// Command horizon-rig runs real ledgers through an unmodified stellar-horizon (`db reingest range` from a
// Filesystem datastore, no captive core, no network) and writes a run directory: manifest.json, status.jsonl
// (ingested / halted with Horizon's error / skipped), tables/<table>.jsonl.zst (every history table), rows.jsonl
// (common rows) and summary.json.
//
//	horizon-rig --lake DIR (--ledgers FILE | --range S-E) (--horizon-bin FILE | --version V --horizon-src CLONE)
//	            --out DIR [--shards N] [--group single|contiguous] [--max-group N] [--passphrase P]
//	horizon-rig rows --out rows.jsonl [--commit C] RUN/tables   # re-export common rows from the raw dumps
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/tolgayayci/xdrcheck/go/adapters/horizon"
)

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) > 0 && args[0] == "rows" {
		return rows(args[1:])
	}
	fs := flag.NewFlagSet("horizon-rig", flag.ContinueOnError)
	lake := fs.String("lake", "", "lake directory (SEP-54 layout, one ledger per file, 64000 files per partition)")
	list := fs.String("ledgers", "", "file of ledger sequences (first field per line; other lines ignored)")
	rng := fs.String("range", "", "inclusive range S-E")
	bin := fs.String("horizon-bin", "", "prebuilt static stellar-horizon binary")
	version := fs.String("version", "", "Horizon tag, branch or commit (built from --horizon-src unless --horizon-bin)")
	src := fs.String("horizon-src", "", "stellar-horizon clone to build --version from")
	binDir := fs.String("bin-dir", "", "where built binaries are cached (default <horizon-src>/../bin)")
	out := fs.String("out", "", "run directory (new)")
	shards := fs.Int("shards", 1, "parallel Horizon workers, one database each")
	group := fs.String("group", "single", "single: one reingest per ledger; contiguous: one per run of consecutive ledgers")
	maxGroup := fs.Int("max-group", 64, "max ledgers per contiguous group")
	pass := fs.String("passphrase", horizon.PubnetPassphrase, "network passphrase")
	timeout := fs.Duration("timeout", 5*time.Minute, "per reingest call")
	pgImage := fs.String("pg-image", "timescale/timescaledb:2.28.2-pg17@sha256:909e2c7577c074517c8936b6d8799294b33f25fb5bad978a2199250665f1ce1a", "Postgres image")
	hzImage := fs.String("hz-image", "ubuntu:noble@sha256:2198e4c65076e9cb0b3d695219df667c0e3b0072da64ca3c2648aca17dcecaf5", "image the static Horizon binary runs in")
	pgMem := fs.String("pg-memory", "32g", "Postgres container memory cap")
	hzMem := fs.String("hz-memory", "32g", "Horizon container memory cap")
	name := fs.String("name", "", "container name prefix (default xdrcheck-hz-<pid>)")
	keep := fs.Bool("keep", false, "keep containers")
	noRows := fs.Bool("no-rows", false, "skip the common-row export")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *lake == "" || *out == "" || (*list == "") == (*rng == "") || (*bin == "" && (*version == "" || *src == "")) {
		fmt.Fprintln(os.Stderr, "horizon-rig: need --lake, --out, one of --ledgers/--range, and --horizon-bin or --version with --horizon-src")
		return 2
	}
	var seqs []uint32
	var err error
	if *list != "" {
		seqs, err = horizon.ReadList(*list)
	} else {
		seqs, err = horizon.ParseRange(*rng)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "horizon-rig:", err)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	commit := ""
	if *bin == "" {
		d := *binDir
		if d == "" {
			d = filepath.Join(filepath.Dir(filepath.Clean(*src)), "bin")
		}
		fmt.Fprintf(os.Stderr, "horizon-rig: building %s\n", *version)
		if *bin, commit, err = horizon.Build(ctx, *src, *version, d); err != nil {
			fmt.Fprintln(os.Stderr, "horizon-rig:", err)
			return 1
		}
	} else if *version == "" {
		*version = filepath.Base(*bin)
	}
	if commit == "" {
		if i := strings.LastIndex(filepath.Base(*bin), "-"); i >= 0 && len(filepath.Base(*bin))-i-1 == 40 {
			commit = filepath.Base(*bin)[i+1:]
		}
	}
	if *name == "" {
		*name = fmt.Sprintf("xdrcheck-hz-%d", os.Getpid())
	}
	sum, err := horizon.Run(ctx, horizon.Config{Lake: *lake, Ledgers: seqs, Binary: *bin, Version: *version,
		Commit: commit, Out: *out, Shards: *shards, GroupMode: *group, MaxGroup: *maxGroup, Passphrase: *pass,
		Timeout: *timeout, PGImage: *pgImage, HZImage: *hzImage, PGMemory: *pgMem, HZMemory: *hzMem,
		Name: *name, Keep: *keep, NoRows: *noRows}, os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "horizon-rig:", err)
		return 1
	}
	b, _ := json.MarshalIndent(sum, "", "  ")
	fmt.Println(string(b))
	if len(sum.HarnessFaults) > 0 {
		return 3
	}
	return 0
}

func rows(args []string) int {
	fs := flag.NewFlagSet("horizon-rig rows", flag.ContinueOnError)
	pass := fs.String("passphrase", horizon.PubnetPassphrase, "network passphrase")
	out := fs.String("out", "", "rows.jsonl to write")
	commit := fs.String("commit", "", "Horizon commit to stamp on rows")
	if err := fs.Parse(args); err != nil || *out == "" || fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: horizon-rig rows --out rows.jsonl [--passphrase P] [--commit C] TABLES_DIR")
		return 2
	}
	counts := map[string]int{}
	if err := horizon.ExportRows(fs.Arg(0), *out, *pass, *commit, counts); err != nil {
		fmt.Fprintln(os.Stderr, "horizon-rig rows:", err)
		return 1
	}
	b, _ := json.Marshal(counts)
	fmt.Println(string(b))
	return 0
}

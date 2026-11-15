package main

// xdrcheck data (docs/data.md): the dataset (which version is present, its tables and named ledger sets), ledger
// downloads from the public lake into a local lake-layout cache, and the design of the append-only top-up.

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/tolgayayci/xdrcheck/go/internal/hunt"
	"github.com/tolgayayci/xdrcheck/go/internal/hunt/dataset"
	"github.com/tolgayayci/xdrcheck/go/internal/hunt/rundir"
)

func init() {
	register("data", "the dataset: status, named ledger sets, ledger fetch, manifest, top-up plan", func(args []string) int {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return dataMain(ctx, args, os.Stdout, os.Stderr)
	})
}

func dataUsage(w io.Writer) {
	fmt.Fprintf(w, `usage: %[1]s data <subcommand> [flags]

subcommands:
  status    the dataset present: version, tip ledger, tables and sets with their files (--verify: sha256)
  sets      the named ledger sets shipped with the dataset
  fetch     download ledgers from the public lake into the local ledger cache (size and MD5 checked)
  manifest  write a dataset manifest for derived data under named roots
  update    print the plan of an append-only top-up from the dataset's tip (does not scan)
  export    copy named sets (and small tables) with a manifest into a portable dataset directory, for CI
`, hunt.Tool)
}

func dataMain(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		dataUsage(stderr)
		return 2
	}
	switch args[0] {
	case "status":
		return dataStatus(args[1:], stdout, stderr)
	case "sets":
		return dataSets(args[1:], stdout, stderr)
	case "fetch":
		return dataFetch(ctx, args[1:], stdout, stderr)
	case "manifest":
		return dataManifest(args[1:], stdout, stderr)
	case "update":
		return dataUpdate(args[1:], stdout, stderr)
	case "export":
		return dataExport(args[1:], stdout, stderr)
	}
	fmt.Fprintf(stderr, "%s data: unknown subcommand %q\n", hunt.Tool, args[0])
	dataUsage(stderr)
	return 2
}

func human(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

func dataStatus(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(hunt.Tool+" data status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	ds := fs.String("dataset", "", "dataset directory (default $"+hunt.EnvName("DATASET")+", else the per-user data directory)")
	verify := fs.Bool("verify", false, "recompute every file's sha256 (slow on the large tables)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	m, err := dataset.Load(dataset.Dir(*ds))
	if err != nil {
		fmt.Fprintln(stdout, err)
		return 3
	}
	if err := rundir.ValidateFile(rundir.SchemaDataset, m.Path()); err != nil {
		fmt.Fprintf(stdout, "INVALID manifest: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "dataset   %s (%s)\nnetwork   %s\ntip       ledger %d\nmanifest  %s\n", m.Version, m.Created, m.Network, m.TipLedger, m.Path())
	for _, n := range sortedRoots(m.Roots) {
		fmt.Fprintf(stdout, "root      %-8s %s\n", n, m.Root(n))
	}
	for _, l := range m.Lakes {
		fmt.Fprintf(stdout, "lake      %s (read-only)\n", m.Resolve(l))
	}
	checks := m.Verify(*verify)
	state := map[string][]string{}
	for _, c := range checks {
		state[c.Table] = append(state[c.Table], c.State)
	}
	bad := 0
	fmt.Fprintln(stdout, "\ntables:")
	for _, n := range m.TableNames() {
		t := m.Tables[n]
		var size int64
		for _, f := range t.Files {
			size += f.Bytes
		}
		switch {
		case t.Missing != "":
			fmt.Fprintf(stdout, "  %-18s missing: %s\n", n, t.Missing)
		case t.Glob != "":
			fmt.Fprintf(stdout, "  %-18s %-7s %s  %s\n", n, t.Format, strings.Join(state[n], ","), m.Resolve(t.Glob))
		default:
			st := summarise(state[n])
			if st != "ok" && st != "size-ok" {
				bad++
			}
			fmt.Fprintf(stdout, "  %-18s %-7s %3d files %9s  %s\n", n, t.Format, len(t.Files), human(size), st)
		}
	}
	fmt.Fprintln(stdout, "\nsets:")
	for _, n := range m.SetNames() {
		s := m.Sets[n]
		if s.Missing != "" {
			fmt.Fprintf(stdout, "  %-22s missing: %s\n", n, s.Missing)
			continue
		}
		st := summarise(state["set:"+n])
		if st != "ok" && st != "size-ok" {
			bad++
		}
		fmt.Fprintf(stdout, "  %-22s %6d %-6s %s\n", n, s.Count, s.Unit, st)
	}
	if bad > 0 {
		fmt.Fprintf(stdout, "\n%d tables or sets do not match the manifest\n", bad)
		return 1
	}
	return 0
}

func summarise(states []string) string {
	if len(states) == 0 {
		return "-"
	}
	for _, s := range states {
		if s != states[0] {
			return strings.Join(states, ",")
		}
	}
	return states[0]
}

func sortedRoots(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func dataSets(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(hunt.Tool+" data sets", flag.ContinueOnError)
	fs.SetOutput(stderr)
	ds := fs.String("dataset", "", "dataset directory")
	show := fs.String("show", "", "print the ledgers (or ledger<TAB>tx) of one set")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	m, err := dataset.Load(dataset.Dir(*ds))
	if err != nil {
		fmt.Fprintln(stdout, err)
		return 3
	}
	if *show != "" {
		refs, err := m.SetRefs(*show)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		for _, r := range refs {
			if r.Tx >= 0 {
				fmt.Fprintf(stdout, "%d\t%d\n", r.Ledger, r.Tx)
			} else {
				fmt.Fprintf(stdout, "%d\n", r.Ledger)
			}
		}
		return 0
	}
	for _, n := range m.SetNames() {
		s := m.Sets[n]
		if s.Missing != "" {
			fmt.Fprintf(stdout, "%-22s %8s  not available: %s\n", n, "-", s.Missing)
			continue
		}
		fmt.Fprintf(stdout, "%-22s %8d %-6s  %s\n", n, s.Count, s.Unit, s.Description)
	}
	return 0
}

func dataFetch(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(hunt.Tool+" data fetch", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var src sourceFlags
	src.add(fs)
	ledgers := fs.String("ledgers", "", "ledgers: comma-separated sequences and ranges a-b, or @FILE (one per line, or ledger<TAB>tx)")
	set := fs.String("set", "", "a named set of the dataset")
	out := fs.String("out", "", "lake-layout directory to fill (default: the ledger cache, see --lake)")
	local := fs.Bool("from-local", true, "copy ledgers a read-only lake of the dataset already holds instead of downloading them")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if src.offline {
		fmt.Fprintln(stderr, hunt.Tool+" data fetch: --offline: nothing to do")
		return 2
	}
	if src.network == "" {
		src.network = "pubnet"
	}
	m, err := src.openDataset()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	var seqs []uint32
	if *ledgers != "" {
		seqs, err = dataset.ParseLedgers(*ledgers)
		if err != nil {
			fmt.Fprintf(stderr, "%s data fetch: %v\n", hunt.Tool, err)
			return 2
		}
	}
	if *set != "" {
		if m == nil {
			fmt.Fprintln(stderr, hunt.Missing("dataset manifest", "--set needs a dataset").Error())
			return 3
		}
		refs, err := m.SetRefs(*set)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		seqs = append(seqs, dataset.Ledgers(refs)...)
	}
	if len(seqs) == 0 {
		fmt.Fprintln(stderr, hunt.Tool+" data fetch: give --ledgers or --set")
		return 2
	}
	cache := *out
	if cache == "" {
		cache = dataset.LakeDir(src.lake, dataset.Dir(src.dataset))
	}
	lk := dataset.NewLake(m, cache, src.network)
	t := time.Now()
	res, err := lk.Fetch(ctx, seqs, dataset.FetchOptions{BaseURL: src.lakeURL, Parallel: src.parallel, Rate: src.rate, Local: *local,
		Progress: func(d, n int, c map[string]int) { fmt.Fprintf(stderr, "%d/%d %v\n", d, n, c) }})
	if err != nil {
		fmt.Fprintf(stderr, "%s data fetch: %v\n", hunt.Tool, err)
	}
	fmt.Fprintf(stdout, "%d ledgers into %s in %.1fs: %v, %s downloaded\n", len(seqs), cache, time.Since(t).Seconds(), res.Counts, human(res.Bytes))
	if len(res.Failed) > 0 {
		n := 0
		for s, why := range res.Failed {
			if n++; n > 10 {
				break
			}
			fmt.Fprintf(stdout, "  failed %d: %s\n", s, why)
		}
		return 1
	}
	if err != nil {
		return 1
	}
	return 0
}

type rootsFlag map[string]string

func (r rootsFlag) String() string { return fmt.Sprint(map[string]string(r)) }
func (r rootsFlag) Set(s string) error {
	k, v, ok := strings.Cut(s, "=")
	if !ok || k == "" || v == "" {
		return fmt.Errorf("want NAME=PATH")
	}
	r[k] = strings.TrimRight(v, "/")
	return nil
}

func dataManifest(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(hunt.Tool+" data manifest", flag.ContinueOnError)
	fs.SetOutput(stderr)
	roots := rootsFlag{}
	fs.Var(roots, "root", "a named root, NAME=PATH: derived (census, cover, tokens, leads, kept-ledger index), kept (lake of kept ledgers), scan (full-scan Parquet), hunt (locate index, tags, generated ledgers); repeatable")
	out := fs.String("out", "", "dataset directory to write manifest.json into (default: the dataset directory)")
	version := fs.String("version", time.Now().UTC().Format("2006-01-02")+".1", "dataset version")
	network := fs.String("network", "pubnet", "network of the data")
	corpus := fs.String("corpus", "corpus", "corpus root: per-CAP sets and the corpus_entries table (empty to skip)")
	findings := fs.String("findings", "findings", "public finding records: the findings table (empty to skip)")
	noHash := fs.Bool("no-hash", false, "record sizes only, no sha256")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if len(roots) == 0 {
		fmt.Fprintln(stderr, hunt.Tool+" data manifest: give at least one --root NAME=PATH")
		return 2
	}
	dir := dataset.Dir(*out)
	if _, err := os.Stat(*corpus); err != nil {
		*corpus = ""
	}
	if _, err := os.Stat(*findings); err != nil {
		*findings = ""
	}
	m, err := dataset.Build(dataset.BuildOptions{Version: *version, Network: *network, Roots: roots, Corpus: *corpus, Find: *findings, Out: dir, Hash: !*noHash,
		Log: func(s string) { fmt.Fprintln(stderr, s) }})
	if err != nil {
		fmt.Fprintf(stderr, "%s data manifest: %v\n", hunt.Tool, err)
		return 2
	}
	fmt.Fprintf(stdout, "dataset %s, tip %d: %d tables, %d sets -> %s\n", m.Version, m.TipLedger, len(m.Tables), len(m.Sets), m.Path())
	return 0
}

func dataUpdate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(hunt.Tool+" data update", flag.ContinueOnError)
	fs.SetOutput(stderr)
	ds := fs.String("dataset", "", "dataset directory")
	to := fs.Uint("to", 0, "last ledger of the top-up (default: the lake's newest, which this command does not look up)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	m, err := dataset.Load(dataset.Dir(*ds))
	if err != nil {
		fmt.Fprintln(stdout, err)
		return 3
	}
	from := m.TipLedger + 1
	end := "<lake tip>"
	if *to > 0 {
		end = fmt.Sprint(*to)
	}
	fmt.Fprintf(stdout, `Top-up plan for dataset %[1]s (tip %[2]d). Not run: this command only prints the plan.

The dataset is append-only. A top-up never rewrites a file; it adds one new block of every table for the
ledgers after the tip, then writes a new manifest version that lists the old files unchanged plus the new ones.

  1. range      ledgers %[3]d..%[4]s (the public lake lists its newest object; partitions are 64,000 ledgers)
  2. scan       %[5]s-corpus scan run over the range, written as new blocks next to the existing ones
                (one block per partition; a partly filled last partition is rescanned as a whole next time)
  3. census     %[5]s-corpus scan census-extract on the new blocks, then census-merge into new shapes-*.tsv.zst
                files whose name carries the range; first/last ledger and occurrences merge by id
  4. tokens     token-census on the new blocks; tokens.tsv.zst gains a sibling file for the range
  5. covers     covers are not incremental: a new token or shape adds its first ledger to cover-*-new.tsv.zst
  6. locate     scan locate on the new blocks (one more file under locate/)
  7. tags       the value tagger on the new ledgers (one more file under tags/)
  8. manifest   %[5]s data manifest --version <next> with the same roots: new files are hashed, old hashes kept

Each step is resumable per block. Old runs stay reproducible: a run directory names the dataset version and
manifest sha256 it was resolved through, and old versions' files are never changed.
`, m.Version, m.TipLedger, from, end, hunt.Tool)
	return 0
}

func dataExport(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(hunt.Tool+" data export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	ds := fs.String("dataset", "", "dataset directory to export from")
	out := fs.String("out", "", "portable dataset directory to write (required)")
	var sets, tables listFlag
	fs.Var(&sets, "set", "a set to copy; repeatable")
	fs.Var(&tables, "table", "a small table to copy (at most 64 MB); repeatable")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *out == "" || len(sets)+len(tables) == 0 {
		fmt.Fprintln(stderr, hunt.Tool+" data export: give --out and at least one --set or --table")
		return 2
	}
	m, err := dataset.Load(dataset.Dir(*ds))
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 3
	}
	em := &dataset.Manifest{Version: m.Version, Network: m.Network, TipLedger: m.TipLedger, Created: m.Created,
		Roots: map[string]string{}, Tables: map[string]*dataset.Table{}, Sets: map[string]*dataset.Set{}}
	copyIn := func(src, rel string) (dataset.File, error) {
		b, err := os.ReadFile(src)
		if err != nil {
			return dataset.File{}, err
		}
		dst := filepath.Join(*out, rel)
		os.MkdirAll(filepath.Dir(dst), 0o755)
		if err := os.WriteFile(dst, b, 0o644); err != nil {
			return dataset.File{}, err
		}
		f, err := dataset.FileOf(dst)
		f.Path = rel
		return f, err
	}
	for _, n := range sets {
		s := m.Sets[n]
		if s == nil || s.File == nil {
			fmt.Fprintf(stderr, "%s data export: no set %q with a file\n", hunt.Tool, n)
			return 2
		}
		f, err := copyIn(m.Resolve(s.File.Path), "sets/"+n+filepath.Ext(s.File.Path))
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		em.Sets[n] = &dataset.Set{Description: s.Description, Unit: s.Unit, Count: s.Count, File: &f}
	}
	for _, n := range tables {
		t := m.Tables[n]
		if t == nil || t.Missing != "" || t.Glob != "" {
			fmt.Fprintf(stderr, "%s data export: table %q has no files to copy\n", hunt.Tool, n)
			return 2
		}
		nt := &dataset.Table{Description: t.Description, Format: t.Format, FilenameColumns: t.FilenameColumns}
		for _, f := range t.Files {
			if f.Bytes > 64<<20 {
				fmt.Fprintf(stderr, "%s data export: table %s is too large to export (%s)\n", hunt.Tool, n, human(f.Bytes))
				return 2
			}
			g, err := copyIn(m.Resolve(f.Path), "tables/"+n+"/"+filepath.Base(f.Path))
			if err != nil {
				fmt.Fprintln(stderr, err)
				return 2
			}
			nt.Files = append(nt.Files, g)
		}
		em.Tables[n] = nt
	}
	if err := em.Save(*out); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	fmt.Fprintf(stdout, "dataset %s: %d sets, %d tables -> %s\n", em.Version, len(em.Sets), len(em.Tables), em.Path())
	return 0
}

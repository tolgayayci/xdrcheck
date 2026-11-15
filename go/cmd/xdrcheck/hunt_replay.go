package main

// xdrcheck replay --target (docs/replay.md): any target at any version against ledgers, transactions, a named set,
// a CAP's corpus examples or a known issue; writes a run directory (docs/run-directory.md).
//
// The corpus form of xdrcheck replay (--adapter, replay.go) is unchanged; --target selects this form.

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/tolgayayci/xdrcheck/go/internal/hunt"
	"github.com/tolgayayci/xdrcheck/go/internal/hunt/dataset"
	"github.com/tolgayayci/xdrcheck/go/internal/hunt/issues"
	"github.com/tolgayayci/xdrcheck/go/internal/hunt/ledger"
	"github.com/tolgayayci/xdrcheck/go/internal/hunt/rundir"
	"github.com/tolgayayci/xdrcheck/go/internal/hunt/targets"
)

// isTargetReplay reports whether a replay command line is the target form: it names a target, or selects
// ledgers in a way only the target form can (the corpus form selects entries with --entries and --caps).
func isTargetReplay(args []string) bool {
	for _, a := range args {
		if a == "--" {
			break
		}
		name := strings.TrimLeft(a, "-")
		if name == a {
			continue
		}
		name, _, _ = strings.Cut(name, "=")
		if name == "rig" {
			return false // xdrcheck replay --rig: the service rigs' own form
		}
	}
	for _, a := range args {
		if a == "--" {
			break
		}
		name := strings.TrimLeft(a, "-")
		if name == a {
			continue
		}
		name, _, _ = strings.Cut(name, "=")
		switch name {
		case "target", "issue", "tx", "ledgers", "set", "cap", "ledger-file":
			return true
		}
	}
	return false
}

// listFlag collects a repeatable, comma-separated flag.
type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }
func (l *listFlag) Set(s string) error {
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			*l = append(*l, p)
		}
	}
	return nil
}

// sourceFlags are the flags every data-side command shares to find ledgers.
type sourceFlags struct {
	dataset, lake, corpus, network, lakeURL string
	offline                                 bool
	parallel                                int
	rate                                    float64
}

func (s *sourceFlags) add(fs *flag.FlagSet) {
	fs.StringVar(&s.dataset, "dataset", "", "dataset directory (default $"+hunt.EnvName("DATASET")+", else the per-user data directory)")
	fs.StringVar(&s.lake, "lake", "", "ledger cache in lake layout (default $"+hunt.EnvName("LAKE")+", else <dataset>/lake)")
	fs.StringVar(&s.corpus, "corpus", "corpus", "corpus root (for --cap, --issue and corpus ledgers)")
	fs.StringVar(&s.network, "network", "", "pubnet or testnet (default: pubnet, or the network of the issue or corpus entry)")
	fs.StringVar(&s.lakeURL, "lake-url", "", "lake URL to fetch missing ledgers from (default: the public pubnet lake)")
	fs.BoolVar(&s.offline, "offline", false, "never use the network: no ledger download, no target fetch")
	fs.IntVar(&s.parallel, "parallel", 64, "downloads in flight (at most 256)")
	fs.Float64Var(&s.rate, "rate", 200, "download requests per second, 0 for no cap")
}

// openDataset returns the dataset manifest, or nil when none is present.
func (s *sourceFlags) openDataset() (*dataset.Manifest, error) {
	m, err := dataset.Load(dataset.Dir(s.dataset))
	var u *hunt.Unavailable
	if errors.As(err, &u) {
		return nil, nil
	}
	return m, err
}

type replayInput struct {
	seq    uint32
	path   string
	object string
}

func huntReplay(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(hunt.Tool+" replay --target", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		src          sourceFlags
		target       = fs.String("target", "", "go, js, rust, python, wallet-backend, stellar-etl or horizon (required)")
		version      = fs.String("version", "", "tag, commit, branch (main) or local path of the target (required unless --issue gives it)")
		ledgers      = fs.String("ledgers", "", "ledgers: comma-separated sequences and ranges a-b, or @FILE")
		set          = fs.String("set", "", "a named ledger set of the dataset (xdrcheck data sets)")
		capN         = fs.Int("cap", 0, "the corpus ledgers of a CAP")
		issue        = fs.String("issue", "", "a known issue, repo#n (issues.json): its ledgers, and by default its pre-fix version")
		fixed        = fs.Bool("fixed", false, "with --issue and no --version: run the fixed version instead of the pre-fix one")
		out          = fs.String("out", "", "run directory (default runs/<time>-<target>-<version>)")
		force        = fs.Bool("force", false, "replace a run directory that already holds a run")
		dispositions = fs.String("dispositions", hunt.Env("DISPOSITIONS"), "private dispositions overlay table (default $"+hunt.EnvName("DISPOSITIONS")+")")
		issuesOver   = fs.String("issues-overlay", hunt.Env("ISSUES"), "private issues overlay file (default $"+hunt.EnvName("ISSUES")+")")
		rebuild      = fs.Bool("rebuild", false, "rebuild the target even when the cache holds this version")
		maxLedgers   = fs.Int("max-ledgers", 5000, "refuse selections larger than this")
		failOn       = fs.String("fail-on", "", "exit 1 when a cluster has this disposition (for example candidate)")
		rigArgs      = fs.String("rig-args", "", "pipeline targets: extra flags for the rig, space-separated (e.g. \"--shards 24\")")
		scope        = fs.String("scope", "", "pipeline targets: the judge's scope file")
		judgeJobs    = fs.Int("judge-jobs", 0, "pipeline targets: judge facts threads (0: the judge's default)")
		txs          listFlag
		files        listFlag
	)
	src.add(fs)
	fs.Var(&txs, "tx", "a transaction, LEDGER:INDEX (0-based apply order) or a 64-hex hash (with --ledgers to search); repeatable")
	fs.Var(&files, "ledger-file", "a ledger object file (zstd LedgerCloseMetaBatch or raw LedgerCloseMeta; name SEQ.xdr or a lake key); repeatable")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, hunt.Tool+" replay: "+format+"\n", a...)
		return 2
	}
	if fs.NArg() > 0 {
		return fail("unexpected arguments %v", fs.Args())
	}
	sel := rundir.Selection{Set: *set, Cap: *capN, Issue: *issue}
	allIssues, err := issues.Load(*issuesOver)
	if err != nil {
		return fail("%v", err)
	}
	var is *issues.Issue
	if *issue != "" {
		i, err := issues.Find(allIssues, *issue)
		if err != nil {
			return fail("%v", err)
		}
		is = &i
		if *target == "" {
			*target = i.Target
		}
		if *version == "" {
			*version = i.Prefix
			if *fixed {
				*version = i.Fixed
			}
		}
		if src.network == "" {
			src.network = i.Network
		}
	}
	if _, err := targets.Get(*target); err != nil {
		return fail("--target: %v", err)
	}
	if *version == "" {
		return fail("--version is required")
	}
	if src.network == "" {
		src.network = "pubnet"
	}
	pass, err := dataset.Passphrase(src.network)
	if err != nil {
		return fail("%v", err)
	}
	ds, err := src.openDataset()
	if err != nil {
		return fail("%v", err)
	}
	// ---- selection → refs (ledger, tx) and corpus inputs
	var refs []dataset.TxRef
	var hashes []string
	var corpusVs []issues.Variant
	if *ledgers != "" {
		ls, err := dataset.ParseLedgers(*ledgers)
		if err != nil {
			return fail("--ledgers: %v", err)
		}
		sel.Ledgers = ls
		for _, l := range ls {
			refs = append(refs, dataset.TxRef{Ledger: l, Tx: -1})
		}
	}
	for _, t := range txs {
		if dataset.IsHash(t) {
			hashes = append(hashes, strings.ToLower(t))
			continue
		}
		r, err := dataset.ParseTx(t)
		if err != nil {
			return fail("--tx: %v", err)
		}
		refs = append(refs, r)
		sel.Txs = append(sel.Txs, r.String())
	}
	if len(hashes) > 0 && *ledgers == "" && is == nil {
		return fail("--tx HASH needs --ledgers to search (the index maps ledgers to transactions, not hashes)")
	}
	if *set != "" {
		if ds == nil {
			return fail("--set needs a dataset (%s)", hunt.Missing("dataset manifest", hunt.Tool+" data status").Error())
		}
		r, err := ds.SetRefs(*set)
		if err != nil {
			return fail("%v", err)
		}
		refs = append(refs, r...)
	}
	if *capN > 0 || is != nil {
		vs, err := issues.Corpus(src.corpus)
		if err != nil {
			return fail("%v", err)
		}
		if *capN > 0 {
			for _, v := range issues.ByCap(vs, *capN) {
				if v.Network == src.network {
					corpusVs = append(corpusVs, v)
				}
			}
			if len(corpusVs) == 0 {
				return fail("the corpus has no %s ledger for CAP %d", src.network, *capN)
			}
		}
		if is != nil && is.CorpusEntry != "" {
			for _, v := range issues.ByEntry(vs, is.CorpusEntry) {
				if v.Network == src.network && (is.Ledger == 0 || v.Ledger == is.Ledger) {
					corpusVs = append(corpusVs, v)
					break
				}
			}
			if len(corpusVs) == 0 {
				return fail("issue %s: corpus entry %s has no %s ledger", is.ID, is.CorpusEntry, src.network)
			}
			if is.TxHash != "" {
				hashes = append(hashes, is.TxHash)
			}
		} else if is != nil && is.Ledger > 0 {
			refs = append(refs, dataset.TxRef{Ledger: is.Ledger, Tx: -1})
		}
	}
	if len(refs) == 0 && len(corpusVs) == 0 && len(files) == 0 {
		return fail("nothing selected: give --ledgers, --tx, --set, --cap, --issue or --ledger-file")
	}
	// ---- run directory
	if *out == "" {
		*out = filepath.Join("runs", time.Now().UTC().Format("20060102T150405Z")+"-"+*target+"-"+sanitize(*version))
	}
	if abs, err := filepath.Abs(*out); err == nil {
		*out = abs
	}
	dir, err := rundir.Create(*out, *force)
	if err != nil {
		return fail("%v", err)
	}
	started := time.Now()
	r := &rundir.Run{Manifest: rundir.Manifest{
		Tool:      rundir.ToolInfo{Name: hunt.Tool, Version: hunt.Version},
		Target:    *target,
		Version:   rundir.VersionInfo{Requested: *version},
		Network:   src.network,
		Selection: sel,
		Command:   append([]string{hunt.Tool, "replay"}, args...),
		Host:      rundir.ThisHost(),
		Started:   started.UTC().Format(time.RFC3339),
	}}
	if ds != nil {
		r.Manifest.Dataset = &rundir.DatasetRef{Version: ds.Version, TipLedger: ds.TipLedger}
		if f, err := dataset.FileOf(ds.Path()); err == nil {
			r.Manifest.Dataset.ManifestSHA256 = f.SHA256
		}
	}
	finish := func(status, msg string, res *targets.Result, b *targets.Built) int {
		r.Summary.Status, r.Summary.Message = status, msg
		r.Summary.Cost.WallS = time.Since(started).Seconds()
		if b != nil {
			r.Manifest.Version.Resolved, r.Manifest.Version.Source = b.Resolved, b.Source
			r.Summary.Cost.BuildS = b.BuildS
		}
		if r.Manifest.Version.Resolved == "" {
			r.Manifest.Version.Resolved = "not built"
		}
		var tested map[string]int64
		if res != nil {
			tested = res.Tested
			r.Summary.Cost.Ledgers, r.Summary.Cost.Txs, r.Summary.Cost.CPUS = res.Ledgers, res.Txs, res.CPUS
		}
		rundir.Summarise(&r.Summary, r.Verdicts, r.Clusters.Clusters, tested)
		r.Manifest.Finished = time.Now().UTC().Format(time.RFC3339)
		if err := dir.Save(r); err != nil {
			fmt.Fprintf(stderr, hunt.Tool+" replay: %v\n", err)
			return 2
		}
		fmt.Fprintf(stdout, "%s %s@%s: %s", hunt.Tool, *target, r.Manifest.Version.Resolved, status)
		if msg != "" {
			fmt.Fprintf(stdout, " (%s)", msg)
		}
		fmt.Fprintf(stdout, "; %d rows in %d clusters -> %s\n", len(r.Verdicts), len(r.Clusters.Clusters), dir.Path)
		for i, c := range r.Clusters.Clusters {
			if i == 12 {
				fmt.Fprintf(stdout, "  … %d more in clusters.json\n", len(r.Clusters.Clusters)-i)
				break
			}
			fmt.Fprintf(stdout, "  %-16s %5d  %s\n", c.Disposition, c.Count, c.Key)
		}
		switch status {
		case rundir.StatusUnavailable:
			return 3
		case rundir.StatusFailed, rundir.StatusPartial:
			return 2
		}
		if *failOn != "" && r.Summary.Clusters[*failOn] > 0 {
			return 1
		}
		return 0
	}
	r.Clusters.Target, r.Clusters.Version = *target, *version
	// ---- inputs
	var inputs []replayInput
	for i, f := range files {
		seq, obj, err := ledgerFileInput(f, dir.Work("inputs"), i)
		if err != nil {
			return fail("--ledger-file %s: %v", f, err)
		}
		inputs = append(inputs, replayInput{seq: seq, path: obj, object: filepath.Base(f)})
		r.Manifest.Selection.LedgerFiles = append(r.Manifest.Selection.LedgerFiles, filepath.Base(f))
	}
	seenSeq := map[uint32]string{}
	for _, v := range corpusVs {
		if prev, dup := seenSeq[v.Ledger]; dup {
			// rows are keyed by ledger sequence: two variants with one sequence (local-core twins) cannot share a run
			fmt.Fprintf(stderr, "skipping %s ledger %d: the run already has %s at that sequence\n", v.Entry, v.Ledger, prev)
			continue
		}
		seenSeq[v.Ledger] = v.Entry
		blob, err := os.ReadFile(v.BlobPath)
		if err != nil {
			return fail("corpus entry %s: %v", v.Entry, err)
		}
		p := dir.Work("inputs", fmt.Sprintf("%d.xdr.zst", v.Ledger))
		if _, err := ledger.WriteBlobObject(blob, v.Ledger, p); err != nil {
			return fail("%v", err)
		}
		inputs = append(inputs, replayInput{seq: v.Ledger, path: p, object: "corpus:" + v.Entry})
		if v.FocusTx != nil && is == nil {
			refs = append(refs, dataset.TxRef{Ledger: v.Ledger, Tx: -1})
		}
	}
	have := map[uint32]bool{}
	for _, in := range inputs {
		have[in.seq] = true
	}
	var want []uint32
	for _, l := range dataset.Ledgers(refs) {
		if !have[l] {
			want = append(want, l)
		}
	}
	if len(want)+len(inputs) > *maxLedgers {
		return fail("%d ledgers selected, more than --max-ledgers %d", len(want)+len(inputs), *maxLedgers)
	}
	lk := dataset.NewLake(ds, dataset.LakeDir(src.lake, dataset.Dir(src.dataset)), src.network)
	var missing []uint32
	for _, s := range want {
		if lk.Locate(s) == "" {
			missing = append(missing, s)
		}
	}
	if len(missing) > 0 {
		if src.offline {
			return finish(rundir.StatusFailed, fmt.Sprintf("%d ledgers not in any local lake and --offline", len(missing)), nil, nil)
		}
		fmt.Fprintf(stderr, "fetching %d ledgers into %s\n", len(missing), lk.Cache)
		res, err := lk.Fetch(ctx, missing, dataset.FetchOptions{BaseURL: src.lakeURL, Parallel: src.parallel, Rate: src.rate, Local: true})
		if err != nil {
			return fail("fetch: %v", err)
		}
		if len(res.Failed) > 0 {
			return fail("fetch: %d ledgers failed: %v", len(res.Failed), res.Failed)
		}
	}
	for _, s := range want {
		inputs = append(inputs, replayInput{seq: s, path: lk.Locate(s), object: lk.Key(s)})
	}
	sort.Slice(inputs, func(i, j int) bool { return inputs[i].seq < inputs[j].seq })
	var tin []targets.Input
	for _, in := range inputs {
		f, err := dataset.FileOf(in.path)
		if err != nil {
			return fail("%v", err)
		}
		r.Manifest.Inputs = append(r.Manifest.Inputs, rundir.Input{Kind: "ledger", Ledger: in.seq, Object: in.object, SHA256: f.SHA256, Bytes: f.Bytes})
		tin = append(tin, targets.Input{Seq: in.seq, Path: in.path})
	}
	// transaction hashes → indexes
	for _, h := range hashes {
		found := false
		for _, in := range inputs {
			if i, err := ledger.FindHash(in.path, pass, h); err == nil && i >= 0 {
				refs = append(refs, dataset.TxRef{Ledger: in.seq, Tx: i})
				r.Manifest.Selection.Txs = append(r.Manifest.Selection.Txs, fmt.Sprintf("%d:%d", in.seq, i))
				found = true
				break
			}
		}
		if !found {
			return fail("transaction %s is in none of the selected ledgers", h)
		}
	}
	// ---- build and run
	tg, _ := targets.Get(*target)
	logf, _ := os.Create(dir.Work("build.log"))
	defer logf.Close()
	o := targets.Options{Version: *version, Passphrase: pass, Offline: src.offline, Rebuild: *rebuild, Log: logf,
		RigArgs: strings.Fields(*rigArgs), Scope: *scope, JudgeJobs: *judgeJobs}
	b, err := tg.Build(ctx, o)
	var u *hunt.Unavailable
	if errors.As(err, &u) {
		return finish(rundir.StatusUnavailable, err.Error(), nil, nil)
	}
	if err != nil {
		return finish(rundir.StatusFailed, "build: "+firstLine(err.Error())+" (see work/build.log)", nil, nil)
	}
	fmt.Fprintf(stderr, "built %s %s (%s)\n", *target, b.Resolved, b.Dir)
	res, err := tg.Run(ctx, b, tin, dir.Work(), o)
	if errors.As(err, &u) {
		return finish(rundir.StatusUnavailable, err.Error(), nil, b)
	}
	if err != nil {
		return finish(rundir.StatusFailed, "run: "+firstLine(err.Error()), nil, b)
	}
	r.Verdicts = filterRows(res.Rows, refs, inputs)
	disp, err := rundir.LoadDispositions(*dispositions)
	if err != nil {
		return fail("%v", err)
	}
	r.Clusters.Version = b.Resolved
	r.Clusters.Clusters = rundir.Group(*target, r.Verdicts, disp, strataOf(ds, inputs))
	msg := ""
	if hasTxOnly(refs, inputs) {
		msg = "rows limited to the selected transactions; tested counts cover whole ledgers"
	}
	if n := targets.NotIngested(res.LedgerStatus); n > 0 {
		// a ledger the pipeline did not ingest has no rows of its own to judge: the run is not complete
		part := fmt.Sprintf("%d of %d ledgers not ingested (%s; see work/rig/status.jsonl)", n, len(inputs), targets.StatusText(res.LedgerStatus))
		if msg != "" {
			part += "; " + msg
		}
		return finish(rundir.StatusPartial, part, res, b)
	}
	return finish(rundir.StatusComplete, msg, res, b)
}

func sanitize(s string) string {
	s = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, s)
	if len(s) > 40 {
		s = s[len(s)-40:]
	}
	return s
}

// ledgerFileInput turns a --ledger-file into a lake object under dir and returns its sequence.
func ledgerFileInput(path, dir string, i int) (uint32, string, error) {
	raw, err := ledger.ReadObject(path)
	if err != nil {
		return 0, "", err
	}
	seq := seqFromName(filepath.Base(path))
	b, err := ledger.Batch(path)
	if err == nil && len(b.LedgerCloseMetas) > 0 {
		abs, _ := filepath.Abs(path)
		return b.LedgerCloseMetas[0].LedgerSequence(), abs, nil
	}
	if seq == 0 {
		return 0, "", fmt.Errorf("not a LedgerCloseMetaBatch, and no ledger sequence in the file name (SEQ.xdr)")
	}
	p := filepath.Join(dir, fmt.Sprintf("%d.xdr.zst", seq))
	_, err = ledger.WriteBlobObject(raw, seq, p)
	return seq, p, err
}

func seqFromName(name string) uint32 {
	name = strings.TrimSuffix(strings.TrimSuffix(name, ".zst"), ".xdr")
	if i := strings.LastIndex(name, "--"); i >= 0 {
		name = name[i+2:]
	}
	n, _ := strconv.ParseUint(name, 10, 32)
	return uint32(n)
}

// filterRows keeps the rows of the selection: every row of a ledger selected whole, and the rows of each
// selected transaction of a ledger selected only by transaction.
func filterRows(rows []rundir.Verdict, refs []dataset.TxRef, inputs []replayInput) []rundir.Verdict {
	whole := map[uint32]bool{}
	txOf := map[uint32]map[int]bool{}
	for _, in := range inputs {
		whole[in.seq] = true
	}
	for _, r := range refs {
		if r.Tx >= 0 {
			if txOf[r.Ledger] == nil {
				txOf[r.Ledger] = map[int]bool{}
			}
			txOf[r.Ledger][r.Tx] = true
		}
	}
	for _, r := range refs {
		if r.Tx < 0 {
			delete(txOf, r.Ledger)
		}
	}
	var out []rundir.Verdict
	for _, v := range rows {
		if m, ok := txOf[v.Ledger]; ok {
			if v.Tx == nil || !m[*v.Tx] {
				continue
			}
		} else if !whole[v.Ledger] {
			continue
		}
		out = append(out, v)
	}
	return out
}

func hasTxOnly(refs []dataset.TxRef, inputs []replayInput) bool {
	all := map[uint32]bool{}
	for _, r := range refs {
		if r.Tx < 0 {
			all[r.Ledger] = true
		}
	}
	for _, r := range refs {
		if r.Tx >= 0 && !all[r.Ledger] {
			return true
		}
	}
	return false
}

// strataOf returns the dataset strata of the run's ledgers (from the kept-ledger index), or nil.
func strataOf(ds *dataset.Manifest, inputs []replayInput) func(uint32) []string {
	if ds == nil {
		return nil
	}
	want := map[uint32]bool{}
	for _, in := range inputs {
		want[in.seq] = true
	}
	got := map[uint32][]string{}
	err := ds.ScanTable("kept_ledgers", func(cols map[string]int, row []string) bool {
		s, err := strconv.ParseUint(row[cols["seq"]], 10, 32)
		if err == nil && want[uint32(s)] {
			if i, ok := cols["strata"]; ok && i < len(row) && row[i] != "" {
				got[uint32(s)] = strings.Split(row[i], ",")
			}
		}
		return true
	})
	if err != nil {
		return nil
	}
	return func(s uint32) []string { return got[s] }
}

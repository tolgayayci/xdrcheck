package main

// xdrcheck replay --rig (service rigs): a real pipeline built from source at a commit, run over ledgers read from a
// lake-layout directory, with its rows exported to the common row schema.
//
//	xdrcheck replay --rig wallet-backend|stellar-etl|horizon --ledgers LIST|RANGE|@FILE --commit SHA --out DIR
//	           [--lake DIR] [--network pubnet|testnet|PASSPHRASE] [--fetch URL|none] [--fetch-cache DIR]
//	           [--shards N] [--memory-max SIZE] [--cachedir DIR] [--pins FILE] [--name-prefix P]
//	           wallet-backend: [--seed DIR] [--seed-rpc URL] [--seed-only] [--protocols ID,ID] [--skip-halted]
//	                           [--no-retry-halt]
//	           horizon: --commit takes a tag too (v30.0.1); ledgers come from --lake only (no fetch); see
//	                    go/adapters/horizon/README.md
//
// Output (DIR): manifest.json, status.jsonl (one line per requested ledger: ingested | halted | skipped |
// harness_fault; stellar-etl also dropped: exported cleanly but a drop check failed), rows.jsonl (common rows), checks.jsonl, summary.json, and per shard shard-N/{tables or exports,
// logs}. Exit codes: 0 every ledger was ingested; 1 a ledger halted, was skipped or dropped; 2 a harness fault or bad
// arguments.
//
// --seed-rpc fetches the state seed (the instance entries of the WASM contracts the ledgers touch and their code
// entries) from an RPC into --seed; a request header for it, if needed, is read from $XDRCHECK_STATE_RPC_HEADER
// ("Name: value") and never written anywhere.

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	protocol "github.com/stellar/go-stellar-sdk/protocols/rpc"

	"github.com/tolgayayci/xdrcheck/go/adapters/stellaretl"
	"github.com/tolgayayci/xdrcheck/go/adapters/walletbackend"
	"github.com/tolgayayci/xdrcheck/go/internal/rig"
	"github.com/tolgayayci/xdrcheck/go/internal/userdir"
)

const (
	passPubnet  = "Public Global Stellar Network ; September 2015"
	passTestnet = "Test SDF Network ; September 2015"
)

func usesRig(args []string) bool {
	for _, a := range args {
		if a == "--rig" || a == "-rig" || strings.HasPrefix(a, "--rig=") || strings.HasPrefix(a, "-rig=") {
			return true
		}
	}
	return false
}

type rigManifest struct {
	Schema     string         `json:"schema"`
	Rig        string         `json:"rig"`
	Commit     string         `json:"commit"`
	Requested  string         `json:"requested_commit"`
	Network    string         `json:"network"`
	Lake       string         `json:"lake"`
	Ledgers    int            `json:"ledgers"`
	Segments   int            `json:"segments"`
	Shards     int            `json:"shards"`
	Started    string         `json:"started"`
	WallMS     int64          `json:"wall_ms"`
	Host       map[string]any `json:"host"`
	ShardsInfo []any          `json:"shard_reports"`
}

func replayRig(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("xdrcheck replay --rig", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		rigName    = fs.String("rig", "", "wallet-backend, stellar-etl or horizon")
		ledgers    = fs.String("ledgers", "", "ledgers: A-B, A,B,C or @FILE (first column)")
		commit     = fs.String("commit", "", "commit, tag or branch of the pipeline (built from source, cached per commit)")
		out        = fs.String("out", "", "run directory")
		lakeDir    = fs.String("lake", "", "lake-layout directory holding the ledgers (index.tsv optional; required)")
		network    = fs.String("network", "pubnet", "pubnet, testnet or a passphrase")
		fetch      = fs.String("fetch", rig.PublicLake, "lake URL to fetch ledgers the lake directory lacks (none: never)")
		fetchCache = fs.String("fetch-cache", "", "where fetched ledgers are kept (default <cachedir>/rig-lake)")
		shards     = fs.Int("shards", 1, "parallel shards; each has its own process and database")
		cachedir   = fs.String("cachedir", "", "adapter cache root (default <user cache>/xdrcheck/adapters)")
		pinsFile   = fs.String("pins", "", "pins file (default: pins.toml found upwards)")
		prefix     = fs.String("name-prefix", "", "docker name prefix (default xdrcheck-rig-<pid>)")
		seedDir    = fs.String("seed", "", "wallet-backend: state seed directory (entries.jsonl)")
		seedRPC    = fs.String("seed-rpc", "", "wallet-backend: fetch missing seed entries from this RPC first")
		seedOnly   = fs.Bool("seed-only", false, "wallet-backend: build the seed and stop")
		protocols  = fs.String("protocols", "", "wallet-backend: protocol ids to classify and enable (default: all the commit registers)")
		skipHalted = fs.Bool("skip-halted", false, "wallet-backend: after a halt, move the cursor past the halted ledger and go on")
		noRetry    = fs.Bool("no-retry-halt", false, "wallet-backend: do not restart once after a halt")
		deadline   = fs.Duration("segment-deadline", 0, "wallet-backend: deadline per segment (default 90s + 3s per ledger)")
		logLevel   = fs.String("log-level", "", "wallet-backend: the service's log level (default INFO)")
	)
	var memMax sizeFlag = 4 << 30
	fs.Var(&memMax, "memory-max", "memory cap per database container (wallet-backend) or export command (stellar-etl)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *rigName != "wallet-backend" && *rigName != "stellar-etl" && *rigName != "horizon" {
		fmt.Fprintln(stderr, "xdrcheck replay: --rig must be wallet-backend, stellar-etl or horizon")
		return 2
	}
	if *ledgers == "" || (*commit == "" && !*seedOnly) || *out == "" || *lakeDir == "" {
		fmt.Fprintln(stderr, "xdrcheck replay --rig: --ledgers, --lake, --commit and --out are required")
		return 2
	}
	seqs, err := rig.ParseLedgers(*ledgers)
	if err != nil {
		fmt.Fprintln(stderr, "xdrcheck replay:", err)
		return 2
	}
	pass := *network
	switch pass {
	case "pubnet":
		pass = passPubnet
	case "testnet":
		pass = passTestnet
	}
	if *cachedir == "" {
		d, _ := userdir.UserCache()
		*cachedir = filepath.Join(d, "adapters")
	}
	if *fetchCache == "" {
		*fetchCache = filepath.Join(*cachedir, "rig-lake")
	}
	if *fetch == "none" {
		*fetch = ""
	}
	if *pinsFile == "" {
		*pinsFile = findPinsUp()
	}
	if *prefix == "" {
		*prefix = fmt.Sprintf("xdrcheck-rig-%d", os.Getpid())
	}
	if *rigName == "horizon" {
		return replayRigHorizon(ctx, horizonRigArgs{ledgers: seqs, commit: *commit, out: *out, lake: *lakeDir,
			passphrase: pass, shards: *shards, cachedir: *cachedir, prefix: *prefix}, stdout, stderr)
	}
	lk, err := rig.OpenLake(*lakeDir, pass, *fetch, *fetchCache)
	if err != nil {
		fmt.Fprintln(stderr, "xdrcheck replay:", err)
		return 2
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fmt.Fprintln(stderr, "xdrcheck replay:", err)
		return 2
	}
	segs := rig.Segments(seqs)
	start := time.Now()
	logw := &lockedWriter{w: stderr}

	seedMap, err := rig.LoadSeed(*seedDir)
	if err != nil {
		fmt.Fprintln(stderr, "xdrcheck replay:", err)
		return 2
	}
	if *rigName == "wallet-backend" && *seedRPC != "" {
		if *seedDir == "" {
			fmt.Fprintln(stderr, "xdrcheck replay: --seed-rpc needs --seed")
			return 2
		}
		n, err := buildSeed(ctx, lk, pass, seqs, *seedRPC, os.Getenv("XDRCHECK_STATE_RPC_HEADER"), seedMap, *seedDir, logw)
		if err != nil {
			fmt.Fprintln(stderr, "xdrcheck replay: seed:", err)
			return 2
		}
		fmt.Fprintf(stderr, "xdrcheck replay: seed holds %d entries (%d new)\n", len(seedMap), n)
	}
	if *seedOnly {
		return 0
	}

	parts := rig.Shard(segs, *shards)
	reports := make([]any, len(parts))
	errs := make([]error, len(parts))
	var wg sync.WaitGroup
	for i, part := range parts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dir := filepath.Join(*out, fmt.Sprintf("shard-%d", i))
			switch *rigName {
			case "wallet-backend":
				var ps []string
				if *protocols != "" {
					ps = strings.Split(*protocols, ",")
				}
				rep, err := walletbackend.RunRig(ctx, walletbackend.RigOptions{Pins: *pinsFile, CacheDir: *cachedir,
					NamePrefix: fmt.Sprintf("%s-%d", *prefix, i), Commit: *commit, Passphrase: pass, Lake: lk, Segments: part,
					Shard: i, Out: dir, MemoryMax: int64(memMax), Seed: seedMap, Protocols: ps, SkipHalted: *skipHalted,
					RetryHalt: !*noRetry, SegmentDeadline: *deadline, LogLevel: *logLevel, Log: logw})
				reports[i], errs[i] = rep, err
			case "stellar-etl":
				rep, err := stellaretl.RunRig(ctx, stellaretl.RigOptions{CacheDir: *cachedir, Commit: *commit, Passphrase: pass,
					Lake: lk, Segments: part, Shard: i, Out: dir, ExportMemoryMax: int64(memMax), Log: logw})
				reports[i], errs[i] = rep, err
			}
		}()
	}
	wg.Wait()

	man := rigManifest{Schema: "xcc.rig/v1", Rig: *rigName, Requested: *commit, Network: pass, Lake: *lakeDir, Ledgers: len(seqs),
		Segments: len(segs), Shards: len(parts), Started: start.UTC().Format(time.RFC3339), WallMS: time.Since(start).Milliseconds(),
		Host: map[string]any{"cpus": runtime.NumCPU()}, ShardsInfo: reports}
	code := 0
	for i, err := range errs {
		if err != nil {
			fmt.Fprintf(stderr, "xdrcheck replay: shard %d: %v\n", i, err)
			man.ShardsInfo[i] = map[string]string{"error": err.Error()}
			code = 2
		}
	}
	for _, r := range reports {
		switch x := r.(type) {
		case *walletbackend.RigReport:
			if x != nil {
				man.Commit = x.Commit
			}
		case *stellaretl.RigReport:
			if x != nil {
				man.Commit = x.Commit
			}
		}
	}
	// Merge the shards' files.
	counts := map[string]int{}
	if err := mergeRows(*out, len(parts), counts); err != nil {
		fmt.Fprintln(stderr, "xdrcheck replay:", err)
		return 2
	}
	for _, name := range []string{"status.jsonl", "checks.jsonl"} {
		n, err := mergeShards(*out, len(parts), name, counts, name == "status.jsonl")
		if err != nil {
			fmt.Fprintln(stderr, "xdrcheck replay:", err)
			return 2
		}
		counts["lines:"+name] = n
	}
	rig.WriteJSON(filepath.Join(*out, "manifest.json"), man)
	summary := map[string]any{"ledgers": len(seqs), "wall_ms": man.WallMS, "counts": counts,
		"ms_per_ledger": float64(man.WallMS) / float64(max(1, len(seqs)))}
	rig.WriteJSON(filepath.Join(*out, "summary.json"), summary)
	fmt.Fprintf(stdout, "%s %s: %d ledgers in %d segments, %d shards, %.0f ms/ledger; %v\n", *rigName, shortCommit(man.Commit), len(seqs),
		len(segs), len(parts), summary["ms_per_ledger"], statusCounts(counts))
	if code == 0 {
		if counts["status:"+rig.StatusHarnessFault] > 0 {
			code = 2
		} else if counts["status:"+rig.StatusHalted]+counts["status:"+rig.StatusSkipped]+counts["status:"+stellaretl.StatusDropped] > 0 {
			code = 1
		}
	}
	return code
}

func shortCommit(c string) string {
	if len(c) > 12 {
		return c[:12]
	}
	return c
}

func statusCounts(c map[string]int) string {
	var parts []string
	for _, s := range []string{rig.StatusIngested, stellaretl.StatusDropped, rig.StatusHalted, rig.StatusSkipped, rig.StatusHarnessFault} {
		parts = append(parts, fmt.Sprintf("%s=%d", s, c["status:"+s]))
	}
	parts = append(parts, fmt.Sprintf("rows=%d other=%d", c["lines:rows.jsonl"], c["lines:rows-other.jsonl"]))
	return strings.Join(parts, " ")
}

// mergeShards concatenates shard-N/name into out/name (status lines sorted by ledger) and counts statuses.
func mergeShards(out string, n int, name string, counts map[string]int, sortLedger bool) (int, error) {
	var lines [][]byte
	dst, err := os.Create(filepath.Join(out, name))
	if err != nil {
		return 0, err
	}
	defer dst.Close()
	bw := bufio.NewWriterSize(dst, 1<<20)
	defer bw.Flush()
	total := 0
	for i := 0; i < n; i++ {
		f, err := os.Open(filepath.Join(out, fmt.Sprintf("shard-%d", i), name))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 256<<20)
		for sc.Scan() {
			total++
			if sortLedger {
				lines = append(lines, slices.Clone(sc.Bytes()))
				continue
			}
			bw.Write(sc.Bytes())
			bw.WriteByte('\n')
		}
		f.Close()
	}
	if sortLedger {
		type st struct {
			Ledger uint32 `json:"ledger"`
			Status string `json:"status"`
		}
		parsed := make([]st, len(lines))
		for i, l := range lines {
			json.Unmarshal(l, &parsed[i])
			counts["status:"+parsed[i].Status]++
		}
		idx := make([]int, len(lines))
		for i := range idx {
			idx[i] = i
		}
		sort.SliceStable(idx, func(a, b int) bool { return parsed[idx[a]].Ledger < parsed[idx[b]].Ledger })
		for _, i := range idx {
			bw.Write(lines[i])
			bw.WriteByte('\n')
		}
	}
	return total, nil
}

// buildSeed fetches the instance entries of the contracts the ledgers touch and the code entries they bind to.
func buildSeed(ctx context.Context, lk *rig.Lake, pass string, seqs []uint32, url, header string, seed map[string]protocol.LedgerEntryResult, dir string, log io.Writer) (int, error) {
	contracts := map[string]bool{}
	var hashes []string
	for _, q := range seqs {
		lcm, err := lk.Load(ctx, q)
		if err != nil {
			return 0, err
		}
		info, err := rig.Analyze(pass, lcm)
		if err != nil {
			return 0, err
		}
		for _, c := range info.Contracts {
			if _, sac := info.SACs[c]; !sac {
				contracts[c] = true
			}
		}
		for _, h := range info.Instances {
			if h != "" {
				hashes = append(hashes, h)
			}
		}
		for _, h := range info.InstancesBefore {
			hashes = append(hashes, h)
		}
	}
	var keys []string
	var list []string
	for c := range contracts {
		list = append(list, c)
		k, err := walletbackend.InstanceKey(c)
		if err == nil {
			if _, have := seed[k]; !have {
				keys = append(keys, k)
			}
		}
	}
	sort.Strings(keys)
	got, err := rig.FetchEntries(ctx, url, header, keys)
	if err != nil {
		return 0, err
	}
	added := len(got)
	for k, e := range got {
		seed[k] = e
	}
	keys = keys[:0]
	for _, h := range walletbackend.SeedWasmHashes(seed, list, hashes...) {
		k, err := walletbackend.CodeKey(h)
		if err == nil {
			if _, have := seed[k]; !have {
				keys = append(keys, k)
			}
		}
	}
	got, err = rig.FetchEntries(ctx, url, header, keys)
	if err != nil {
		return 0, err
	}
	added += len(got)
	for k, e := range got {
		seed[k] = e
	}
	fmt.Fprintf(log, "seed: %d contracts, %d instance and code entries fetched\n", len(contracts), added)
	return added, rig.SaveSeed(dir, seed)
}

func findPinsUp() string {
	d, err := os.Getwd()
	if err != nil {
		return ""
	}
	for {
		p := filepath.Join(d, "pins.toml")
		if _, err := os.Stat(p); err == nil {
			return p
		}
		parent := filepath.Dir(d)
		if parent == d {
			return ""
		}
		d = parent
	}
}

type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// judgeKinds are the row kinds the judge compares; they go to rows.jsonl, sorted by ledger. Every other row goes
// to rows-other.jsonl in shard order. Besides the judge's own families, a rig may write kinds that a target's
// scope file compares with one of them: effect_balance_change (effects, as balance changes) and op_token_event
// (an operation's asset balance changes, as token events).
var judgeKinds = map[string]bool{"balance_change": true, "participant": true, "entry_change": true, "token_event": true, "ledger": true,
	"effect_balance_change": true, "op_token_event": true}

func mergeRows(out string, n int, counts map[string]int) error {
	type line struct {
		ledger uint32
		b      []byte
	}
	var keep []line
	other, err := os.Create(filepath.Join(out, "rows-other.jsonl"))
	if err != nil {
		return err
	}
	defer other.Close()
	ow := bufio.NewWriterSize(other, 1<<20)
	defer ow.Flush()
	for i := 0; i < n; i++ {
		f, err := os.Open(filepath.Join(out, fmt.Sprintf("shard-%d", i), "rows.jsonl"))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 256<<20)
		for sc.Scan() {
			var h struct {
				Kind   string `json:"kind"`
				Ledger uint32 `json:"ledger"`
				Source string `json:"source"`
			}
			json.Unmarshal(sc.Bytes(), &h)
			counts["rows:"+h.Source+":"+h.Kind]++
			if judgeKinds[h.Kind] {
				keep = append(keep, line{h.Ledger, slices.Clone(sc.Bytes())})
				continue
			}
			counts["lines:rows-other.jsonl"]++
			ow.Write(sc.Bytes())
			ow.WriteByte('\n')
		}
		f.Close()
	}
	sort.SliceStable(keep, func(a, b int) bool { return keep[a].ledger < keep[b].ledger })
	dst, err := os.Create(filepath.Join(out, "rows.jsonl"))
	if err != nil {
		return err
	}
	defer dst.Close()
	bw := bufio.NewWriterSize(dst, 1<<20)
	for _, l := range keep {
		bw.Write(l.b)
		bw.WriteByte('\n')
	}
	counts["lines:rows.jsonl"] = len(keep)
	return bw.Flush()
}

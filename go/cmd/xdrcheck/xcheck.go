package main

// xdrcheck xcheck (docs/xcheck.md): the same transactions through two or more targets or versions; only fields
// computed by both sides are compared, after the rule table of internal/hunt/xcheck.

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/tolgayayci/xdrcheck/go/internal/hunt"
	"github.com/tolgayayci/xdrcheck/go/internal/hunt/dataset"
	"github.com/tolgayayci/xdrcheck/go/internal/hunt/rundir"
	"github.com/tolgayayci/xdrcheck/go/internal/hunt/targets"
	"github.com/tolgayayci/xdrcheck/go/internal/hunt/xcheck"
)

func init() {
	register("xcheck", "the same transactions through two or more targets or versions; diff the fields both compute", func(args []string) int {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return xcheckMain(ctx, args, os.Stdout, os.Stderr)
	})
}

func xcheckMain(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(hunt.Tool+" xcheck", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var src sourceFlags
	src.add(fs)
	var tg, txs, files listFlag
	fs.Var(&tg, "target", "TARGET@VERSION (go, js, python or rust); give two or more; repeatable")
	fs.Var(&txs, "tx", "a transaction LEDGER:INDEX; repeatable")
	fs.Var(&files, "ledger-file", "a ledger object file; repeatable")
	ledgers := fs.String("ledgers", "", "ledgers: comma-separated sequences and ranges a-b, or @FILE")
	set := fs.String("set", "", "a named set of the dataset")
	out := fs.String("out", "", "output directory (default xcheck/<time>)")
	rules := fs.Bool("rules", false, "print the normalisation rules and exit")
	maxLedgers := fs.Int("max-ledgers", 2000, "refuse selections larger than this")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *rules {
		fmt.Fprintf(stdout, "%-12s %-60s %s\n", "rule", "fields", "what is equal")
		for _, r := range xcheck.Rules {
			fmt.Fprintf(stdout, "%-12s %-60s %s\n", r.ID, r.Fields, r.What)
		}
		return 0
	}
	fail := func(f string, a ...any) int {
		fmt.Fprintf(stderr, hunt.Tool+" xcheck: "+f+"\n", a...)
		return 2
	}
	if len(tg) < 2 {
		return fail("give two or more --target TARGET@VERSION")
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
	var refs []dataset.TxRef
	if *ledgers != "" {
		ls, err := dataset.ParseLedgers(*ledgers)
		if err != nil {
			return fail("%v", err)
		}
		for _, l := range ls {
			refs = append(refs, dataset.TxRef{Ledger: l, Tx: -1})
		}
	}
	for _, t := range txs {
		r, err := dataset.ParseTx(t)
		if err != nil {
			return fail("%v", err)
		}
		refs = append(refs, r)
	}
	if *set != "" {
		if ds == nil {
			return fail("--set needs a dataset")
		}
		r, err := ds.SetRefs(*set)
		if err != nil {
			return fail("%v", err)
		}
		refs = append(refs, r...)
	}
	if *out == "" {
		*out = filepath.Join("xcheck", time.Now().UTC().Format("20060102T150405Z"))
	}
	*out, _ = filepath.Abs(*out)
	if err := os.MkdirAll(*out, 0o755); err != nil {
		return fail("%v", err)
	}
	var inputs []targets.Input
	have := map[uint32]bool{}
	for i, f := range files {
		seq, p, err := ledgerFileInput(f, filepath.Join(*out, "inputs"), i)
		if err != nil {
			return fail("--ledger-file %s: %v", f, err)
		}
		inputs = append(inputs, targets.Input{Seq: seq, Path: p})
		have[seq] = true
	}
	var want []uint32
	for _, l := range dataset.Ledgers(refs) {
		if !have[l] {
			want = append(want, l)
		}
	}
	if len(want)+len(inputs) == 0 {
		return fail("nothing selected: give --ledgers, --tx, --set or --ledger-file")
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
			return fail("%d ledgers not in any local lake and --offline", len(missing))
		}
		res, err := lk.Fetch(ctx, missing, dataset.FetchOptions{BaseURL: src.lakeURL, Parallel: src.parallel, Rate: src.rate, Local: true})
		if err != nil || len(res.Failed) > 0 {
			return fail("fetch: %v %v", err, res.Failed)
		}
	}
	for _, s := range want {
		inputs = append(inputs, targets.Input{Seq: s, Path: lk.Locate(s)})
	}
	sort.Slice(inputs, func(i, j int) bool { return inputs[i].Seq < inputs[j].Seq })
	// only the selected transactions when the selection names transactions only
	keep := map[string]bool{}
	whole := map[uint32]bool{}
	for _, r := range refs {
		if r.Tx < 0 {
			whole[r.Ledger] = true
		}
	}
	for _, in := range inputs {
		if have[in.Seq] {
			whole[in.Seq] = true
		}
	}
	for _, r := range refs {
		if r.Tx >= 0 && !whole[r.Ledger] {
			keep[r.String()] = true
		}
	}
	type side struct {
		name, resolved string
		rows           map[string]xcheck.Row
	}
	var sides []side
	for _, t := range tg {
		name, ver, ok := strings.Cut(t, "@")
		if !ok {
			return fail("--target %q: want TARGET@VERSION", t)
		}
		tt, err := targets.Get(name)
		if err != nil {
			return fail("%v", err)
		}
		fl, ok := tt.(targets.Fielder)
		if !ok {
			fmt.Fprintf(stdout, "%s: not available: fields extractor for %s missing (xcheck covers go, js and python)\n", t, name)
			return 3
		}
		o := targets.Options{Version: ver, Passphrase: pass, Offline: src.offline}
		b, err := tt.Build(ctx, o)
		var u *hunt.Unavailable
		if errors.As(err, &u) {
			fmt.Fprintf(stdout, "%s: %v\n", t, err)
			return 3
		}
		if err != nil {
			return fail("%s: build: %v", t, firstLine(err.Error()))
		}
		work := filepath.Join(*out, "work", sanitize(t))
		p, err := fl.Fields(ctx, b, inputs, work, o)
		if err != nil {
			return fail("%s: %v", t, firstLine(err.Error()))
		}
		rows, err := xcheck.Read(p)
		if err != nil {
			return fail("%v", err)
		}
		if len(keep) > 0 {
			for k := range rows {
				if !keep[k] {
					delete(rows, k)
				}
			}
		}
		label := name + "@" + b.Resolved
		sides = append(sides, side{name: label, resolved: b.Resolved, rows: rows})
		copyOut(p, filepath.Join(*out, "fields-"+sanitize(t)+".jsonl"))
	}
	f, err := os.Create(filepath.Join(*out, "diffs.jsonl"))
	if err != nil {
		return fail("%v", err)
	}
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	type pair struct {
		A     string       `json:"a"`
		B     string       `json:"b"`
		Stats xcheck.Stats `json:"stats"`
	}
	var pairs []pair
	total := 0
	for i := 0; i < len(sides); i++ {
		for j := i + 1; j < len(sides); j++ {
			d, st := xcheck.Compare(sides[i].name, sides[j].name, sides[i].rows, sides[j].rows)
			for _, x := range d {
				enc.Encode(x)
			}
			total += len(d)
			pairs = append(pairs, pair{sides[i].name, sides[j].name, st})
			fmt.Fprintf(stdout, "%s vs %s: %d transactions, %d fields differ\n", sides[i].name, sides[j].name, st.Txs, len(d))
			var fields []string
			for k := range st.Compared {
				fields = append(fields, k)
			}
			sort.Strings(fields)
			for _, k := range fields {
				if st.Differ[k] > 0 {
					fmt.Fprintf(stdout, "  %-34s %6d of %6d differ\n", k, st.Differ[k], st.Compared[k])
				}
			}
		}
	}
	f.Close()
	rundir.WriteJSON(filepath.Join(*out, "summary.json"), map[string]any{
		"schema": hunt.SchemaID("xcheck"), "network": src.network, "command": append([]string{hunt.Tool, "xcheck"}, args...),
		"pairs": pairs, "diffs": total, "rules": xcheck.Rules,
	})
	fmt.Fprintf(stdout, "-> %s (diffs.jsonl, summary.json)\n", *out)
	if total > 0 {
		return 1
	}
	return 0
}

func copyOut(src, dst string) {
	if b, err := os.ReadFile(src); err == nil {
		os.WriteFile(dst, b, 0o644)
	}
}

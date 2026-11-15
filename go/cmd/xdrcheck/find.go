package main

// xdrcheck find (docs/find.md): from a token, a token class, a value tag, a CAP, a linter assumption key, an
// operation type or a named set to example transactions (ledger, tx), from the dataset's index files.

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/tolgayayci/xdrcheck/go/internal/hunt"
	"github.com/tolgayayci/xdrcheck/go/internal/hunt/find"
)

func init() {
	register("find", "example transactions for a token, class, value tag, CAP, assumption or operation type", func(args []string) int {
		return findMain(args, os.Stdout, os.Stderr)
	})
}

func findMain(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(hunt.Tool+" find", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var q find.Query
	ds := fs.String("dataset", "", "dataset directory (default $"+hunt.EnvName("DATASET")+", else the per-user data directory)")
	corpus := fs.String("corpus", "corpus", "corpus root (for --cap)")
	fs.StringVar(&q.Token, "token", "", "a token, as its text (K|class|path) or its 32-hex id")
	fs.StringVar(&q.Class, "class", "", "every token of a class, K|class (for example V|u64band)")
	fs.StringVar(&q.TokenContains, "token-contains", "", "every token whose text contains this string (kept-ledger index only)")
	fs.StringVar(&q.Tag, "tag", "", "a value tag (for example u64>=2^63); a trailing * matches a prefix")
	fs.IntVar(&q.Cap, "cap", 0, "the corpus examples of a CAP, and the dataset's cap-N set")
	fs.StringVar(&q.Assumption, "assumption", "", "a linter assumption key (for example text-to-db:memo); --list-assumptions shows the mapped keys")
	fs.StringVar(&q.Op, "op", "", "an operation type (for example PATH_PAYMENT_STRICT_SEND)")
	fs.StringVar(&q.Set, "set", "", "a named set of the dataset")
	fs.StringVar(&q.Order, "order", "first", "first, last, rarest (by census occurrences of the matched token) or random")
	fs.IntVar(&q.Limit, "limit", 20, "examples to print")
	fs.Uint64Var(&q.Seed, "seed", 1, "seed of --order random")
	fs.StringVar(&q.Source, "source", "auto", "auto (locate index, else the kept-ledger index), locate or kept")
	format := fs.String("format", "tsv", "tsv, json or ledgers (one ledger per line, for --ledgers @FILE)")
	listA := fs.Bool("list-assumptions", false, "print the assumption keys find can map to ledgers")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *listA {
		as, err := find.Assumptions()
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		for _, a := range as {
			sel := a.Tag
			switch {
			case a.Tag != "":
				sel = "tag " + a.Tag
			case a.Class != "" && a.TokenContains != "":
				sel = "class " + a.Class + " containing " + a.TokenContains
			case a.TokenContains != "":
				sel = "token containing " + a.TokenContains
			case a.Class != "":
				sel = "class " + a.Class
			case a.Op != "":
				sel = "op " + a.Op
			}
			fmt.Fprintf(stdout, "%-28s %-40s %s\n", a.Key, sel, a.Why)
		}
		return 0
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "%s find: unexpected arguments %v\n", hunt.Tool, fs.Args())
		return 2
	}
	src := sourceFlags{dataset: *ds}
	m, err := src.openDataset()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	res, err := find.Run(m, *corpus, q)
	var u *hunt.Unavailable
	if errors.As(err, &u) {
		fmt.Fprintln(stderr, err)
		return 3
	}
	if err != nil {
		fmt.Fprintf(stderr, "%s find: %v\n", hunt.Tool, err)
		return 2
	}
	for _, n := range res.Notes {
		fmt.Fprintln(stderr, "note: "+n)
	}
	fmt.Fprintf(stderr, "%d transactions matched (%s); %d shown, order %s\n", res.Matched, res.Source, len(res.Hits), q.Order)
	switch *format {
	case "json":
		enc := json.NewEncoder(stdout)
		enc.SetEscapeHTML(false)
		for _, h := range res.Hits {
			enc.Encode(h)
		}
	case "ledgers":
		seen := map[uint32]bool{}
		for _, h := range res.Hits {
			if !seen[h.Ledger] {
				seen[h.Ledger] = true
				fmt.Fprintln(stdout, h.Ledger)
			}
		}
	default:
		fmt.Fprintln(stdout, "ledger\ttx\tmatch\toccurrences\tsource")
		for _, h := range res.Hits {
			tx := ""
			if h.Tx != nil {
				tx = fmt.Sprint(*h.Tx)
			}
			occ := ""
			if h.Occ > 0 {
				occ = fmt.Sprint(h.Occ)
			}
			fmt.Fprintf(stdout, "%d\t%s\t%s\t%s\t%s\n", h.Ledger, tx, strings.ReplaceAll(h.Match, "\t", " "), occ, h.Source)
		}
	}
	if len(res.Hits) == 0 {
		return 1
	}
	return 0
}

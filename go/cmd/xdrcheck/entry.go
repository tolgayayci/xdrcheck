package main

// xdrcheck entry: look at the corpus from the command line. List the entries of a CAP or matching a glob, or show
// one entry: its tags, its variants (network, protocol, ledger, XDR type, blob), the values the manifest expects,
// the readers it is declared to trip, how common its rarest shape is on mainnet, and the commands that replay it
// and run it through the SDKs; --decoded prints one variant's decoded SEP-51 JSON. Read-only, offline.

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/klauspost/compress/zstd"
)

func init() {
	register("entry", "list corpus entries by CAP or glob; show one entry, its expected values, decoded XDR and mainnet prevalence", func(args []string) int {
		return entryMain(args, os.Stdout, os.Stderr)
	})
}

type indexVariant struct {
	Network   string `json:"network"`
	Protocol  int    `json:"protocol"`
	LedgerSeq int64  `json:"ledger_seq"`
	XDRType   string `json:"xdr_type"`
	Validity  string `json:"validity"`
	Source    string `json:"source"`
	Blob      string `json:"blob"`
	SHA256    string `json:"sha256"`
	Bytes     int64  `json:"bytes"`
	Decoded   string `json:"decoded"`
}

type indexEntry struct {
	ID        string         `json:"id"`
	Title     string         `json:"title"`
	Kind      string         `json:"kind"`
	Caps      []int          `json:"caps"`
	Protocol  map[string]any `json:"protocol"`
	Synthetic bool           `json:"synthetic"`
	Validity  string         `json:"validity"`
	Flags     []string       `json:"flags"`
	Sources   []string       `json:"sources"`
	Tier      string         `json:"tier"`
	Manifest  string         `json:"manifest"`
	Variants  []indexVariant `json:"variants"`
}

// key is the variant key reports use: the network, or network@protocol when the entry's variants do not share
// one protocol.
func (e *indexEntry) key(i int) string {
	v := e.Variants[i]
	if v.Network == "" {
		return "none"
	}
	for _, o := range e.Variants {
		if o.Protocol != v.Protocol {
			return fmt.Sprintf("%s@%d", v.Network, v.Protocol)
		}
	}
	return v.Network
}

func entryMain(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("xdrcheck entry", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: xdrcheck entry [--corpus DIR] (--cap N | --list [GLOB])\n"+
			"       xdrcheck entry [--corpus DIR] [--json] [--decoded [VARIANT]] ENTRY\n\n"+
			"List corpus entries by CAP or ID glob ('*' crosses '/'), or show one entry. VARIANT is a variant key\n"+
			"(testnet, pubnet@30, none) or its position from 1; --decoded alone takes the first variant.")
		fs.PrintDefaults()
	}
	corpus := fs.String("corpus", "corpus", "corpus root (the directory holding index.json)")
	capN := fs.Int("cap", 0, "list the entries tagged with this CAP number")
	list := fs.Bool("list", false, "list the entries whose ID matches GLOB (default every entry)")
	asJSON := fs.Bool("json", false, "print the entry's manifest as JSON instead of the summary")
	decoded := fs.String("decoded", "", "print a variant's decoded SEP-51 JSON (the variant key or position; - for the first)")
	// --decoded with no value: Go's flag package needs a value, so a bare --decoded before ENTRY is rewritten.
	args = bareDecoded(args)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "xdrcheck entry: "+format+"\n", a...)
		return 2
	}
	idx, err := readIndex(*corpus)
	if err != nil {
		return fail("%v", err)
	}
	switch {
	case *capN != 0 || *list:
		if fs.NArg() > 1 || (*capN != 0 && fs.NArg() > 0) {
			return fail("--cap takes no entry; --list takes at most one glob")
		}
		glob := "*"
		if fs.NArg() == 1 {
			glob = fs.Arg(0)
		}
		re := globRE(glob)
		n := 0
		for i := range idx {
			e := &idx[i]
			if *capN != 0 && !containsInt(e.Caps, *capN) || !re.MatchString(e.ID) {
				continue
			}
			n++
			fmt.Fprintf(stdout, "%s\t%s\t%s\tp%s\t%s%s\t%s\n", e.ID, e.Kind, capsText(e.Caps), protoText(e.Protocol),
				e.Validity, map[bool]string{true: ",synthetic"}[e.Synthetic], e.Title)
		}
		if n == 0 {
			fmt.Fprintln(stderr, "xdrcheck entry: no entry matches")
			return 1
		}
		fmt.Fprintf(stderr, "%d entries\n", n)
		return 0
	case fs.NArg() != 1:
		fs.Usage()
		return 2
	}
	var e *indexEntry
	for i := range idx {
		if idx[i].ID == fs.Arg(0) {
			e = &idx[i]
		}
	}
	if e == nil {
		var near []string
		for i := range idx {
			if strings.Contains(idx[i].ID, fs.Arg(0)) {
				near = append(near, idx[i].ID)
			}
		}
		if len(near) > 0 && len(near) <= 10 {
			return fail("no entry %s; did you mean: %s", fs.Arg(0), strings.Join(near, ", "))
		}
		return fail("no entry %s (xdrcheck entry --list '*%s*')", fs.Arg(0), fs.Arg(0))
	}
	manifestPath := filepath.Join(*corpus, e.Manifest)
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return fail("%v", err)
	}
	if *decoded != "" {
		return printDecoded(stdout, *corpus, e, *decoded, fail)
	}
	if *asJSON {
		_, _ = stdout.Write(raw)
		return 0
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return fail("%s: %v", manifestPath, err)
	}
	showEntry(stdout, *corpus, e, m, manifestPath)
	return 0
}

func bareDecoded(args []string) []string {
	out := make([]string, 0, len(args)+1)
	for i, a := range args {
		out = append(out, a)
		if a == "--decoded" || a == "-decoded" {
			next := ""
			if i+1 < len(args) {
				next = args[i+1]
			}
			// a bare --decoded is followed by the entry (it has a slash) or nothing
			if next == "" || strings.Contains(next, "/") || strings.HasPrefix(next, "-") {
				out = append(out, "-")
			}
		}
	}
	return out
}

func readIndex(corpus string) ([]indexEntry, error) {
	raw, err := os.ReadFile(filepath.Join(corpus, "index.json"))
	if err != nil {
		return nil, fmt.Errorf("%v (run from the repository root, or pass --corpus)", err)
	}
	var idx struct {
		Entries []indexEntry `json:"entries"`
	}
	if err := json.Unmarshal(raw, &idx); err != nil {
		return nil, fmt.Errorf("%s: %v", filepath.Join(corpus, "index.json"), err)
	}
	return idx.Entries, nil
}

func globRE(glob string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("^")
	for _, r := range glob {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String())
}

func containsInt(xs []int, x int) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func capsText(caps []int) string {
	if len(caps) == 0 {
		return "-"
	}
	s := make([]string, len(caps))
	for i, c := range caps {
		s[i] = fmt.Sprintf("CAP-%04d", c)
	}
	return strings.Join(s, ",")
}

func protoText(p map[string]any) string {
	if v, ok := p["introduced"].(float64); ok {
		return strconv.Itoa(int(v))
	}
	return "?"
}

func showEntry(w io.Writer, corpus string, e *indexEntry, m map[string]any, manifestPath string) {
	fmt.Fprintf(w, "%s\n  %s\n\n", e.ID, e.Title)
	fmt.Fprintf(w, "kind        %s\n", e.Kind)
	fmt.Fprintf(w, "CAPs        %s\n", capsText(e.Caps))
	fmt.Fprintf(w, "protocol    introduced %s\n", protoText(e.Protocol))
	fmt.Fprintf(w, "validity    %s\n", e.Validity)
	fmt.Fprintf(w, "synthetic   %v\n", e.Synthetic)
	fmt.Fprintf(w, "sources     %s\n", strings.Join(e.Sources, ", "))
	if len(e.Flags) > 0 {
		fmt.Fprintf(w, "flags       %s\n", strings.Join(e.Flags, ", "))
	}
	if s, ok := m["shapes"].([]any); ok && len(s) > 0 {
		fmt.Fprintf(w, "shapes      %s\n", joinAny(s))
	}
	fmt.Fprintf(w, "manifest    %s\n", manifestPath)
	if why, ok := m["why"].(string); ok && why != "" {
		fmt.Fprintf(w, "\nwhy\n  %s\n", why)
	}
	if len(e.Variants) > 0 {
		fmt.Fprintln(w, "\nvariants (xdrcheck entry --decoded VARIANT "+e.ID+" prints one decoded)")
		for i, v := range e.Variants {
			fmt.Fprintf(w, "  %d %-12s ledger %-9d %-22s %7d bytes  %s\n", i+1, e.key(i), v.LedgerSeq, v.XDRType, v.Bytes,
				filepath.Join(corpus, v.Blob))
		}
	}
	if ex, ok := m["expect"]; ok {
		fmt.Fprintln(w, "\nexpected (the manifest's expect; every reader must agree with these)")
		writeIndented(w, ex)
	}
	if c, ok := m["conformance"].(map[string]any); ok {
		kd, _ := c["known_divergences"].([]any)
		for _, replay := range []bool{false, true} {
			head := false
			for _, x := range kd {
				d, _ := x.(map[string]any)
				if (d["level"] == "replay") != replay {
					continue
				}
				if !head {
					fmt.Fprintln(w, map[bool]string{false: "\nknown SDK divergences", true: "\nknown indexer divergences"}[replay])
					head = true
				}
				fmt.Fprintf(w, "  %v %v: %v%s\n", d["target"], d["versions"], d["outcome"], findingSuffix(d))
			}
		}
	}
	showPrevalence(w, corpus, e.ID)
	fmt.Fprintln(w, "\nrun it")
	if e.Kind == "ledger" {
		fmt.Fprintf(w, "  xdrcheck replay --adapter bin/baseline --target-version dev --entries '%s'\n", e.ID)
	}
	fmt.Fprintf(w, "  xdrcheck conform run --entries '%s'            # every SDK column of the pr set\n", e.ID)
	fmt.Fprintf(w, "  xdrcheck conform run --columns 'js@17.4.0' --entries '%s'\n", e.ID)
}

func findingSuffix(d map[string]any) string {
	if f, ok := d["finding"].(string); ok && f != "" {
		return " (finding " + f + ")"
	}
	return ""
}

func joinAny(xs []any) string {
	s := make([]string, len(xs))
	for i, x := range xs {
		s[i] = fmt.Sprint(x)
	}
	return strings.Join(s, ", ")
}

func writeIndented(w io.Writer, v any) {
	b, err := json.MarshalIndent(v, "  ", "  ")
	if err != nil {
		return
	}
	fmt.Fprintf(w, "  %s\n", b)
}

// showPrevalence prints how often the entry's rarest shape token occurs on mainnet, from the committed scan
// summary next to the corpus (evidence/mainnet-scan/entry-prevalence.json), when there is one.
func showPrevalence(w io.Writer, corpus, id string) {
	raw, err := os.ReadFile(filepath.Join(corpus, "..", "evidence", "mainnet-scan", "entry-prevalence.json"))
	if err != nil {
		return
	}
	var p struct {
		Entries map[string]struct {
			Never  bool  `json:"never_seen_on_mainnet"`
			Rarest int64 `json:"rarest_occurrences"`
			Walked bool  `json:"walked"`
			Tokens []struct {
				Token string `json:"token"`
				First int64  `json:"first_ledger"`
				Last  int64  `json:"last_ledger"`
				N     int64  `json:"occurrences"`
			} `json:"rarest_tokens"`
		} `json:"entries"`
	}
	if json.Unmarshal(raw, &p) != nil {
		return
	}
	x, ok := p.Entries[id]
	fmt.Fprintln(w, "\non mainnet (evidence/mainnet-scan/entry-prevalence.json)")
	switch {
	case !ok || !x.Walked:
		fmt.Fprintln(w, "  not walked by the scan (no focus transaction or ledger the scan reads)")
	case x.Never:
		fmt.Fprintln(w, "  its rarest shape never occurs on mainnet")
	default:
		fmt.Fprintf(w, "  rarest shape seen %d times\n", x.Rarest)
		for _, t := range x.Tokens {
			fmt.Fprintf(w, "  %s: ledgers %d..%d\n", t.Token, t.First, t.Last)
		}
	}
}

func printDecoded(w io.Writer, corpus string, e *indexEntry, which string, fail func(string, ...any) int) int {
	if len(e.Variants) == 0 {
		return fail("%s has no variants (kind %s): nothing decoded", e.ID, e.Kind)
	}
	i := -1
	if which == "-" {
		i = 0
	} else if n, err := strconv.Atoi(which); err == nil && n >= 1 && n <= len(e.Variants) {
		i = n - 1
	} else {
		var keys []string
		for j := range e.Variants {
			keys = append(keys, e.key(j))
			if e.key(j) == which && i < 0 {
				i = j
			}
		}
		if i < 0 {
			sort.Strings(keys)
			return fail("%s has no variant %q (variants: %s)", e.ID, which, strings.Join(keys, ", "))
		}
	}
	v := e.Variants[i]
	if v.Decoded == "" {
		return fail("%s variant %s has no decoded sidecar (the bytes do not decode: validity %s)", e.ID, e.key(i), v.Validity)
	}
	f, err := os.Open(filepath.Join(corpus, v.Decoded))
	if err != nil {
		return fail("%v", err)
	}
	defer f.Close()
	zr, err := zstd.NewReader(f)
	if err != nil {
		return fail("%v", err)
	}
	defer zr.Close()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, zr); err != nil {
		return fail("%s: %v", v.Decoded, err)
	}
	var out bytes.Buffer
	if err := json.Indent(&out, buf.Bytes(), "", "  "); err != nil {
		if errors.Is(err, io.EOF) {
			return fail("%s: empty", v.Decoded)
		}
		_, _ = w.Write(buf.Bytes())
		return 0
	}
	out.WriteByte('\n')
	_, _ = w.Write(out.Bytes())
	return 0
}

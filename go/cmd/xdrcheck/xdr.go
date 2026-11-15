package main

// xdrcheck xdr: the XDR definitions as data, for keeping the kit in step with upstream (docs/maintenance.md):
//
//	xdrcheck xdr diff [flags] <base> <head>     structural diff of two definition sets
//	xdrcheck xdr ceilings --check|--write       the drivers' enum ceilings against the pinned definitions
//	xdrcheck xdr candidates [flags] <diff.json>…  candidate corpus rows (caps.toml, arms.toml, plan.json) from diffs
//	xdrcheck xdr watch --out DIR [flags]        diff every source of unreleased XDR; log, digests, per-source diffs
//
// An input of diff is a directory of .x files, a definitions JSON file (`.json` or `.json.zst`, as
// rs-stellar-xdr's generator writes it), `pinned` (the stellar-xdr commit pins.toml names) or any git ref of
// stellar-xdr (branch, tag, commit, `refs/pull/N/head`), fetched read-only into a blobless clone under
// $XDRCHECK_CACHE/src.
//
// Exit codes: 0 done (diff: also with differences, unless --exit-code; ceilings --check: no drift); 1 diff
// --exit-code found differences, or ceilings --check found drift; 2 the tool could not run.

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/tolgayayci/xdrcheck/go/internal/pins"
	"github.com/tolgayayci/xdrcheck/go/internal/xdrdef"
)

// vendoredDefinitions is the pinned definitions JSON the corpus tools compile in, relative to the root.
const vendoredDefinitions = "crates/xdrcheck-corpus/data/xdr-definitions-v30.0.0.json.zst"

func init() {
	register("xdr", "diff XDR definition sets, watch upstream, generate driver ceilings and candidate rows", func(args []string) int {
		return xdrMain(args, os.Stdout, os.Stderr)
	})
}

func xdrMain(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprintln(stderr, "usage: xdrcheck xdr diff|ceilings|candidates|watch [flags]")
		return 2
	}
	switch args[0] {
	case "diff":
		return xdrDiff(args[1:], stdout, stderr)
	case "ceilings":
		return xdrCeilings(args[1:], stdout, stderr)
	case "candidates":
		return xdrCandidates(args[1:], stdout, stderr)
	case "watch":
		return xdrWatch(args[1:], stdout, stderr)
	}
	fmt.Fprintf(stderr, "xdrcheck xdr: unknown subcommand %q\n", args[0])
	return 2
}

// parseInterleaved parses flags that may come before, between or after positional arguments.
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

// xdrPins loads pins.toml from the repository root.
func xdrPins() (*pins.Pins, string, error) {
	root, err := repoRoot()
	if err != nil {
		return nil, "", err
	}
	p, err := pins.Load(filepath.Join(root, "pins.toml"))
	return p, root, err
}

func xdrDiff(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("xdrcheck xdr diff", flag.ContinueOnError)
	fs.SetOutput(stderr)
	baseF := fs.String("base-features", "none", "features enabled in the base: none, all, or a comma-separated list")
	headF := fs.String("head-features", "all", "features enabled in the head: none, all, or a comma-separated list")
	roots := fs.String("roots", strings.Join(xdrdef.DefaultRoots, ","), "types whose reachability marks a change as reader-visible")
	repo := fs.String("repo", xdrdef.DefaultRepoURL, "git repository git refs are read from")
	format := fs.String("format", "md", "what to print: md or json")
	jsonOut := fs.String("json", "", "also write the JSON report to this file")
	mdOut := fs.String("md", "", "also write the Markdown report to this file")
	capFlag := fs.String("cap", "", "attribute every change to this CAP (CAP-NNNN), e.g. for a CAP document's own diff")
	exitCode := fs.Bool("exit-code", false, "exit 1 when the sets differ")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: xdrcheck xdr diff [flags] <base> <head>\n\nbase and head: a directory of .x files, a definitions .json(.zst), `pinned`, or a stellar-xdr git ref.")
		fs.PrintDefaults()
	}
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return 2
	}
	if len(pos) != 2 {
		fmt.Fprintln(stderr, "usage: xdrcheck xdr diff [flags] <base> <head>")
		return 2
	}
	pinned := ""
	if p, _, err := xdrPins(); err == nil {
		pinned = p.StellarXDRDefinitions.Commit
	}
	r := xdrdef.NewRepo(*repo, "stellar-xdr")
	base, err := xdrdef.LoadInput(pos[0], r, pinned)
	if err != nil {
		fmt.Fprintf(stderr, "xdrcheck xdr diff: base: %v\n", err)
		return 2
	}
	head, err := xdrdef.LoadInput(pos[1], r, pinned)
	if err != nil {
		fmt.Fprintf(stderr, "xdrcheck xdr diff: head: %v\n", err)
		return 2
	}
	rep, err := xdrdef.DiffInputs(base, head, *baseF, *headF, xdrdef.DiffOptions{Roots: splitList(*roots), CAP: *capFlag})
	if err != nil {
		fmt.Fprintf(stderr, "xdrcheck xdr diff: %v\n", err)
		return 2
	}
	js, _ := json.MarshalIndent(rep, "", "  ")
	js = append(js, '\n')
	var md strings.Builder
	rep.WriteMarkdown(&md, "")
	if *jsonOut != "" {
		if err := os.WriteFile(*jsonOut, js, 0o644); err != nil {
			fmt.Fprintf(stderr, "xdrcheck xdr diff: %v\n", err)
			return 2
		}
	}
	if *mdOut != "" {
		if err := os.WriteFile(*mdOut, []byte(md.String()), 0o644); err != nil {
			fmt.Fprintf(stderr, "xdrcheck xdr diff: %v\n", err)
			return 2
		}
	}
	switch *format {
	case "json":
		stdout.Write(js)
	case "md":
		io.WriteString(stdout, md.String())
	default:
		fmt.Fprintf(stderr, "xdrcheck xdr diff: --format %q: md or json\n", *format)
		return 2
	}
	if *exitCode && !rep.Empty() {
		return 1
	}
	return 0
}

func splitList(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

func xdrCeilings(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("xdrcheck xdr ceilings", flag.ContinueOnError)
	fs.SetOutput(stderr)
	defs := fs.String("defs", "", "the definitions: a .x directory, a definitions .json(.zst) or a stellar-xdr git ref (default: the vendored pinned definitions, "+vendoredDefinitions+")")
	label := fs.String("label", "", "the definitions' label written on each block's BEGIN line (default: stellar-xdr <pinned tag>)")
	dir := fs.String("dir", "drivers", "directory searched for ceiling blocks")
	check := fs.Bool("check", false, "fail (exit 1) when a block differs from the definitions; write nothing")
	write := fs.Bool("write", false, "rewrite every block from the definitions")
	repo := fs.String("repo", xdrdef.DefaultRepoURL, "git repository a git ref is read from")
	if _, err := parseInterleaved(fs, args); err != nil {
		return 2
	}
	if *check == *write {
		fmt.Fprintln(stderr, "xdrcheck xdr ceilings: give exactly one of --check or --write")
		return 2
	}
	p, root, err := xdrPins()
	if err != nil {
		fmt.Fprintf(stderr, "xdrcheck xdr ceilings: %v\n", err)
		return 2
	}
	if *label == "" {
		*label = "stellar-xdr " + p.StellarXDRDefinitions.Tag
	}
	src := *defs
	if src == "" {
		src = filepath.Join(root, vendoredDefinitions)
	}
	in, err := xdrdef.LoadInput(src, xdrdef.NewRepo(*repo, "stellar-xdr"), p.StellarXDRDefinitions.Commit)
	if err != nil {
		fmt.Fprintf(stderr, "xdrcheck xdr ceilings: %v\n", err)
		return 2
	}
	// The pinned definitions as released: no feature enabled.
	set := in.Set.Resolve(map[string]bool{})
	d := *dir
	if !filepath.IsAbs(d) {
		d = filepath.Join(root, d)
	}
	files, err := xdrdef.FindCeilingFiles(d)
	if err != nil {
		fmt.Fprintf(stderr, "xdrcheck xdr ceilings: %v\n", err)
		return 2
	}
	if len(files) == 0 {
		fmt.Fprintf(stderr, "xdrcheck xdr ceilings: no file under %s holds a %q block\n", *dir, xdrdef.CeilingBegin)
		return 2
	}
	drifted := 0
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			fmt.Fprintf(stderr, "xdrcheck xdr ceilings: %v\n", err)
			return 2
		}
		rel, _ := filepath.Rel(root, f)
		out, drift, err := xdrdef.UpdateCeilings(rel, string(b), set, *label)
		if err != nil {
			fmt.Fprintf(stderr, "xdrcheck xdr ceilings: %v\n", err)
			return 2
		}
		for _, x := range drift {
			fmt.Fprintln(stdout, x)
		}
		drifted += len(drift)
		if *write && out != string(b) {
			if err := os.WriteFile(f, []byte(out), 0o644); err != nil {
				fmt.Fprintf(stderr, "xdrcheck xdr ceilings: %v\n", err)
				return 2
			}
		}
	}
	switch {
	case *write:
		fmt.Fprintf(stdout, "xdrcheck xdr ceilings: %d files from %s; %d values changed\n", len(files), *label, drifted)
	case drifted > 0:
		fmt.Fprintf(stdout, "xdrcheck xdr ceilings: %d values differ from %s; run make xdr-ceilings\n", drifted, *label)
		return 1
	default:
		fmt.Fprintf(stdout, "xdrcheck xdr ceilings: %d files agree with %s\n", len(files), *label)
	}
	return 0
}

func xdrCandidates(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("xdrcheck xdr candidates", flag.ContinueOnError)
	fs.SetOutput(stderr)
	corpusDir := fs.String("corpus", "corpus", "corpus directory holding caps.toml, arms.toml and plan.json")
	capsInfo := fs.String("caps-info", "", "CAP preambles as `xdrcheck xdr watch` writes them (caps.json)")
	list := fs.String("from", "", "a file listing diff reports, one per line, relative to its own directory (candidates.txt of a watch run)")
	next := fs.Int("next-protocol", 0, "protocol for rows no CAP names (default: pins.toml max_supported + 1)")
	write := fs.Bool("write", false, "rewrite the three files in place (default: write nothing, list the rows)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: xdrcheck xdr candidates [flags] (--from candidates.txt | <diff.json>...)")
		fs.PrintDefaults()
	}
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return 2
	}
	if *list != "" {
		b, err := os.ReadFile(*list)
		if err != nil {
			fmt.Fprintf(stderr, "xdrcheck xdr candidates: %v\n", err)
			return 2
		}
		for _, l := range strings.Split(string(b), "\n") {
			if l = strings.TrimSpace(l); l != "" {
				pos = append(pos, filepath.Join(filepath.Dir(*list), l))
			}
		}
	}
	if len(pos) == 0 {
		fmt.Fprintln(stderr, "usage: xdrcheck xdr candidates [--corpus DIR] [--caps-info caps.json] [--write] (--from candidates.txt | <diff.json>…)")
		return 2
	}
	in := xdrdef.CandidateInput{CAPs: map[string]xdrdef.CAPInfo{}, NextProtocol: *next}
	if in.NextProtocol == 0 {
		p, _, err := xdrPins()
		if err != nil {
			fmt.Fprintf(stderr, "xdrcheck xdr candidates: %v\n", err)
			return 2
		}
		in.NextProtocol = p.Protocol.MaxSupported + 1
	}
	for _, f := range pos {
		b, err := os.ReadFile(f)
		if err != nil {
			fmt.Fprintf(stderr, "xdrcheck xdr candidates: %v\n", err)
			return 2
		}
		var r xdrdef.Report
		if err := json.Unmarshal(b, &r); err != nil || r.Schema != xdrdef.DiffSchema {
			fmt.Fprintf(stderr, "xdrcheck xdr candidates: %s is not an %s report\n", f, xdrdef.DiffSchema)
			return 2
		}
		in.Diffs = append(in.Diffs, &r)
	}
	if *capsInfo != "" {
		b, err := os.ReadFile(*capsInfo)
		if err == nil {
			err = json.Unmarshal(b, &in.CAPs)
		}
		if err != nil {
			fmt.Fprintf(stderr, "xdrcheck xdr candidates: %s: %v\n", *capsInfo, err)
			return 2
		}
	}
	paths := map[string]*string{"caps.toml": &in.CapsToml, "arms.toml": &in.ArmsToml, "plan.json": &in.PlanJSON}
	for n, dst := range paths {
		b, err := os.ReadFile(filepath.Join(*corpusDir, n))
		if err != nil {
			fmt.Fprintf(stderr, "xdrcheck xdr candidates: %v\n", err)
			return 2
		}
		*dst = string(b)
	}
	out, err := xdrdef.Candidates(in)
	if err != nil {
		fmt.Fprintf(stderr, "xdrcheck xdr candidates: %v\n", err)
		return 2
	}
	for _, a := range out.Added {
		fmt.Fprintln(stdout, a)
	}
	if *write {
		for n, text := range map[string]string{"caps.toml": out.CapsToml, "arms.toml": out.ArmsToml, "plan.json": out.PlanJSON} {
			if err := os.WriteFile(filepath.Join(*corpusDir, n), []byte(text), 0o644); err != nil {
				fmt.Fprintf(stderr, "xdrcheck xdr candidates: %v\n", err)
				return 2
			}
		}
	}
	verb := "would add"
	if *write {
		verb = "added"
	}
	fmt.Fprintf(stdout, "xdrcheck xdr candidates: %s %d rows from %d diff reports\n", verb, len(out.Added), len(in.Diffs))
	return 0
}

func xdrWatch(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("xdrcheck xdr watch", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "", "output directory (required)")
	prev := fs.String("previous", "", "the previous run's watch-log.jsonl, carried over and used to mark what is new")
	standing := fs.String("standing", "lcm_v3", "stellar-xdr branches always reported, comma-separated")
	skip := fs.String("skip", "", "parts not to run, comma-separated: main, branches, prs, caps")
	repo := fs.String("repo", xdrdef.DefaultRepoURL, "the XDR definitions repository")
	slug := fs.String("github-repo", "stellar/stellar-xdr", "the same repository as owner/name, for listing open pull requests")
	protoRepo := fs.String("protocol-repo", "https://github.com/stellar/stellar-protocol.git", "the CAP repository")
	api := fs.String("api", "https://api.github.com", "GitHub API base URL (read-only; GH_TOKEN or GITHUB_TOKEN is sent when set)")
	next := fs.Int("next-protocol", 0, "the next protocol (default: pins.toml max_supported + 1)")
	if _, err := parseInterleaved(fs, args); err != nil {
		return 2
	}
	if *out == "" {
		fmt.Fprintln(stderr, "xdrcheck xdr watch: --out is required")
		return 2
	}
	p, _, err := xdrPins()
	if err != nil {
		fmt.Fprintf(stderr, "xdrcheck xdr watch: %v\n", err)
		return 2
	}
	if *next == 0 {
		*next = p.Protocol.MaxSupported + 1
	}
	skips := map[string]bool{}
	for _, s := range splitList(*skip) {
		if s != "main" && s != "branches" && s != "prs" && s != "caps" {
			fmt.Fprintf(stderr, "xdrcheck xdr watch: --skip %q: main, branches, prs or caps\n", s)
			return 2
		}
		skips[s] = true
	}
	token := os.Getenv("GH_TOKEN")
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}
	cfg := &xdrdef.WatchConfig{
		XDR:      xdrdef.NewRepo(*repo, "stellar-xdr"),
		Protocol: &xdrdef.Repo{URL: *protoRepo, Dir: filepath.Join(xdrdef.CacheDir(), "src", "stellar-protocol-tip.git"), Shallow: true},
		RepoSlug: *slug, API: *api, Token: token,
		Pinned: p.StellarXDRDefinitions.Commit, PinnedLabel: p.StellarXDRDefinitions.Tag,
		NextProtocol: *next, Standing: splitList(*standing), Skip: skips, Out: *out, Previous: *prev,
	}
	res, err := xdrdef.Watch(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "xdrcheck xdr watch: %v\n", err)
		return 2
	}
	blocked := 0
	for _, it := range res.Items {
		mark := ""
		if it.New {
			mark = " (new)"
		}
		detail := ""
		if it.Detail != "" {
			detail = "; " + it.Detail
		}
		fmt.Fprintf(stdout, "%-8s %-8s %-40s %-12s caps %s, %d changes (%d readers), %d new arms%s%s\n", it.Kind, "p"+strconv.Itoa(it.Protocol),
			it.Name, it.Status, orNone(strings.Join(it.CAPs, ",")), it.Changes, it.ReaderChanges, len(it.NewArms), mark, detail)
		if it.Status == "blocked" {
			blocked++
		}
	}
	fmt.Fprintf(stdout, "xdrcheck xdr watch: %d sources, %d blocked; digests for protocol %v in %s\n", len(res.Items), blocked, res.Protocols, *out)
	if blocked == len(res.Items) && blocked > 0 {
		fmt.Fprintln(stderr, "xdrcheck xdr watch: every source was blocked")
		return 2
	}
	return 0
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

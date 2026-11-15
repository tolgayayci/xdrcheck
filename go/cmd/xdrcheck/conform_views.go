package main

// `xdrcheck conform readiness` and `xdrcheck conform scoreboard`: views over a finished run for SDK maintainers and
// reviewers (go/internal/conform/report). Both read matrix.json and write into the report directory; neither
// starts a driver or opens a network connection. The scoreboard reads finding records from the public tree only,
// never from an overlay, and lists only those that are public, filed and carry an upstream URL.

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/tolgayayci/xdrcheck/go/internal/conform"
	conformreport "github.com/tolgayayci/xdrcheck/go/internal/conform/report"
	"github.com/tolgayayci/xdrcheck/go/internal/conform/verdict"
	"github.com/tolgayayci/xdrcheck/go/internal/findings"
	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
	"github.com/tolgayayci/xdrcheck/go/internal/report"
)

// sourceRoot is the repository root (repoRoot), or "" outside a repository.
func sourceRoot() string {
	root, err := repoRoot()
	if err != nil {
		return ""
	}
	return root
}

// pinnedColumns is every column of the repository's sets file (or $XDRCHECK_SETS), the overlay's left out.
func pinnedColumns() ([]conformreport.Pinned, error) {
	root, err := repoRoot()
	if err != nil {
		return nil, err
	}
	path := os.Getenv("XDRCHECK_SETS")
	if path == "" {
		path = filepath.Join(root, "drivers", "sets.toml")
	}
	sets, err := conform.LoadSets(path, root)
	if err != nil {
		return nil, err
	}
	var out []conformreport.Pinned
	for id, c := range sets.Columns {
		out = append(out, conformreport.Pinned{ID: id, SDK: c.SDK, Version: c.Version, Profile: c.Profile, Kind: c.Kind})
	}
	return out, nil
}

func conformReadiness(args []string) int {
	fs := flag.NewFlagSet("xdrcheck conform readiness", flag.ContinueOnError)
	protocol := fs.Int("protocol", 0, "only the entries introduced at this protocol (default every protocol)")
	reportDir := fs.String("report", "", "the run's report directory: read its matrix.json (unless one is named) and write readiness.md and readiness.json into it")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	path := filepath.Join("reports", "conformance", verdict.MatrixFile)
	if *reportDir != "" {
		path = filepath.Join(*reportDir, verdict.MatrixFile)
	}
	switch fs.NArg() {
	case 0:
	case 1:
		path = fs.Arg(0)
	default:
		fmt.Fprintln(os.Stderr, "usage: xdrcheck conform readiness [--protocol N] [--report DIR] [matrix.json]")
		return 2
	}
	if *protocol < 0 {
		fmt.Fprintln(os.Stderr, "xdrcheck conform readiness: --protocol must be a protocol number")
		return 2
	}
	m, err := verdict.ReadMatrix(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "xdrcheck conform readiness: %v\n", err)
		return 2
	}
	pinned, err := pinnedColumns()
	if err != nil {
		fmt.Fprintf(os.Stderr, "xdrcheck conform readiness: %v; showing the matrix's columns only\n", err)
	}
	r := conformreport.BuildReadiness(m, pinned, *protocol)
	if *protocol != 0 {
		n := 0
		for _, g := range r.Groups {
			if g.Kind == "protocol" {
				n = len(g.Entries)
			}
		}
		fmt.Printf("Protocol %d readiness: %d entries introduced at Protocol %d, across %d SDK versions.\n\n", *protocol, n, *protocol, len(r.Rows))
	}
	r.Markdown(os.Stdout)
	if *protocol != 0 {
		// The entries one by one, for the latest column of each SDK line.
		fmt.Printf("\n## Entries introduced at Protocol %d, latest column of each SDK line\n\n", *protocol)
		m.Readiness(*protocol).Markdown(os.Stdout, nil)
	}
	if *reportDir != "" {
		if err := r.Write(*reportDir); err != nil {
			fmt.Fprintf(os.Stderr, "xdrcheck conform readiness: %v\n", err)
			return 2
		}
		fmt.Fprintf(os.Stderr, "xdrcheck conform readiness: wrote %s and %s\n",
			filepath.Join(*reportDir, conformreport.ReadinessMarkdown), filepath.Join(*reportDir, conformreport.ReadinessJSON))
	}
	return 0
}

// repeated is a repeatable string flag.
type repeated []string

func (r *repeated) String() string     { return strings.Join(*r, ",") }
func (r *repeated) Set(v string) error { *r = append(*r, v); return nil }

func conformScoreboard(args []string) int {
	fs := flag.NewFlagSet("xdrcheck conform scoreboard", flag.ContinueOnError)
	reportDir := fs.String("report", "", "directory to write scoreboard.html and scoreboard.json into (required); its matrix.json is read unless --matrix names one")
	matrixPath := fs.String("matrix", "", "the conformance matrix (default <report>/matrix.json; optional when --replay is given)")
	var replays repeated
	fs.Var(&replays, "replay", "an indexer replay report (report.json of xdrcheck replay --report); repeatable")
	findingsDir := fs.String("findings", "", "public finding records directory (default findings/ at the repository root); only public, filed records with an upstream URL are listed")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	fail := func(err error) int {
		fmt.Fprintf(os.Stderr, "xdrcheck conform scoreboard: %v\n", err)
		return 2
	}
	if fs.NArg() > 0 || *reportDir == "" {
		fmt.Fprintln(os.Stderr, "usage: xdrcheck conform scoreboard --report DIR [--matrix FILE] [--replay FILE]… [--findings DIR]")
		return 2
	}
	in := conformreport.ScoreboardInput{}
	mp := *matrixPath
	if mp == "" {
		mp = filepath.Join(*reportDir, verdict.MatrixFile)
		if _, err := os.Stat(mp); err != nil && len(replays) > 0 {
			mp = ""
		}
	}
	if mp != "" {
		m, err := verdict.ReadMatrix(mp)
		if err != nil {
			return fail(err)
		}
		in.Matrix = m
	}
	for _, p := range replays {
		rep, err := report.ReadAll(p)
		if err != nil {
			return fail(fmt.Errorf("%s: %w", p, err))
		}
		in.Replays = append(in.Replays, rep)
	}
	root := sourceRoot()
	if len(replays) > 0 && root != "" {
		// Replay rows carry no flags: read them from the public corpus.
		if c, err := manifest.Load(filepath.Join(root, "corpus"), manifest.Options{SkipBlobCheck: true}); err == nil {
			in.Flags = func(id string) []string {
				if e := c.Entry(id); e != nil {
					return e.Flags
				}
				return nil
			}
		} else {
			fmt.Fprintf(os.Stderr, "xdrcheck conform scoreboard: corpus not read (%v); replay failures show under %s\n", err, conformreport.NoFlag)
		}
	}
	fd := *findingsDir
	if fd == "" && root != "" {
		fd = filepath.Join(root, "findings")
	}
	if fd != "" && root != "" {
		schema, err := findings.LoadSchema(filepath.Join(root, "corpus", "schema", "finding-record.schema.json"))
		if err != nil {
			return fail(err)
		}
		store, err := findings.Load(schema, fd, "") // the public tree only: never an overlay
		if err != nil {
			return fail(err)
		}
		for _, id := range store.IDs() {
			in.Records = append(in.Records, store.Records[id].Record)
		}
	} else {
		fmt.Fprintln(os.Stderr, "xdrcheck conform scoreboard: no repository root; the bugs-found list is empty")
	}
	if err := os.MkdirAll(*reportDir, 0o755); err != nil {
		return fail(err)
	}
	s := conformreport.BuildScoreboard(in)
	if err := s.Write(*reportDir); err != nil {
		return fail(err)
	}
	fmt.Fprintf(os.Stderr, "xdrcheck conform scoreboard: %d implementation(s), %d bug(s) listed; wrote %s\n",
		len(s.Implementations), len(s.Bugs), filepath.Join(*reportDir, conformreport.ScoreboardHTML))
	return 0
}

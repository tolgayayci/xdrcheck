package main

// xdrcheck findings (the process is described in findings/README.md):
//
//	xdrcheck findings check --mode development|acceptance [--pending-ok] [--overlay DIR] <reports-dir>
//	xdrcheck findings new   --from <report> --row <row_id> [--sibling-of ID] [--overlay DIR]
//	xdrcheck findings issue <id> [--overlay DIR]
//	xdrcheck findings list  [--state S] [--target T] [--overlay DIR]
//	xdrcheck findings tally --make TARGET [--overlay DIR] <reports-dir>
//
// Records are findings/<id>/finding.json under the repository root (the nearest directory, from the working
// directory up, that holds pins.toml), validated against corpus/schema/finding-record.schema.json there. With
// --overlay (or XDRCHECK_OVERLAY) the overlay's findings/ is merged over them.
//
// Exit codes: 0 the check passed or the command did what it was asked; 1 the check failed; 2 the tool could
// not run (bad arguments, an unreadable report, a report made with the overlay but checked without it).
//
// No subcommand files, comments on or reports anything: `issue` writes the draft body and prints the command
// that would file it, and never runs it.

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/tolgayayci/xdrcheck/go/internal/conform"
	"github.com/tolgayayci/xdrcheck/go/internal/findings"
	"github.com/tolgayayci/xdrcheck/go/internal/report"
)

func init() {
	register("findings", "check, create and render finding records", func(args []string) int {
		return findingsMain(args, os.Stdout, os.Stderr)
	})
}

func findingsMain(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprintln(stderr, "usage: xdrcheck findings check|new|issue|list|tally [flags]")
		return 2
	}
	switch args[0] {
	case "check":
		return findingsCheck(args[1:], stdout, stderr)
	case "new":
		return findingsNew(args[1:], stdout, stderr)
	case "issue":
		return findingsIssue(args[1:], stdout, stderr)
	case "list":
		return findingsList(args[1:], stdout, stderr)
	case "tally":
		return findingsTally(args[1:], stdout, stderr)
	}
	fmt.Fprintf(stderr, "xdrcheck findings: unknown subcommand %q\n", args[0])
	return 2
}

// repoRoot is the nearest directory, from the working directory up, that holds pins.toml.
func repoRoot() (string, error) {
	d, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(d, "pins.toml")); err == nil {
			return d, nil
		}
		parent := filepath.Dir(d)
		if parent == d {
			return "", errors.New("no pins.toml in the working directory or above it; run from the repository")
		}
		d = parent
	}
}

// findingSchemaPath is the frozen record schema under a corpus directory.
func findingSchemaPath(corpusDir string) string {
	return filepath.Join(corpusDir, "schema", "finding-record.schema.json")
}

// openStore loads the repository's records, with the overlay's merged over them when overlay is set.
func openStore(overlay string) (*findings.Store, string, error) {
	root, err := repoRoot()
	if err != nil {
		return nil, "", err
	}
	schema, err := findings.LoadSchema(findingSchemaPath(filepath.Join(root, "corpus")))
	if err != nil {
		return nil, "", err
	}
	ov := ""
	if overlay != "" {
		if ov, err = overlayFindings(root, overlay); err != nil {
			return nil, "", err
		}
	}
	s, err := findings.Load(schema, filepath.Join(root, "findings"), ov)
	return s, root, err
}

// overlayFindings returns <overlay>/findings and refuses an overlay inside the public working tree.
func overlayFindings(root, overlay string) (string, error) {
	abs, err := filepath.Abs(overlay)
	if err != nil {
		return "", err
	}
	if st, err := os.Stat(abs); err != nil || !st.IsDir() {
		return "", fmt.Errorf("--overlay %s is not a directory", overlay)
	}
	if rel, err := filepath.Rel(root, abs); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("--overlay %s is inside the public working tree; the overlay must live outside it", overlay)
	}
	return filepath.Join(abs, "findings"), nil
}

func overlayFlag(fs *flag.FlagSet) *string {
	return fs.String("overlay", os.Getenv("XDRCHECK_OVERLAY"), "private overlay directory (default $XDRCHECK_OVERLAY)")
}

func findingsCheck(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("xdrcheck findings check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	mode := fs.String("mode", "", "development or acceptance (required)")
	pendingOK := fs.Bool("pending-ok", false, "acceptance mode: exit 0 when the only failure is rows awaiting finding review (findings-linked stays not met; printed, and noted in a GitHub job summary and annotation)")
	overlay := overlayFlag(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "xdrcheck findings check: "+format+"\n", a...)
		return 2
	}
	if *mode != findings.Development && *mode != findings.Acceptance {
		return fail("--mode must be development or acceptance")
	}
	if *pendingOK && *mode != findings.Acceptance {
		return fail("--pending-ok applies to --mode acceptance only")
	}
	if fs.NArg() != 1 {
		return fail("want exactly one reports directory")
	}
	store, root, err := openStore(*overlay)
	if err != nil {
		return fail("%v", err)
	}
	pending, err := findings.LoadPending(root)
	if err != nil {
		return fail("%v", err)
	}
	res, err := checkReportsDir(store, pending, fs.Arg(0), *mode, *overlay != "", privateRows(root), noDriver(root))
	if err != nil {
		return fail("%v", err)
	}
	res.Print(stdout)
	if *pendingOK && res.PendingOnly() {
		notePendingOnly(res.PendingRows, stdout)
		return 0
	}
	if !res.Passed() {
		return 1
	}
	return 0
}

// notePendingOnly states that the acceptance-mode check failed only on rows awaiting finding review (--pending-ok):
// on stdout, and in a GitHub Actions run also as a warning annotation and a line of the job summary.
func notePendingOnly(n int, stdout io.Writer) {
	msg := fmt.Sprintf("findings-linked not met: %s finding review; this blocks a release tag, not main", count(n, "row awaits", "rows await"))
	fmt.Fprintln(stdout, msg)
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		fmt.Fprintf(stdout, "::warning title=findings-linked not met::%s\n", msg)
		if p := os.Getenv("GITHUB_STEP_SUMMARY"); p != "" {
			if f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
				fmt.Fprintf(f, "**%s**\n", msg)
				f.Close()
			}
		}
	}
}

// checkReportsDir runs the check over every report under dir, accepting in development mode the rows that a
// pending list names.
func checkReportsDir(store *findings.Store, pending *findings.Pending, dir, mode string, allowOverlay bool, private func(string) bool, noDriver func(string, string) bool) (*findings.Result, error) {
	paths, err := findings.FindReports(dir)
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no %s files under %s", report.Schema, dir)
	}
	c := findings.NewChecker(store)
	c.AllowOverlay = allowOverlay
	c.Pending = pending
	c.PrivateRow = private
	c.NoDriver = noDriver
	for _, p := range paths {
		if err := c.AddReport(p); err != nil {
			return nil, err
		}
	}
	// A required run's report that CI withheld from the upload (scripts/ci/withhold-pending.py) is counted from
	// its tally (findings.ReportTally), written by the job that still had the report.
	tallies, err := findings.ReadTallies(dir)
	if err != nil {
		return nil, err
	}
	for _, t := range standInTallies(dir, pending, tallies) {
		if err := c.AddTally(t); err != nil {
			return nil, err
		}
	}
	return c.Finish(mode, true), nil
}

// standInTallies returns, in required-run order, the tallies of the required runs whose report is not under dir.
func standInTallies(dir string, pending *findings.Pending, tallies map[string]*findings.ReportTally) []*findings.ReportTally {
	if pending == nil {
		return nil
	}
	var out []*findings.ReportTally
	for _, r := range pending.Required {
		t := tallies[r.Report]
		if t == nil {
			continue
		}
		if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(r.Report))); err == nil {
			continue
		}
		out = append(out, t)
	}
	return out
}

// findingsTally writes <reports-dir>/<target>.tally.json: the tallies of make target's required runs, which a
// findings check reads in place of a report CI withholds from its upload.
func findingsTally(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("xdrcheck findings tally", flag.ContinueOnError)
	fs.SetOutput(stderr)
	target := fs.String("make", "", "the make target whose required runs' reports to tally (required)")
	overlay := overlayFlag(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "xdrcheck findings tally: "+format+"\n", a...)
		return 2
	}
	if *target == "" || fs.NArg() != 1 {
		return fail("want --make TARGET and exactly one reports directory")
	}
	store, root, err := openStore(*overlay)
	if err != nil {
		return fail("%v", err)
	}
	pending, err := findings.LoadPending(root)
	if err != nil {
		return fail("%v", err)
	}
	c := findings.NewChecker(store)
	c.AllowOverlay = *overlay != ""
	c.Pending = pending
	if _, err := c.WriteTallies(fs.Arg(0), *target, stdout); err != nil {
		return fail("%v", err)
	}
	return 0
}

// checkRunFindings applies the development-mode check to one run's report against the records in
// findingsDir (xdrcheck replay --findings). Orphans are not checked: one run does not refer to every record.
func checkRunFindings(reportPath, findingsDir, schemaPath string, w io.Writer) (bool, error) {
	schema, err := findings.LoadSchema(schemaPath)
	if err != nil {
		return false, err
	}
	store, err := findings.Load(schema, findingsDir, "")
	if err != nil {
		return false, err
	}
	c := findings.NewChecker(store)
	if err := c.AddReport(reportPath); err != nil {
		return false, err
	}
	res := c.Finish(findings.Development, false)
	res.Print(w)
	return res.Passed(), nil
}

func findingsNew(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("xdrcheck findings new", flag.ContinueOnError)
	fs.SetOutput(stderr)
	from := fs.String("from", "", "report file (required)")
	rowID := fs.String("row", "", "row_id of the failure row (required)")
	siblingOf := fs.String("sibling-of", "", "finding ID this candidate is a sibling of")
	overlay := overlayFlag(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "xdrcheck findings new: "+format+"\n", a...)
		return 2
	}
	switch {
	case fs.NArg() > 0:
		return fail("unexpected arguments %v", fs.Args())
	case *from == "" || *rowID == "":
		return fail("--from and --row are required")
	case *siblingOf != "" && !findings.IDPattern.MatchString(*siblingOf):
		return fail("--sibling-of %q is not a finding ID", *siblingOf)
	}
	store, root, err := openStore(*overlay)
	if err != nil {
		return fail("%v", err)
	}
	var row *report.Row
	h, _, err := report.ReadFile(*from, func(r *report.Row) error {
		if r.RowID == *rowID {
			row = r
		}
		return nil
	})
	if err != nil {
		return fail("%v", err)
	}
	if row == nil {
		return fail("%s has no row %q", *from, *rowID)
	}
	if h.Mode.Overlay && *overlay == "" {
		return fail("%s was made with the private overlay; its rows become records only in the overlay (--overlay DIR)", *from)
	}
	for _, id := range store.IDs() {
		if ev := store.Records[id].Record.Evidence; ev != nil {
			for _, r := range ev.ReportRows {
				if r == *rowID {
					return fail("row %s is already accounted for by %s", *rowID, id)
				}
			}
		}
	}
	o := findings.NewOptions{Today: time.Now().UTC().Format("2006-01-02"), Overlay: *overlay != ""}
	if row.Target.Column != "" {
		// The column's package ecosystem tells apart packages of one name (the Rust crate and the Python
		// package are both "stellar-xdr"); an overlay's sets file defines the columns only it runs.
		sets, err := conform.LoadSetsWithOverlay(filepath.Join(root, "drivers", "sets.toml"), root, *overlay)
		if err != nil {
			return fail("%v", err)
		}
		c := sets.Columns[row.Target.Column]
		if c == nil {
			return fail("row %s names column %s, which no sets file defines (an overlay column needs --overlay DIR)", *rowID, row.Target.Column)
		}
		o.Ecosystem = findings.RecordEcosystem(c.Ecosystem)
	}
	if abs, err := filepath.Abs(*from); err == nil {
		if rel, err := filepath.Rel(root, abs); err == nil && !strings.HasPrefix(rel, "..") {
			o.Report = filepath.ToSlash(rel)
		}
	}
	if *siblingOf != "" {
		l, ok := store.Records[*siblingOf]
		if !ok {
			return fail("--sibling-of %s: no such record", *siblingOf)
		}
		o.SiblingOf = l.Record
	}
	rec, err := findings.Candidate(store.NextID(o.Overlay), row, o)
	if err != nil {
		return fail("%v", err)
	}
	// When in doubt, embargo: a candidate that may be security-relevant and is not already public upstream is
	// created only in the overlay.
	if rec.SecurityRelevant && !o.Overlay {
		return fail("row %s (%s) may be security-relevant (provisional severity %s) and matches no public upstream item; "+
			"create it in the private overlay with --overlay DIR, a directory outside the public working tree", *rowID, rec.Class, rec.Severity)
	}
	path, err := store.Write(rec, o.Overlay)
	if err != nil {
		return fail("%v", err)
	}
	fmt.Fprintf(stdout, "%s: candidate written to %s\n", rec.ID, displayPath(root, path))
	fmt.Fprintf(stdout, "next: triage for embargo, reproduce independently, search upstream, then add %s to the known divergence or suppression this row matched\n", rec.ID)
	if o.SiblingOf != nil {
		fmt.Fprintf(stdout, "add %s to the siblings of %s\n", rec.ID, o.SiblingOf.ID)
	}
	return 0
}

// displayPath shows a path relative to the repository root when it is inside it.
func displayPath(root, p string) string {
	if rel, err := filepath.Rel(root, p); err == nil && !strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(rel)
	}
	return p
}

func findingsIssue(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("xdrcheck findings issue", flag.ContinueOnError)
	fs.SetOutput(stderr)
	overlay := overlayFlag(fs)
	// The ID may come before or after the flags.
	var id string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		id, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "xdrcheck findings issue: "+format+"\n", a...)
		return 2
	}
	if id == "" && fs.NArg() == 1 {
		id = fs.Arg(0)
	} else if fs.NArg() > 0 {
		return fail("unexpected arguments %v", fs.Args())
	}
	if !findings.IDPattern.MatchString(id) {
		return fail("want one finding ID F-NNNN")
	}
	store, root, err := openStore(*overlay)
	if err != nil {
		return fail("%v", err)
	}
	l, ok := store.Records[id]
	if !ok {
		return fail("%s: no such record", id)
	}
	rec := l.Record
	if rec.Visibility == "embargoed" && !l.Overlay {
		return fail("%s is embargoed but sits in the public tree; move it to the overlay first", id)
	}
	recDir := "findings/" + id
	d, err := findings.RenderIssue(rec, recDir)
	if err != nil {
		return fail("%v", err)
	}
	bodyPath := filepath.Join(l.Dir, d.File)
	if err := os.WriteFile(bodyPath, []byte(d.Body), 0o644); err != nil {
		return fail("%v", err)
	}
	rec.IssueDraft = &findings.IssueDraft{Path: d.File, Kind: d.Kind, DryRunCommand: d.Command}
	if _, err := store.Write(rec, l.Overlay); err != nil {
		return fail("%v", err)
	}
	where := displayPath(root, bodyPath)
	if l.Overlay {
		where = "overlay " + filepath.ToSlash(filepath.Join("findings", id, d.File))
	}
	fmt.Fprintf(stdout, "%s: draft body written to %s (%s)\n", id, where, d.Kind)
	fmt.Fprintln(stdout, "# NOT RUN. Nothing is filed by this tool. After the user approves this exact draft and channel,")
	fmt.Fprintln(stdout, "# a person runs the command below and records the result in the finding record.")
	fmt.Fprintln(stdout, d.Command)
	return 0
}

func findingsList(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("xdrcheck findings list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	state := fs.String("state", "", "only records in this state")
	target := fs.String("target", "", "only records whose project or package contains this text")
	overlay := overlayFlag(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "xdrcheck findings list: unexpected arguments %v\n", fs.Args())
		return 2
	}
	store, _, err := openStore(*overlay)
	if err != nil {
		fmt.Fprintf(stderr, "xdrcheck findings list: %v\n", err)
		return 2
	}
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSTATE\tVISIBILITY\tSEVERITY\tTARGET\tTITLE")
	n := 0
	for _, id := range store.IDs() {
		l := store.Records[id]
		r := l.Record
		if *state != "" && r.State != *state {
			continue
		}
		if t := strings.ToLower(*target); t != "" && !strings.Contains(strings.ToLower(r.Target.Project), t) &&
			!strings.Contains(strings.ToLower(r.Target.Package), t) {
			continue
		}
		vis := r.Visibility
		if l.Overlay {
			vis += " (overlay)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", id, r.State, vis, r.Severity, r.Target.Project, r.Title)
		n++
	}
	tw.Flush()
	fmt.Fprintf(stdout, "%d record(s)\n", n)
	for _, p := range store.Problems {
		fmt.Fprintln(stderr, "warning: "+p)
	}
	return 0
}

// noDriver reports, from drivers/sets.toml, whether no conformance column drives a target's package (the record's
// target.ecosystem and target.package). Nil when the sets file does not load: then no record is exempt from the
// orphan check.
func noDriver(root string) func(ecosystem, pkg string) bool {
	sets, err := conform.LoadSets(filepath.Join(root, "drivers", "sets.toml"), root)
	if err != nil {
		return nil
	}
	return func(ecosystem, pkg string) bool {
		for _, c := range sets.Columns {
			if c.Package == pkg && (c.Ecosystem == "" || ecosystem == "" || sameEcosystem(c.Ecosystem, ecosystem)) {
				return false
			}
		}
		return true
	}
}

// sameEcosystem compares a drivers/sets.toml ecosystem with a finding record's: the sets file names the
// Rust registry "crates.io", records name it "crates".
func sameEcosystem(set, record string) bool {
	norm := func(e string) string {
		if e == "crates.io" {
			return "crates"
		}
		return e
	}
	return norm(set) == norm(record)
}

// privateRows returns a test for conformance report rows that no run of this tree can produce: rows of a
// column drivers/sets.toml does not define (a column only an overlay's sets file adds). It is nil when the
// sets file cannot be read. A conformance row ID is "conform:<entry>:<variant>:<column>:<level>", and the
// column may carry a ":<profile>".
func privateRows(root string) func(string) bool {
	sets, err := conform.LoadSets(filepath.Join(root, "drivers", "sets.toml"), root)
	if err != nil {
		return nil
	}
	return func(rowID string) bool {
		rest, ok := strings.CutPrefix(rowID, "conform:")
		if !ok {
			return false
		}
		i := strings.LastIndex(rest, ":")
		if i < 0 {
			return false
		}
		parts := strings.SplitN(rest[:i], ":", 3)
		return len(parts) == 3 && sets.Columns[parts[2]] == nil
	}
}

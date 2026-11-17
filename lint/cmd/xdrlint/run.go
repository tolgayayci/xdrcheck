package main

// The standalone driver: load packages, run every analyzer with
// golang.org/x/tools/go/analysis/checker, collect the framework's findings
// (suppressed ones included), check the external suppression files, and
// write the outputs.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"golang.org/x/tools/go/analysis/checker"
	"golang.org/x/tools/go/packages"

	"github.com/tolgayayci/xdrcheck/lint/internal/catalogue"
	"github.com/tolgayayci/xdrcheck/lint/internal/framework"
)

// Version of xdrlint, written into report headers.
const Version = "0.1.0"

type options struct {
	profile, config, sarif, report, expect, pending, failOn, overlay, docsBase string
	json                                                                       bool
}

// defaultDocsBase is where the rule pages are, relative to the repository
// root; -docs-base or XDRLINT_DOCS_BASE points diagnostics at a published
// copy instead.
const defaultDocsBase = "lint/docs"

// docsLink returns the page of a rule under base: base/XDR103.md, or base
// with {rule} replaced when base is a template
// (https://example.org/lint/{rule}).
func docsLink(base, id string) string {
	if strings.Contains(base, "{rule}") {
		return strings.ReplaceAll(base, "{rule}", id)
	}
	return strings.TrimSuffix(base, "/") + "/" + id + ".md"
}

func ruleFix(id string) string {
	if r := framework.Default.Rule(id); r != nil {
		return r.Fix
	}
	return ""
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("xdrlint", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var o options
	fs.StringVar(&o.profile, "profile", "", "shipped profile `NAME` or profile file PATH")
	fs.StringVar(&o.config, "config", "", "project configuration `FILE` (default: .xdrlint.yml found from the working directory up to the module root)")
	fs.BoolVar(&o.json, "json", false, "print diagnostics as JSON")
	fs.StringVar(&o.sarif, "sarif", "", "write SARIF 2.1.0 to `FILE`")
	fs.StringVar(&o.report, "report", "", "write every diagnostic, suppressed ones included, as xcc.report/v1 to `FILE`")
	fs.StringVar(&o.expect, "expect", "", "compare (rule, file, function, suppressed) of the reports with the expected list in `FILE`; exit 1 on any difference")
	fs.StringVar(&o.pending, "pending", "", "reports pending finding review, as (rule, file, line) in `FILE` (xdrlint.pending/v1); they are marked pending in -report and do not fail the run")
	fs.StringVar(&o.failOn, "fail-on", "error", "lowest severity that fails the run: error, warning or info")
	fs.StringVar(&o.overlay, "overlay", "", "private overlay `DIR` (loads DIR/xdrlint.yml)")
	docsDefault := defaultDocsBase
	if v := os.Getenv("XDRLINT_DOCS_BASE"); v != "" {
		docsDefault = v
	}
	fs.StringVar(&o.docsBase, "docs-base", docsDefault, "where diagnostics link the rule pages: `BASE`/XDR103.md, or a URL template with {rule} (env XDRLINT_DOCS_BASE)")
	fs.Usage = func() { usage(fs, stderr) }
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	failOn := framework.Severity(o.failOn)
	if !failOn.Valid() {
		fmt.Fprintf(stderr, "xdrlint: -fail-on %q: want error, warning or info\n", o.failOn)
		return 2
	}
	if fs.NArg() == 0 {
		usage(fs, stderr)
		return 2
	}
	start := time.Now()

	wd, _ := os.Getwd()
	cfg, err := framework.Load(framework.LoadOptions{Profile: o.profile, ConfigFile: o.config, DiscoverFrom: wd, OverlayDir: o.overlay})
	if err == nil {
		err = cfg.Validate(framework.Default)
	}
	if err != nil {
		fmt.Fprintf(stderr, "xdrlint: %v\n", err)
		return 2
	}
	framework.SetConfig(cfg)
	var expected []framework.ExpectEntry
	if o.expect != "" {
		if expected, err = framework.LoadExpect(o.expect); err != nil {
			fmt.Fprintf(stderr, "xdrlint: -expect: %v\n", err)
			return 2
		}
	}
	var pending []framework.PendingEntry
	if o.pending != "" {
		if pending, err = framework.LoadPending(o.pending, cfg.TargetVersion); err != nil {
			fmt.Fprintf(stderr, "xdrlint: -pending: %v\n", err)
			return 2
		}
	}

	pkgs, err := packages.Load(&packages.Config{Mode: packages.LoadAllSyntax | packages.NeedModule}, expandTestdata(fs.Args())...)
	if err != nil {
		fmt.Fprintf(stderr, "xdrlint: %v\n", err)
		return 2
	}
	if n := packages.PrintErrors(pkgs); n > 0 {
		fmt.Fprintf(stderr, "xdrlint: %d package loading error(s); no analysis done\n", n)
		return 2
	}
	if len(pkgs) == 0 {
		fmt.Fprintln(stderr, "xdrlint: no packages matched")
		return 2
	}
	var loaded []*types.Package
	for _, p := range pkgs {
		loaded = append(loaded, p.Types)
	}
	lookup := framework.PackageLookup(loaded, cfg.XDRPackageAliases)
	if !framework.LoadsSourcePackage(lookup) {
		// Configured names in packages that are not loaded are skipped, and
		// no rule has a source to follow: exit 0 would claim a clean run.
		fmt.Fprintf(stderr, "xdrlint: warning: no recognised source package is loaded: none of the packages matched, nor anything they import, is %s "+
			"(or its pre-split path, or an xdrpackagealiases path), so no rule can report anything; nothing was analysed\n", catalogue.XDR)
		return 2
	}
	if err := cfg.CheckNames(lookup); err != nil {
		fmt.Fprintf(stderr, "xdrlint: configuration: %v\n", err)
		return 2
	}
	graph, err := checker.Analyze(framework.Analyzers(), pkgs, nil)
	if err != nil {
		fmt.Fprintf(stderr, "xdrlint: %v\n", err)
		return 2
	}

	var findings []framework.Finding
	byPkg := map[string][]jsonDiag{} // package path → diagnostics, for -json
	used := map[string]bool{}
	failed := false
	for _, act := range graph.Roots {
		if act.Err != nil {
			fmt.Fprintf(stderr, "xdrlint: %s: %v\n", act, act.Err)
			failed = true
			continue
		}
		res, ok := act.Result.(*framework.Result)
		if !ok {
			continue
		}
		for k := range res.UsedSuppressions {
			used[k] = true
		}
		findings = append(findings, res.Findings...)
		for _, f := range res.Findings {
			byPkg[act.Package.PkgPath] = append(byPkg[act.Package.PkgPath], newJSONDiag(f))
		}
	}
	if failed {
		return 2
	}
	for _, f := range framework.Default.SuppressionFindings(cfg, used) {
		findings = append(findings, f)
		byPkg["(suppressions)"] = append(byPkg["(suppressions)"], newJSONDiag(f))
	}
	findings = framework.SortFindings(findings)

	if o.json {
		for pkg, diags := range byPkg {
			for i := range diags {
				diags[i].Docs = docsLink(o.docsBase, diags[i].Rule)
				diags[i].Fix = ruleFix(diags[i].Rule)
			}
			byPkg[pkg] = diags
		}
		writeJSON(stdout, byPkg)
	} else {
		for _, f := range findings {
			if !f.Suppressed {
				fmt.Fprintf(stdout, "%s:%d:%d: %s (%s): %s\n", shortPath(f.Position.Filename), f.Position.Line, f.Position.Column, f.Rule, f.Severity, f.Message)
				if fix := ruleFix(f.Rule); fix != "" {
					fmt.Fprintf(stdout, "\tfix: %s\n", fix)
				}
				fmt.Fprintf(stdout, "\tdocs: %s\n", docsLink(o.docsBase, f.Rule))
			}
		}
		if o.expect == "" {
			writeSummary(stderr, findings, pending, failOn)
		}
	}

	if o.sarif != "" {
		if err := writeSARIF(o.sarif, findings, cfg.Enabled); err != nil {
			fmt.Fprintf(stderr, "xdrlint: -sarif: %v\n", err)
			return 2
		}
	}

	if o.report != "" {
		meta := reportMeta(cfg, pkgs, failOn, expected)
		meta.Pending = pending
		meta.Started, meta.Wall = start, time.Since(start)
		rep := framework.BuildReport(meta, findings)
		data, _ := json.MarshalIndent(rep, "", "  ")
		if err := os.WriteFile(o.report, append(data, '\n'), 0o644); err != nil {
			fmt.Fprintf(stderr, "xdrlint: -report: %v\n", err)
			return 2
		}
	}

	if o.expect != "" {
		missing, extra := framework.CompareExpect(expected, findings)
		for _, e := range missing {
			fmt.Fprintf(stderr, "xdrlint: -expect: missing report: %s\n", e)
		}
		for _, e := range extra {
			fmt.Fprintf(stderr, "xdrlint: -expect: unexpected report: %s\n", e)
		}
		if len(missing)+len(extra) > 0 {
			fmt.Fprintf(stderr, "xdrlint: -expect: %d missing, %d unexpected\n", len(missing), len(extra))
			return 1
		}
		return 0
	}
	for _, f := range findings {
		if !f.Suppressed && f.Severity.Rank() >= failOn.Rank() && !framework.IsPending(pending, f) {
			return 1
		}
	}
	return 0
}

func usage(fs *flag.FlagSet, w io.Writer) {
	fmt.Fprintf(w, "usage: xdrlint [flags] <packages>\n       go vet -vettool=$(which xdrlint) <packages>\n\nflags:\n")
	fs.PrintDefaults()
	fmt.Fprintf(w, "\nshipped profiles: %s\n\nrules in this build:\n", strings.Join(framework.ProfileNames(), ", "))
	for _, r := range framework.Default.Rules() {
		opt := ""
		if r.OptIn {
			opt = ", opt-in"
		}
		fmt.Fprintf(w, "  %s (%s%s) %s\n", r.ID, r.Severity, opt, r.Title)
	}
}

// jsonDiag is one diagnostic of the -json tree: the go/analysis fields
// (posn, message) plus the rule metadata.
type jsonDiag struct {
	Posn              string `json:"posn"`
	Message           string `json:"message"`
	Rule              string `json:"rule"`
	Assumption        string `json:"assumption,omitempty"`
	Severity          string `json:"severity"`
	File              string `json:"file"`
	Function          string `json:"function,omitempty"`
	Guide             string `json:"guide,omitempty"`
	Corpus            string `json:"corpus,omitempty"`
	Checklist         string `json:"checklist,omitempty"`
	Suppressed        bool   `json:"suppressed"`
	SuppressionReason string `json:"suppression_reason,omitempty"`
	Fix               string `json:"fix,omitempty"`
	Docs              string `json:"docs,omitempty"`
}

func newJSONDiag(f framework.Finding) jsonDiag {
	d := jsonDiag{
		Posn:       fmt.Sprintf("%s:%d:%d", f.Position.Filename, f.Position.Line, f.Position.Column),
		Message:    fmt.Sprintf("%s (%s): %s", f.Rule, f.Severity, f.Message),
		Rule:       f.Rule,
		Assumption: f.Assumption,
		Severity:   string(f.Severity),
		File:       f.File,
		Function:   f.Function,
		Suppressed: f.Suppressed,
	}
	if r := framework.Default.Rule(f.Rule); r != nil {
		d.Guide, d.Corpus, d.Checklist = r.Guide, r.Corpus, r.Checklist
	}
	if f.Suppression != nil {
		d.SuppressionReason = f.Suppression.Reason
	}
	return d
}

// writeJSON prints {package: {"xdrlint": [diagnostics]}}, the shape of the
// go/analysis -json tree with one analyzer key.
func writeJSON(w io.Writer, byPkg map[string][]jsonDiag) {
	tree := map[string]map[string][]jsonDiag{}
	for pkg, diags := range byPkg {
		tree[pkg] = map[string][]jsonDiag{"xdrlint": diags}
	}
	data, _ := json.MarshalIndent(tree, "", "\t")
	fmt.Fprintf(w, "%s\n", data)
}

func shortPath(p string) string {
	if wd, err := os.Getwd(); err == nil && filepath.IsAbs(p) {
		if rel, err := filepath.Rel(wd, p); err == nil && !strings.HasPrefix(rel, "..") {
			return rel
		}
	}
	return p
}

func reportMeta(cfg *framework.Config, pkgs []*packages.Package, failOn framework.Severity, expected []framework.ExpectEntry) framework.ReportMeta {
	m := framework.ReportMeta{
		ToolVersion:   Version,
		Overlay:       cfg.Overlay,
		Profile:       cfg.Profile,
		TargetName:    cfg.TargetName,
		TargetVersion: cfg.TargetVersion,
		TargetKind:    cfg.TargetKind,
		FailOn:        failOn,
		Expect:        expected,
		Toolchains:    map[string]string{"go": runtime.Version()},
		PinValues:     map[string]string{"go-stellar-sdk": catalogue.SDKVersion},
		Rules:         map[string]framework.Rule{},
	}
	for _, r := range framework.Default.Rules() {
		m.Rules[r.ID] = r
	}
	if cfg.Profile != "" {
		m.Suite = strings.TrimSuffix(filepath.Base(cfg.Profile), filepath.Ext(cfg.Profile))
	}
	// tool.commit is left out: the go command's VCS stamp looks for a .git
	// directory, so a binary built in a nested git worktree carries the
	// enclosing checkout's commit, not its own.
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if d.Path == "golang.org/x/tools" {
				m.PinValues["x-tools"] = d.Version
			}
		}
	}
	var mainMod *packages.Module
	for _, p := range pkgs {
		if p.Module != nil && p.Module.Main {
			mainMod = p.Module
			break
		}
	}
	if m.TargetName == "" && mainMod != nil {
		m.TargetName = mainMod.Path
	}
	if m.TargetVersion == "" && mainMod != nil && mainMod.Dir != "" {
		if out, err := exec.Command("git", "-C", mainMod.Dir, "rev-parse", "HEAD").Output(); err == nil {
			m.TargetVersion = strings.TrimSpace(string(out))
		}
	}
	if m.TargetVersion != "" {
		m.PinValues["target"] = m.TargetVersion
	}
	if data, err := os.ReadFile(pinsFile()); err == nil {
		sum := sha256.Sum256(data)
		m.PinsSHA256 = hex.EncodeToString(sum[:])
	}
	return m
}

// pinsFile is $XDRCHECK_PINS (else $XCC_PINS, its earlier name), else the first pins.toml found from the working
// directory upwards ("" if none).
func pinsFile() string {
	if p := os.Getenv("XDRCHECK_PINS"); p != "" {
		return p
	}
	if p := os.Getenv("XCC_PINS"); p != "" { // the variable's earlier name
		return p
	}
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	for {
		p := filepath.Join(dir, "pins.toml")
		if _, err := os.Stat(p); err == nil {
			return p
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

package findings

// The required run set: the reports an acceptance findings check (findings-linked) must read, fixed in advance rather than
// taken from whatever happens to be under the reports directory. The repository declares it in
// RequiredRunsDir (and, for a tree that keeps one file, RequiredRunsFile) as the make targets of `make
// verify-acceptance` whose reports count; this file expands each
// target into the reports it writes, resolved against pins.toml (the pinned commits) and the linter's
// before/after plan. A run whose report is absent is `missing`, and an acceptance check with a missing run
// fails. The set includes the full-corpus replay at the pinned pipeline commit (`make replay-full`), so the rows
// the pipeline findings rest on are always in a checked report. A tree without the file (a test fixture) has no
// required set, and neither missing runs nor stale pending entries are checked there.
//
// The declaration is split by area: RequiredRunsDir holds one JSON file per area, each with the same shape,
// read in name order after RequiredRunsFile when that exists.
// An area adds its targets in its own file; a target declared twice is refused.
//
// The set also scopes the pending lists: an entry is checked for staleness only against the required runs that
// could hold its rows (same tool, and the same target and version where both name one), and only once all of
// those runs are present; an entry that no required run can hold is stale.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/tolgayayci/xdrcheck/go/internal/pins"
)

// RequiredRunsFile and the files of RequiredRunsDir declare the required run set, relative to the repository
// root, each as
//
//	{"targets": ["verify-corpus", "verify-replay", …]}
const (
	RequiredRunsFile = "findings/required-runs.json"
	RequiredRunsDir  = "findings/required-runs.d"
)

// requiredTargets reads the declared targets in order: RequiredRunsFile, then each RequiredRunsDir/*.json in
// name order. ok is false when the tree declares none at all.
func requiredTargets(root string) (targets []string, ok bool, err error) {
	files := []string{filepath.Join(root, RequiredRunsFile)}
	frags, err := filepath.Glob(filepath.Join(root, RequiredRunsDir, "*.json"))
	if err != nil {
		return nil, false, err
	}
	slices.Sort(frags)
	files = append(files, frags...)
	seen := map[string]string{}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, false, err
		}
		ok = true
		rel, _ := filepath.Rel(root, f)
		rel = filepath.ToSlash(rel)
		var decl struct {
			Targets []string `json:"targets"`
		}
		dec := json.NewDecoder(strings.NewReader(string(data)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&decl); err != nil {
			return nil, false, fmt.Errorf("%s: %v", rel, err)
		}
		if len(decl.Targets) == 0 {
			return nil, false, fmt.Errorf("%s: no targets", rel)
		}
		for _, t := range decl.Targets {
			if prev, dup := seen[t]; dup {
				return nil, false, fmt.Errorf("%s: target %s is already declared in %s", rel, t, prev)
			}
			seen[t] = rel
			targets = append(targets, t)
		}
	}
	return targets, ok, nil
}

// RequiredRun is one run of the required set.
type RequiredRun struct {
	// Report is the run's xcc.report/v1 file, relative to the reports directory, slash-separated.
	Report string
	// Make is the make target that writes it.
	Make string
	// Checks are the acceptance checks whose verdict reads this report. Every run is in findings-linked.
	Checks []string
	// Tool is the rows' tool (replay, conform, lint, corpus); Target and Version the rows' target name and
	// version where the run has a single one ("" when it has several or the rows do not carry it).
	Tool, Target, Version string
}

// Has reports whether the run belongs to check.
func (r RequiredRun) Has(check string) bool { return slices.Contains(r.Checks, check) }

// RunsFor returns the runs of runs that belong to check, in order.
func RunsFor(runs []RequiredRun, check string) []RequiredRun {
	var out []RequiredRun
	for _, r := range runs {
		if r.Has(check) {
			out = append(out, r)
		}
	}
	return out
}

// Report directory and target name of the full-corpus replay (scripts/replay-full.sh writes
// <reports>/replay-full/wallet-backend-<input>/report.json).
const (
	ReplayFullDir       = "replay-full"
	WalletBackendTarget = "stellar/wallet-backend"
)

// Report directory and target name of the stellar-etl replay of the declared divergences
// (scripts/replay-etl-known.sh writes <reports>/replay-etl-known/stellar-etl-<pinned commit>/report.json).
const (
	ReplayETLKnownDir = "replay-etl-known"
	StellarETLTarget  = "stellar/stellar-etl"
)

// ReplayInputs are the inputs every wallet-backend replay of the required set runs on.
var ReplayInputs = []string{"sep54-s3", "rpc"}

// lintPlan holds the before/after commits of the linter's table.
const lintPlan = "lint/expected/wallet-backend/plan.json"

// RequiredRuns returns the required run set of the repository at root, or nil when root declares none.
func RequiredRuns(root string) ([]RequiredRun, error) {
	targets, declared, err := requiredTargets(root)
	if err != nil || !declared {
		return nil, err
	}
	p, err := pins.Load(filepath.Join(root, "pins.toml"))
	if err != nil {
		return nil, err
	}
	var plan struct {
		Commits []string `json:"commits"`
	}
	data, err := os.ReadFile(filepath.Join(root, lintPlan))
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &plan); err != nil {
		return nil, fmt.Errorf("%s: %v", lintPlan, err)
	}
	var out []RequiredRun
	for _, t := range targets {
		runs, err := targetRuns(t, p, plan.Commits)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", RequiredRunsDir, err)
		}
		out = append(out, runs...)
	}
	return out, nil
}

// targetRuns expands one make target into the reports it writes.
func targetRuns(target string, p *pins.Pins, lintCommits []string) ([]RequiredRun, error) {
	wb, etl := p.Pipelines.WalletBackend, p.Pipelines.StellarETL
	var out []RequiredRun
	add := func(report, tool, name, version string, checks ...string) {
		out = append(out, RequiredRun{Report: report, Make: target, Checks: append(checks, "findings-linked"), Tool: tool, Target: name, Version: version})
	}
	short := func(c string) string { return c[:min(12, len(c))] }
	switch target {
	case "verify-corpus":
		add("corpus-verify.json", "corpus", "", "", "roundtrip", "golden-agreement")
		add("corpus-verify-ag4.json", "corpus", "", "", "golden-agreement")
	case "verify-replay": // scripts/verify-replay.sh: every acceptance pair, then the current commit, on each input
		for _, a := range wb.Acceptance {
			for _, c := range []string{a.Prefix, a.Fixed} {
				for _, in := range ReplayInputs {
					add(path.Join("replay-regression", short(c)+"-"+a.Bug+"-"+in, "report.json"), "replay", WalletBackendTarget, c, "replay-regression")
				}
			}
		}
		for _, in := range ReplayInputs {
			add(path.Join("replay-regression", short(wb.Current)+"-all-"+in, "report.json"), "replay", WalletBackendTarget, wb.Current, "replay-regression")
		}
	case "verify-conformance":
		add("conformance/report.json", "conform", "", "", "sdk-regression")
	case "verify-conformance-public":
		add("conformance-public/report.json", "conform", "", "")
	case "lint-wallet-backend":
		add(path.Join("lint-wallet-backend", wb.Current+".json"), "lint", "", wb.Current, "lint-current")
	case "lint-before-after":
		for _, c := range lintCommits {
			add(path.Join("lint-before-after", c+".json"), "lint", "", c, "lint-current")
		}
	case "lint-stellar-etl":
		add(path.Join("lint-stellar-etl", etl.Commit+".json"), "lint", "", etl.Commit)
	case "replay-etl-known": // scripts/replay-etl-known.sh: the declared stellar-etl divergences at the pinned commit
		add(path.Join(ReplayETLKnownDir, "stellar-etl-"+etl.Commit, "report.json"), "replay", StellarETLTarget, etl.Commit)
	case "replay-full":
		for _, in := range ReplayInputs {
			add(path.Join(ReplayFullDir, "wallet-backend-"+in, "report.json"), "replay", WalletBackendTarget, wb.Current)
		}
	default:
		return nil, fmt.Errorf("target %q writes no report the required set knows", target)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("target %q expands to no report", target)
	}
	return out, nil
}

// runFor returns the index of the required run a report path is, or -1. A path is a run when it ends with the
// run's report path at a directory boundary (the reports directory itself is not known here).
func runFor(runs []RequiredRun, p string) int {
	p = filepath.ToSlash(filepath.Clean(p))
	for i, r := range runs {
		if p == r.Report || strings.HasSuffix(p, "/"+r.Report) {
			return i
		}
	}
	return -1
}

// inScope reports whether a pending entry's rows could come from run r: the same tool, and the same target and
// version wherever both name one.
func inScope(e PendingEntry, r RequiredRun) bool {
	same := func(a, b string) bool { return a == "" || b == "" || a == b }
	return same(e.tool(), r.Tool) && same(e["target"], r.Target) && same(e["version"], r.Version)
}

// tool is the entry's tool: named, or implied by the keys only one tool's rows carry.
func (e PendingEntry) tool() string {
	switch {
	case e["tool"] != "":
		return e["tool"]
	case e["rule"] != "" || e["file"] != "" || e["line"] != "" || e["function"] != "":
		return "lint"
	case e["column"] != "" || e["level"] != "":
		return "conform"
	}
	return ""
}

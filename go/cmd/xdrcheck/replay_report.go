package main

// REPORT.md of `xdrcheck replay --report DIR`: the failures first — for each failing or unexpected row the entry, its
// CAPs, what the corpus expected and what the indexer held (from the row's evidence), and the command that
// replays that entry alone — then the counts. It is rendered from report.json after the run, so it shows exactly
// the rows the report holds.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/tolgayayci/xdrcheck/go/adapterkit"
	"github.com/tolgayayci/xdrcheck/go/internal/match"
	"github.com/tolgayayci/xdrcheck/go/internal/replay/run"
	"github.com/tolgayayci/xdrcheck/go/internal/report"
)

// reproArgs are the run's own arguments that a repro command repeats.
type reproArgs struct {
	prog, adapter, targetVersion, corpus, input, pins, overlay string
}

// detailedFailures is how many failures REPORT.md shows in full; the rest are listed one line each.
const detailedFailures = 100

// factsShown is how many failing facts each failure shows.
const factsShown = 3

// classMeaning says in plain words what a result means.
var classMeaning = map[string]string{
	"mishandled·wrong_value": "the indexer holds a value that differs from what the ledger says",
	"mishandled·crash":       "the indexer crashed on this ledger",
	"mishandled·hang":        "the indexer stopped making progress on this ledger and was still running at the deadline",
	"mishandled·halt":        "the indexer stopped on this ledger (an error exit, or a refusal that is not a declared, confirmed gate)",
	"dropped·silent":         "the indexer went past this ledger without an error but holds nothing for it, or for the transaction under test, or counted fewer items than the ledger has",
	"dropped·partial":        "the indexer holds the transaction but a fact the ledger shows is missing",
	"dropped·refused":        "the indexer refused the ledger at a gate it declares (a safe stop)",
	"harness_fault":          "the harness or the adapter failed; this says nothing about the indexer",
	"not_reached":            "the indexer stopped at an earlier ledger of the same unit",
	"flaky":                  "repeated runs of the same unit gave different results",
}

// plainNotes rewords the classifier's notes that use the harness's own terms.
var plainNotes = map[string]string{
	"the focus transaction is absent":           "the transaction under test is absent from what the indexer holds",
	"the ledger is absent from the observation": "the indexer holds nothing for this ledger",
	"delivery_not_observed":                     "the input is a plain directory, so the harness cannot see which ledgers the indexer read",
}

// listed reports whether a row belongs in the Failures section: a failure (mishandled, dropped silently or
// partly) or any result other than the one the corpus expects.
func listed(r *report.Row) bool {
	return r.Replay != nil && (r.Failure || r.Expectation != "expected")
}

// failureOrder puts unexpected rows first, then rows already found and awaiting review, then known issues.
func failureOrder(r *report.Row) int {
	switch r.Expectation {
	case "unexpected":
		return 0
	case report.ExpectationPending:
		return 1
	}
	return 2
}

// writeReportMD renders REPORT.md from dir/report.json.
func writeReportMD(dir string, res *run.Result, ra reproArgs) error {
	var rows []*report.Row
	_, sum, err := report.ReadFile(filepath.Join(dir, "report.json"), func(r *report.Row) error {
		if listed(r) {
			rows = append(rows, r)
		}
		return nil
	})
	if err != nil {
		return err
	}
	sort.SliceStable(rows, func(i, j int) bool { return failureOrder(rows[i]) < failureOrder(rows[j]) })

	var b strings.Builder
	fmt.Fprintf(&b, "# Replay report\n\nTarget: `%s` at `%s` (%s). Input: `%s`.\n\n", res.Target.Name, res.Target.Version, res.Target.Kind, res.Input)
	if d := res.Describe; d != nil {
		env, _ := json.Marshal(d.Envelope)
		fmt.Fprintf(&b, "Adapter: `%s %s`. Declared envelope: `%s`.\n\n", d.Adapter.Name, d.Adapter.Version, env)
	}

	unexpected := 0
	for _, r := range rows {
		if r.Expectation == "unexpected" {
			unexpected++
		}
	}
	b.WriteString("## Failures\n\n")
	if len(rows) == 0 {
		b.WriteString("None: every entry gave the result the corpus expects.\n\n")
	} else {
		fmt.Fprintf(&b, "%d entr%s did not pass; %d of them %s not the result the corpus expects. Each one below says what the "+
			"ledger holds and what the indexer held, and gives the command that replays that entry alone (add "+
			"`--report DIR` to get this page for it).\n\n", len(rows), plural(len(rows), "y", "ies"), unexpected, plural(unexpected, "is", "are"))
		for i, r := range rows {
			if i == detailedFailures {
				fmt.Fprintf(&b, "### %d more\n\n", len(rows)-detailedFailures)
			}
			if i >= detailedFailures {
				fmt.Fprintf(&b, "- `%s` (%s): %s, %s — `%s`\n", r.Entry, r.Variant, report.ResultKey(r), statusWords(r), reproCommand(r, ra))
				continue
			}
			writeFailure(&b, r, ra)
		}
		b.WriteString("\n")
	}

	b.WriteString("## Counts\n\n")
	head := map[string]int{}
	side := map[string]int{}
	for k, n := range res.ByResult {
		class, _, _ := strings.Cut(k, "·")
		switch class {
		case "pass", "mishandled", "dropped":
			head[class] += n
		default:
			side[class] += n
		}
	}
	fmt.Fprintf(&b, "| pass | mishandled | dropped |\n|---|---|---|\n| %d | %d | %d |\n\n", head["pass"], head["mishandled"], head["dropped"])
	fmt.Fprintf(&b, "Entries that produced no result about the indexer: not applicable %d, not reached %d, harness fault %d, flaky %d.\n\n",
		side["not_applicable"], side["not_reached"], side["harness_fault"], side["flaky"])
	fmt.Fprintf(&b, "Results other than the expected one: %d. Rows: %d.", res.Unexpected, res.Rows)
	if sum != nil && sum.FailuresWithoutFinding > 0 {
		fmt.Fprintf(&b, " Failures not linked to a known issue: %d.", sum.FailuresWithoutFinding)
	}
	b.WriteString(" Every row with its full evidence: `report.json`.\n")
	return os.WriteFile(filepath.Join(dir, "REPORT.md"), []byte(b.String()), 0o644)
}

// writeFailure writes one failure in full.
func writeFailure(b *strings.Builder, r *report.Row, ra reproArgs) {
	key := report.ResultKey(r)
	fmt.Fprintf(b, "### `%s` (%s): %s\n\n", r.Entry, r.Variant, key)
	if m := classMeaning[key]; m != "" {
		fmt.Fprintf(b, "%s.\n\n", upperFirst(m))
	}
	var caps []string
	for _, c := range r.Caps {
		caps = append(caps, fmt.Sprintf("CAP-%04d", c))
	}
	if len(caps) > 0 {
		fmt.Fprintf(b, "- CAPs: %s\n", strings.Join(caps, ", "))
	}
	if rg := r.Replay.Range; rg != nil && rg.Start == rg.End {
		fmt.Fprintf(b, "- Ledger: %d (%s unit)\n", rg.Start, r.Replay.Unit)
	} else if rg != nil {
		fmt.Fprintf(b, "- Ledgers: %d–%d (%s unit)\n", rg.Start, rg.End, r.Replay.Unit)
	}
	want := "pass"
	if r.Expected != nil && r.Expected.Result != "" {
		want = r.Expected.Result
	}
	fmt.Fprintf(b, "- Expected `%s`, got `%s`: %s\n", want, key, statusWords(r))
	for _, line := range evidenceLines(r.Evidence) {
		fmt.Fprintf(b, "- %s\n", line)
	}
	for _, n := range r.Notes {
		if strings.HasPrefix(n, "outside every declared range") {
			continue // the Expected line above says it
		}
		if plain, ok := plainNotes[n]; ok {
			n = plain
		}
		fmt.Fprintf(b, "- %s\n", upperFirst(n))
	}
	fmt.Fprintf(b, "- Reproduce:\n\n  ```sh\n  %s\n  ```\n\n", reproCommand(r, ra))
}

// statusWords says how the row stands against what the corpus expects.
func statusWords(r *report.Row) string {
	switch {
	case r.Expectation == "unexpected":
		return "unexpected"
	case r.Expectation == report.ExpectationPending:
		return "already found by an earlier run and awaiting review (not counted as unexpected)"
	case r.KnownDivergence != nil:
		s := "a known issue (" + r.KnownDivergence.Reference
		if r.Finding != nil {
			s += ", finding " + *r.Finding
		}
		return s + "), as expected"
	}
	return "as expected"
}

// rowEvidence is the part of a replay row's evidence the Failures section reads.
type rowEvidence struct {
	Ingest *adapterkit.IngestResult `json:"ingest"`
	Fault  string                   `json:"fault"`
	Facts  *struct {
		MissingOrWrong []match.Fact  `json:"missing_or_wrong"`
		BeyondCap      int           `json:"beyond_cap"`
		Extras         []match.Extra `json:"extras"`
	} `json:"facts"`
	FullEvidence string `json:"full_evidence"`
}

// evidenceLines turns a row's evidence into a few lines: how the ingest ended when it did not complete, the
// first failing facts with expected and observed values, extras, and where the rest is.
func evidenceLines(raw json.RawMessage) []string {
	var ev rowEvidence
	if len(raw) == 0 || json.Unmarshal(raw, &ev) != nil {
		return nil
	}
	var out []string
	if ev.Fault != "" {
		out = append(out, "Harness: "+ev.Fault)
	}
	if in := ev.Ingest; in != nil && in.Status != adapterkit.StatusCompleted {
		s := "Ingest " + in.Status
		if l, ok := in.Signals.FailingLedger.Get(); ok {
			s += " at ledger " + strconv.FormatInt(l, 10)
		}
		if p, ok := in.Signals.Phase.Get(); ok && p != "" {
			s += " (phase " + p + ")"
		}
		if sig, ok := in.Signals.TermSignal.Get(); ok && sig != "" {
			s += ", signal " + sig
		}
		if t, ok := in.Signals.StderrTail.Get(); ok && strings.TrimSpace(t) != "" {
			s += "; stderr ends: `" + oneLine(t, 200) + "`"
		}
		out = append(out, s)
	}
	if f := ev.Facts; f != nil {
		for i, fact := range f.MissingOrWrong {
			if i == factsShown {
				break
			}
			out = append(out, factLine(fact))
		}
		n := f.BeyondCap
		if len(f.MissingOrWrong) > factsShown {
			n += len(f.MissingOrWrong) - factsShown
		}
		if n > 0 {
			out = append(out, fmt.Sprintf("%d more missing or wrong fact%s in report.json", n, plural(n, "", "s")))
		}
		for _, x := range f.Extras {
			out = append(out, fmt.Sprintf("Extra %s fact (ledger %d, item %d): %s%s", x.Kind, x.Ledger, x.Index, x.Status, reasonSuffix(x.Reason)))
		}
	}
	if ev.FullEvidence != "" {
		out = append(out, "Full evidence: `"+ev.FullEvidence+"`")
	}
	return out
}

func factLine(f match.Fact) string {
	kind := strings.ReplaceAll(f.Kind, "_", " ")
	label := f.Label
	if !strings.HasPrefix(label, kind) {
		label = kind + ": " + label
	}
	s := fmt.Sprintf("%s — %s%s", label, f.Status, reasonSuffix(f.Reason))
	var diffs []string
	for _, d := range f.Diffs {
		diffs = append(diffs, fmt.Sprintf("%s expected `%s`, observed `%s`", d.Field, d.Expected, d.Observed))
	}
	if len(diffs) > 0 {
		s += " (" + strings.Join(diffs, "; ") + ")"
	}
	if len(f.TxHash) >= 8 && !strings.Contains(f.Label, f.TxHash[:8]) {
		s += " [tx " + f.TxHash + "]"
	}
	return s
}

func reasonSuffix(r string) string {
	if r == "" {
		return ""
	}
	return ": " + r
}

// reproCommand is the xdrcheck replay command that runs this entry alone, with the run's own adapter and settings.
func reproCommand(r *report.Row, ra reproArgs) string {
	args := []string{ra.prog, "replay", "--adapter", shellQuote(ra.adapter), "--target-version", shellQuote(ra.targetVersion),
		"--entries", shellQuote(r.Entry)}
	network, _, _ := strings.Cut(r.Variant, "@")
	switch network {
	case "testnet", "pubnet", "core-test":
		args = append(args, "--network", network)
	}
	if in := r.Replay.Input; in != "" {
		args = append(args, "--input", in)
	}
	if u := r.Replay.Unit; u == "chain" || u == "stream" {
		args = append(args, "--unit", u)
	}
	if ra.pins != "" {
		args = append(args, "--pins", shellQuote(ra.pins))
	}
	if ra.overlay != "" {
		args = append(args, "--overlay", shellQuote(ra.overlay))
	}
	if ra.corpus != "" && ra.corpus != "corpus" {
		args = append(args, "--corpus", shellQuote(ra.corpus))
	}
	return strings.Join(args, " ")
}

// shellQuote quotes s for a POSIX shell when it holds anything but plain path characters.
func shellQuote(s string) string {
	plain := s != ""
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-_./:=@,+", c)) {
			plain = false
			break
		}
	}
	if plain {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func oneLine(s string, max int) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndex(s, "\n"); i >= 0 {
		s = s[i+1:]
	}
	s = strings.ReplaceAll(s, "`", "'")
	if len(s) > max {
		s = s[:max] + "…"
	}
	return s
}

func upperFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

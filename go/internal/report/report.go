// Package report writes and reads the shared result format `xcc.report/v1` (corpus/schema/report.schema.json),
// which the replay harness, the conformance runner, the linter and corpus verification all write and which
// `xdrcheck findings check` and `xdrcheck report` read.
//
// The Writer streams: each row is encoded and flushed to the file as soon as it is written, and only the summary
// counters stay in memory. The file it produces is one JSON document with the keys in the order schema, rows,
// header, summary — the header goes last so that the run block (wall time) can be completed at Close. The
// Reader decodes the same document row by row with a callback, in any key order, so memory stays flat for large
// reports too.
//
// Decoding is strict: an unknown field anywhere outside `evidence` is an error.
package report

import (
	"encoding/json"
	"os"
	"regexp"
)

// Schema is the report schema ID.
const Schema = "xcc.report/v1"

// Report is a whole report in memory. Use it only for small reports; large ones are streamed with Writer and
// ReadFile.
type Report struct {
	Schema  string  `json:"schema"`
	Header  Header  `json:"header"`
	Rows    []Row   `json:"rows"`
	Summary Summary `json:"summary"`
}

// Header is the run's metadata.
type Header struct {
	Tool   Tool      `json:"tool"`
	Corpus CorpusRef `json:"corpus"`
	Pins   PinsRef   `json:"pins"`
	Mode   Mode      `json:"mode"`
	Run    *Run      `json:"run,omitempty"`
	// Resumed is set when the run was resumed from an interrupted one; like Run, not part of the comparable body.
	Resumed *Resumed `json:"resumed,omitempty"`
}

// Resumed names the run a resumed run continued, and the rows it carried over from it.
type Resumed struct {
	FromRun     string `json:"from_run"`
	RowsCarried int    `json:"rows_carried"`
}

// Tool names the tool that wrote the report: "xcc replay", "xcc conform", "xdrlint" or "xcc-corpus verify". These
// are the values the frozen report format (xcc.report/v1) enumerates, so they keep the commands' earlier names.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Commit  string `json:"commit,omitempty"`
}

// CorpusRef identifies the corpus the run used.
type CorpusRef struct {
	Version        string `json:"version"`
	ManifestSHA256 string `json:"manifest_sha256"`
	Schema         string `json:"schema,omitempty"`
	Tier           string `json:"tier,omitempty"` // curated, bulk
}

// PinsRef identifies the pins file that drove the run, and the pins that matter for reading the report.
type PinsRef struct {
	FileSHA256 string            `json:"file_sha256"`
	Values     map[string]string `json:"values,omitempty"`
}

// Mode says what was run and whether the private overlay was loaded.
type Mode struct {
	Suite   string `json:"suite"`
	Overlay bool   `json:"overlay"`
	Offline string `json:"offline,omitempty"`
}

// Run is the non-comparable part of the header: two reports are compared without it.
type Run struct {
	ID         string            `json:"id,omitempty"`
	Started    string            `json:"started,omitempty"` // RFC 3339
	WallMS     *float64          `json:"wall_ms,omitempty"`
	Host       string            `json:"host,omitempty"` // empty unless XDRCHECK_REPORT_HOST=1 (RunHost)
	Toolchains map[string]string `json:"toolchains,omitempty"`
	// Timings is the wall time per phase in milliseconds, by phase name.
	Timings map[string]float64 `json:"timings,omitempty"`
}

// RunHost is the value for Run.Host: the machine's hostname when XDRCHECK_REPORT_HOST=1, else empty. Reports are CI
// artefacts and release attachments, so the hostname is left out unless a run asks for it.
func RunHost() string {
	if os.Getenv("XDRCHECK_REPORT_HOST") != "1" {
		return ""
	}
	h, _ := os.Hostname()
	return h
}

// Row is one result. Exactly one of Replay, Conform, Lint and Corpus is set, matching Tool.
type Row struct {
	RowID           string           `json:"row_id"`
	Tool            string           `json:"tool"` // replay, conform, lint, corpus
	Entry           string           `json:"entry,omitempty"`
	Variant         string           `json:"variant,omitempty"`
	Target          Target           `json:"target"`
	Failure         bool             `json:"failure"`
	Expectation     string           `json:"expectation"` // expected, unexpected, pending (ExpectationPending)
	Expected        *Expected        `json:"expected,omitempty"`
	KnownDivergence *DivergenceMatch `json:"known_divergence,omitempty"`
	Finding         *string          `json:"finding,omitempty"`
	Caps            []int            `json:"caps,omitempty"`
	Replay          *ReplayResult    `json:"replay,omitempty"`
	Conform         *ConformResult   `json:"conform,omitempty"`
	Lint            *LintResult      `json:"lint,omitempty"`
	Corpus          *CorpusResult    `json:"corpus,omitempty"`
	Evidence        json.RawMessage  `json:"evidence,omitempty"` // a JSON object; capped by the Writer
	Notes           []string         `json:"notes,omitempty"`
}

// Target is the reader under test.
type Target struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Kind    string `json:"kind"` // sdk, pipeline, core, oracle, selftest, fixture
	Column  string `json:"column,omitempty"`
	Profile string `json:"profile,omitempty"`
}

// Expected says what should have happened and where that comes from.
type Expected struct {
	Source string `json:"source"` // default, known_divergence, suppression, fixture, selftest
	Result string `json:"result,omitempty"`
}

// DivergenceMatch is the manifest's known divergence a row matched.
type DivergenceMatch struct {
	Reference string `json:"reference"`
	Status    string `json:"status"`
	InRange   bool   `json:"in_range"`
	FixedIn   string `json:"fixed_in,omitempty"`
}

// ReplayResult is the replay harness's block: unit, class and qualifier.
type ReplayResult struct {
	Unit      string `json:"unit"`            // single, chain, stream
	Input     string `json:"input,omitempty"` // sep54-dir, sep54-s3, sep54-gcs, rpc
	Range     *Range `json:"range,omitempty"`
	Class     string `json:"class"`               // pass, mishandled, dropped, not_applicable, not_reached, harness_fault, flaky
	Qualifier string `json:"qualifier,omitempty"` // wrong_value, crash, hang, halt | silent, partial, refused
}

// Range is a ledger range, inclusive.
type Range struct {
	Start int64 `json:"start"`
	End   int64 `json:"end"`
}

// ConformResult is the conformance runner's block.
type ConformResult struct {
	Level     string `json:"level"` // L0..L4
	Reference string `json:"reference,omitempty"`
	Outcome   string `json:"outcome"` // ok, diverge, reject, crash, n_a
	Reason    string `json:"reason,omitempty"`
	Verdict   string `json:"verdict"`         // conform, diverge, schema_invalid, roundtrip_changed, roundtrip_refused, accepts_invalid, reject_valid, crash, n_a
	Check     string `json:"check,omitempty"` // conform, known, undeclared, unexpected-conform, known-changed, n_a
}

// LintResult is the linter's block.
type LintResult struct {
	Rule              string   `json:"rule"`
	Severity          string   `json:"severity"` // error, warning, info
	Location          Location `json:"location"`
	Message           string   `json:"message,omitempty"`
	Assumption        string   `json:"assumption,omitempty"` // the assumption key xdrlint names (lint/docs/assumptions.md)
	Suppressed        bool     `json:"suppressed"`
	SuppressionReason string   `json:"suppression_reason,omitempty"`
}

// Location is a source position.
type Location struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	Function string `json:"function,omitempty"`
}

// CorpusResult is corpus verification's block.
type CorpusResult struct {
	Check  string `json:"check"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// Summary holds the counts over all rows.
type Summary struct {
	Rows                   int            `json:"rows"`
	Failures               int            `json:"failures"`
	Unexpected             int            `json:"unexpected"`
	FailuresWithoutFinding int            `json:"failures_without_finding"`
	ByResult               map[string]int `json:"by_result,omitempty"`
}

// ReplayFailure reports whether a replay result is a failure (findings/README.md): class mishandled, or
// dropped with qualifier silent or partial.
func ReplayFailure(class, qualifier string) bool {
	return class == "mishandled" || (class == "dropped" && (qualifier == "silent" || qualifier == "partial"))
}

// ConformFailure reports whether a conformance verdict is a failure.
func ConformFailure(verdict string) bool {
	switch verdict {
	case "diverge", "schema_invalid", "roundtrip_changed", "roundtrip_refused", "accepts_invalid", "reject_valid", "crash":
		return true
	}
	return false
}

// ExpectationPending marks a row that would be unexpected but is named by a committed, description-free pending
// list (findings/README.md): a failure our own runs found that waits on finding review. It is neither expected
// nor counted in summary.unexpected; the acceptance-mode findings check fails on it.
const ExpectationPending = "pending"

// NeedsFinding reports whether a row must carry a finding ID: a failure on a target of kind sdk, pipeline or
// core.
func NeedsFinding(r *Row) bool {
	if !r.Failure {
		return false
	}
	switch r.Target.Kind {
	case "sdk", "pipeline", "core":
		return true
	}
	return false
}

// ResultKey is the row's key in summary.by_result, in the tool's own vocabulary: replay "class·qualifier" (or
// the class alone), conform the check (or the verdict when there is no check), lint "<rule> suppressed" or
// "<rule> reported", corpus "<check> ok" or "<check> failed".
func ResultKey(r *Row) string {
	switch {
	case r.Replay != nil:
		if r.Replay.Qualifier != "" {
			return r.Replay.Class + "·" + r.Replay.Qualifier
		}
		return r.Replay.Class
	case r.Conform != nil:
		if r.Conform.Check != "" {
			return r.Conform.Check
		}
		return r.Conform.Verdict
	case r.Lint != nil:
		if r.Lint.Suppressed {
			return r.Lint.Rule + " suppressed"
		}
		return r.Lint.Rule + " reported"
	case r.Corpus != nil:
		if r.Corpus.OK {
			return r.Corpus.Check + " ok"
		}
		return r.Corpus.Check + " failed"
	}
	return ""
}

// Add counts one row into the summary.
func (s *Summary) Add(r *Row) {
	s.Rows++
	if r.Failure {
		s.Failures++
	}
	if r.Expectation == "unexpected" {
		s.Unexpected++
	}
	if NeedsFinding(r) && r.Finding == nil {
		s.FailuresWithoutFinding++
	}
	if k := ResultKey(r); k != "" {
		if s.ByResult == nil {
			s.ByResult = map[string]int{}
		}
		s.ByResult[k]++
	}
}

var findingRe = regexp.MustCompile(`^F-[0-9]{4}$`)

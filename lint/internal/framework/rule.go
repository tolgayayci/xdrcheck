// Package framework is the part of xdrlint that every rule plugs into.
//
// A rule analyzer is an ordinary golang.org/x/tools/go/analysis analyzer
// built with Register (or Registry.Register). The framework wraps its Run
// function so that every report goes through one place, which
//
//   - drops reports of rules the configuration does not enable,
//   - applies the configured severity,
//   - names the enclosing function and the module-relative file,
//   - applies inline `//xdrlint:ignore` directives and the external
//     suppression files named by the configuration, and
//   - keeps suppressed reports as data (Result) instead of printing them, so
//     that `xdrlint -report` can still write them as rows.
//
// The same analyzers run under the standalone command, `go vet -vettool`,
// analysistest and a golangci-lint plugin. XDR000 (suppression hygiene) is
// itself a framework analyzer; it requires every other registered analyzer so
// that it can see which directives were used.
//
// A rule package registers itself from a package-level variable:
//
//	var XDR201 = framework.Rule{
//		ID: "XDR201", Family: framework.FamilyCaps, Severity: framework.SeverityWarning,
//		Title:  "recursion over a self-referential xdr type with no depth bound",
//		Guide:  "caps", Corpus: "cap-0046/scval-nested-vec-99-in-event", Checklist: "HC-201",
//	}
//
//	var Analyzer = framework.Register(framework.Spec{
//		Name:     "caps",
//		Doc:      "caps reports missing or too-low depth and size bounds (XDR2xx)",
//		Rules:    []framework.Rule{XDR201 /* , XDR202, … */},
//		Requires: []*analysis.Analyzer{buildssa.Analyzer},
//		Run: func(p *framework.Pass) (any, error) {
//			cfg := p.Config() // .xdrlint.yml / profile keys
//			_ = cfg
//			p.Reportf("XDR201", callExpr, "unbounded recursion over %s", "xdr.SorobanAuthorizedInvocation")
//			p.Report(framework.Report{Rule: "XDR201", Pos: pos, Severity: framework.SeverityError, Message: "…; per-level merge is O(n·depth)"})
//			return nil, nil
//		},
//	})
//
// and cmd/xdrlint imports the package for its side effect. Tests run the
// analyzer over fixtures with internal/fixture.Run.
package framework

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Severity of a report. The order is info < warning < error.
type Severity string

const (
	SeverityInfo    Severity = "info"
	SeverityWarning Severity = "warning"
	SeverityError   Severity = "error"
)

// Rank orders severities; an unknown severity ranks below info.
func (s Severity) Rank() int {
	switch s {
	case SeverityInfo:
		return 1
	case SeverityWarning:
		return 2
	case SeverityError:
		return 3
	}
	return 0
}

// Valid reports whether s is one of the three severities.
func (s Severity) Valid() bool { return s.Rank() > 0 }

// Family groups rules by the kind of ingestion mistake they detect.
type Family string

const (
	FamilyHygiene      Family = "XDR0xx" // the tool itself: suppression hygiene
	FamilyUnvalidated  Family = "XDR1xx" // trusting unvalidated fields
	FamilyCaps         Family = "XDR2xx" // missing depth and size caps
	FamilyParticipants Family = "XDR3xx" // participants from the envelope instead of the meta
	FamilyAssumptions  Family = "XDR4xx" // assumptions about the ledger's form, ranges and outcomes
)

// Rule is the metadata of one rule ID. Every report carries it.
type Rule struct {
	ID        string   // XDRnnn
	Family    Family   // must match the ID's hundreds digit
	Title     string   // one line, used in documentation and help
	Severity  Severity // default severity; the configuration may override it
	Guide     string   // guide section anchor, for example "caps"
	Corpus    string   // canonical corpus entry ID that demonstrates the mistake ("" if none)
	Checklist string   // self-audit checklist item, for example "HC-201" ("" for XDR000)
	OptIn     bool     // true for rules outside the default set (XDR105, XDR204)
	Fix       string   // one line on how to fix a report, printed under each diagnostic
	// Assumption is the registered assumption key its reports carry unless a
	// report names a more precise one (see RegisterAssumption).
	Assumption string
}

var ruleIDPattern = regexp.MustCompile(`^XDR[0-9]{3}$`)

func (r Rule) validate() error {
	if !ruleIDPattern.MatchString(r.ID) {
		return fmt.Errorf("rule ID %q does not match XDRnnn", r.ID)
	}
	if want := Family(r.ID[:4] + "xx"); r.Family != want {
		return fmt.Errorf("rule %s: family %q, want %q", r.ID, r.Family, want)
	}
	if !r.Severity.Valid() {
		return fmt.Errorf("rule %s: invalid default severity %q", r.ID, r.Severity)
	}
	if r.Title == "" {
		return fmt.Errorf("rule %s: no title", r.ID)
	}
	if _, ok := LookupAssumption(r.Assumption); !ok {
		return fmt.Errorf("rule %s: assumption %q is not registered", r.ID, r.Assumption)
	}
	return nil
}

// ReservedRuleIDs are the rule IDs of the v1 rule set (lint/docs/README.md).
// The configuration and directives may name a reserved ID before the rule is
// built; an ID that is neither reserved nor registered is an error.
var ReservedRuleIDs = []string{
	"XDR000",
	"XDR101", "XDR102", "XDR103", "XDR105",
	"XDR201", "XDR202", "XDR203", "XDR204", "XDR205", "XDR206", "XDR207",
	"XDR301", "XDR302", "XDR303", "XDR304",
	"XDR401", "XDR402", "XDR403", "XDR404", "XDR405", "XDR406",
}

// DefaultRuleIDs is the default set; XDR105, XDR204 and XDR406 are opt-in.
var DefaultRuleIDs = []string{
	"XDR101", "XDR102", "XDR103",
	"XDR201", "XDR202", "XDR203", "XDR205", "XDR206", "XDR207",
	"XDR301", "XDR302", "XDR303", "XDR304",
	"XDR401", "XDR402", "XDR403", "XDR404", "XDR405",
	"XDR000",
}

func isReserved(id string) bool { return slices.Contains(ReservedRuleIDs, id) }

// XDR000 is the suppression-hygiene rule, provided by the framework itself.
var XDR000 = Rule{
	ID:       "XDR000",
	Family:   FamilyHygiene,
	Title:    "suppression without a reason, naming an unknown rule, or suppressing nothing",
	Severity: SeverityError,
	Guide:    "linter-suppressions",
	Fix:      "give the directive or entry a reason after the rule ID, name a rule that exists, or delete the suppression that matches nothing",

	Assumption: AssumeSuppression,
}

// prefix is the text every diagnostic message starts with: "XDR201 (warning): ".
func prefix(id string, sev Severity) string { return id + " (" + string(sev) + "): " }

// SplitMessage undoes prefix: it returns the rule ID, severity and bare
// message of a diagnostic message written by the framework.
func SplitMessage(msg string) (id string, sev Severity, text string, ok bool) {
	head, text, found := strings.Cut(msg, "): ")
	if !found {
		return "", "", msg, false
	}
	id, s, found := strings.Cut(head, " (")
	if !found || !ruleIDPattern.MatchString(id) || !Severity(s).Valid() {
		return "", "", msg, false
	}
	return id, Severity(s), text, true
}

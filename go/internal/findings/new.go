package findings

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/tolgayayci/xdrcheck/go/internal/report"
)

// project is the upstream repository and ecosystem of a package a report row names, and whether it is an XDR
// library rather than an SDK.
type project struct {
	repo, ecosystem string
	xdrLibrary      bool
}

// knownPackages maps the package names the conformance columns use onto their upstream repositories, per
// package ecosystem: one name can be two packages ("stellar-xdr" is the Rust crate and the Python XDR package).
// The ecosystem key is the record's ecosystem (crates, pypi, ...).
var knownPackages = map[string]map[string]project{
	"@stellar/stellar-sdk": {"npm": {"stellar/js-stellar-sdk", "npm", false}},
	"stellar-xdr": {
		"crates": {"stellar/rs-stellar-xdr", "crates", true},
		"pypi":   {"lightsail-network/py-stellar-xdr", "pypi", true},
	},
	"stellar-sdk":                   {"pypi": {"StellarCN/py-stellar-base", "pypi", false}},
	"network.lightsail:stellar-sdk": {"maven": {"lightsail-network/java-stellar-sdk", "maven", false}},
	"stellar-core":                  {"source": {"stellar/stellar-core", "source", false}},
}

// RecordEcosystem maps a driver's package ecosystem (drivers/sets.toml `ecosystem`: crates.io, pypi, npm, go,
// maven) onto the finding record's ecosystem vocabulary.
func RecordEcosystem(driver string) string {
	if driver == "crates.io" {
		return "crates"
	}
	return driver
}

var (
	repoPattern   = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	githubModule  = regexp.MustCompile(`^github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)`)
	commitPattern = regexp.MustCompile(`^[0-9a-f]{7,40}$`)
	groupInvalid  = regexp.MustCompile(`[^a-z0-9]+`)
)

// UpstreamOf returns the repository (owner/name) and ecosystem for a report row's target name. ecosystem is the
// record ecosystem of the row's column (RecordEcosystem of its sets.toml entry), or "" when unknown; a name
// that is a package in more than one ecosystem needs it.
func UpstreamOf(name, ecosystem string) (repo, eco string, err error) {
	p, err := upstream(name, ecosystem)
	return p.repo, p.ecosystem, err
}

func upstream(name, ecosystem string) (project, error) {
	if byEco, ok := knownPackages[name]; ok {
		if ecosystem != "" {
			if p, ok := byEco[ecosystem]; ok {
				return p, nil
			}
			return project{}, fmt.Errorf("no upstream repository is known for target %q in ecosystem %s", name, ecosystem)
		}
		if len(byEco) == 1 {
			for _, p := range byEco {
				return p, nil
			}
		}
		ecos := make([]string, 0, len(byEco))
		for e := range byEco {
			ecos = append(ecos, e)
		}
		sort.Strings(ecos)
		return project{}, fmt.Errorf("target %q is a package in more than one ecosystem (%s) and the row's column names none",
			name, strings.Join(ecos, ", "))
	}
	if m := githubModule.FindStringSubmatch(name); m != nil {
		return project{repo: m[1], ecosystem: "go"}, nil
	}
	if repoPattern.MatchString(name) {
		return project{repo: name, ecosystem: "source"}, nil
	}
	return project{}, fmt.Errorf("no upstream repository is known for target %q", name)
}

// NewOptions are the inputs of a candidate besides its row.
type NewOptions struct {
	Today     string  // YYYY-MM-DD
	Report    string  // the report's path as it may be written in the record (relative), or ""
	SiblingOf *Record // the record this one is a sibling of, if any
	// Overlay creates the record embargoed (trigger severity-undetermined) for the private overlay.
	Overlay bool
	// Ecosystem is the record ecosystem of the row's conformance column (RecordEcosystem), or "" for a row
	// without a column; it tells apart packages of the same name.
	Ecosystem string
}

// classOf maps a failure row onto the record's class.
func classOf(r *report.Row) (string, error) {
	switch {
	case r.Replay != nil:
		switch r.Replay.Class + "·" + r.Replay.Qualifier {
		case "mishandled·halt":
			return "halt", nil
		case "mishandled·crash":
			return "crash", nil
		case "mishandled·hang":
			return "hang", nil
		case "mishandled·wrong_value":
			return "wrong_value", nil
		case "dropped·silent":
			return "silent_drop", nil
		case "dropped·partial":
			return "partial_drop", nil
		}
	case r.Conform != nil:
		switch r.Conform.Verdict {
		case "diverge":
			return "wrong_value", nil
		case "accepts_invalid":
			return "accepts_invalid", nil
		case "reject_valid":
			return "rejects_valid", nil
		case "crash":
			return "crash", nil
		}
	case r.Lint != nil:
		return "hardening", nil
	}
	return "", fmt.Errorf("row %s: %s is not a result a finding is made from", r.RowID, report.ResultKey(r))
}

// provisionalSeverity is the worst plausible severity for a class (critical: halt, crash, hang or exhaustion;
// high: a silent wrong value or drop; medium: accepting invalid or rejecting valid input; low: hardening). A candidate
// carries it until a reviewer settles the severity; critical and high make the candidate security-relevant
// until then.
func provisionalSeverity(class string) string {
	switch class {
	case "halt", "crash", "hang", "resource_exhaustion":
		return "critical"
	case "wrong_value", "silent_drop", "partial_drop":
		return "high"
	case "accepts_invalid", "rejects_valid", "encode_mismatch":
		return "medium"
	}
	return "low"
}

// PubliclyKnown reports whether a row matched a known divergence that names a public upstream item; such a
// defect is already public and is not embargoed by default.
func PubliclyKnown(r *report.Row) bool {
	return r.KnownDivergence != nil && strings.HasPrefix(r.KnownDivergence.Reference, "https://")
}

// Candidate builds a candidate record with the given ID from a failure row.
func Candidate(id string, r *report.Row, o NewOptions) (*Record, error) {
	if !r.Failure {
		return nil, fmt.Errorf("row %s is not a failure row", r.RowID)
	}
	if !report.NeedsFinding(r) {
		return nil, fmt.Errorf("row %s is on a %s target; only sdk, pipeline and core rows become findings", r.RowID, r.Target.Kind)
	}
	if o.Today == "" {
		return nil, errors.New("no date")
	}
	class, err := classOf(r)
	if err != nil {
		return nil, err
	}
	p, err := upstream(r.Target.Name, o.Ecosystem)
	if err != nil {
		return nil, err
	}
	repo, eco := p.repo, p.ecosystem
	component := r.Target.Kind
	if r.Target.Kind == "sdk" && p.xdrLibrary {
		component = "xdr-library"
	}
	severity := provisionalSeverity(class)
	security := severity == "critical" || severity == "high"
	if PubliclyKnown(r) {
		security = false
	}

	result := report.ResultKey(r)
	rec := &Record{
		Schema: SchemaID,
		ID:     id,
		Title:  title(r, result),
		Target: Target{
			Project:          repo,
			Ecosystem:        eco,
			VersionsAffected: r.Target.Version + " (range not established)",
			VersionsTested:   []string{r.Target.Version},
		},
		Component: component,
		Class:     class,
		Severity:  severity,
		SeverityBasis: "Provisional: the worst plausible severity for the result class, set by xdrcheck findings new. " +
			"Reachability and impact are not yet verified; a reviewer sets the severity.",
		SecurityRelevant: security,
		Visibility:       "public",
		Caps:             r.Caps,
		Entries:          []Entry{entryOf(r, result)},
		Evidence:         &Evidence{ReportRows: []string{r.RowID}},
		State:            "candidate",
		History:          []HistoryItem{{Date: o.Today, State: "candidate", Note: "Created by xdrcheck findings new from report row " + r.RowID + "."}},
	}
	if r.Target.Name != repo {
		rec.Target.Package = r.Target.Name
	}
	if o.Report != "" {
		rec.Evidence.Transcripts = []string{o.Report}
	}
	if r.Lint != nil && commitPattern.MatchString(r.Target.Version) {
		rec.Location = &Location{Commit: r.Target.Version, File: r.Lint.Location.File, Lines: strconv.Itoa(r.Lint.Location.Line), Function: r.Lint.Location.Function}
	}
	if r.KnownDivergence != nil {
		if r.KnownDivergence.FixedIn != "" {
			rec.Target.FixedIn = r.KnownDivergence.FixedIn
		}
		if strings.HasPrefix(r.KnownDivergence.Reference, "https://") {
			rec.Related = []string{r.KnownDivergence.Reference}
		}
	}
	if sib := o.SiblingOf; sib != nil {
		rec.DefectGroup = sib.DefectGroup
		if rec.DefectGroup == "" {
			rec.DefectGroup = "DG-" + strings.Trim(groupInvalid.ReplaceAllString(strings.ToLower(sib.ID), "-"), "-")
		}
		rec.Siblings = []string{sib.ID}
		rec.History[0].Note += " Sibling of " + sib.ID + "."
	}
	if o.Overlay {
		rec.Visibility = "embargoed"
		rec.SecurityRelevant = true
		rec.Embargo = &Embargo{
			Trigger: "severity-undetermined",
			Policy:  "not yet looked up",
			Channel: "not yet decided",
			LiftCondition: "The severity is shown not to warrant an embargo, or the defect is disclosed to its maintainers and " +
				"fixed, or 90 days pass from the report.",
		}
		rec.History = append(rec.History, HistoryItem{Date: o.Today, State: "embargoed", Note: "Severity undetermined; embargoed by default."})
	}
	return rec, nil
}

func title(r *report.Row, result string) string {
	subject := r.Entry
	if subject == "" && r.Lint != nil {
		subject = r.Lint.Location.File
		if r.Lint.Location.Function != "" {
			subject += " " + r.Lint.Location.Function
		}
	}
	t := fmt.Sprintf("%s %s: %s on %s", r.Target.Name, shortVersion(r.Target.Version), result, subject)
	if n := []rune(t); len(n) > 160 {
		t = string(n[:159]) + "…"
	}
	return t
}

func shortVersion(v string) string {
	if commitPattern.MatchString(v) && len(v) > 12 {
		return v[:8]
	}
	return v
}

func entryOf(r *report.Row, result string) Entry {
	e := Entry{ID: r.Entry, Variant: r.Variant, Observed: result, Expected: "pass"}
	if e.ID == "" {
		e.ID = "none"
	}
	switch {
	case r.Replay != nil:
		e.Scope = "replay"
	case r.Conform != nil:
		e.Scope = r.Conform.Level
		e.Expected = "conform"
		if r.Conform.Reason != "" {
			e.Observed += " (" + r.Conform.Reason + ")"
		}
	case r.Lint != nil:
		e.Scope = r.Lint.Rule
		e.Expected = "no " + r.Lint.Rule + " report"
		if r.Lint.Message != "" {
			e.Observed = r.Lint.Rule + ": " + r.Lint.Message
		}
	}
	if r.Expected != nil && r.Expected.Source == "default" && r.Expected.Result != "" {
		e.Expected = r.Expected.Result
	}
	return e
}

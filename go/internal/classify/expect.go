package classify

// What a result should be, from the entry's known divergences (replay-harness.md §9, manifest.md §7): for a
// run against target T at version V, the divergences whose target is T and level is replay and whose range
// holds V. Inside such a range the declared outcome (and qualifier) must appear; outside every range the entry
// must pass. A divergence that was never executed (observed source-reading or reported) is not asserted: inside
// its range any result is accepted as "expected, unconfirmed".

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
)

// Expectation is what the manifest says one entry's result should be for the target under test.
type Expectation struct {
	InRange []*manifest.KnownDivergence // divergences whose range holds the version
	// Unresolved lists ranges nobody could evaluate (an untagged target whose adapter did not answer them).
	Unresolved []string
}

// Source is the report's expected.source.
func (x Expectation) Source() string {
	if len(x.InRange) > 0 {
		return "known_divergence"
	}
	return "default"
}

// Want is the report's expected.result: the declared class·qualifier, or pass.
func (x Expectation) Want() string {
	if len(x.InRange) == 0 {
		return Pass
	}
	var w []string
	for _, d := range x.InRange {
		w = append(w, DeclaredOutcome(d).String())
	}
	return strings.Join(w, " | ")
}

// DeclaredOutcome maps a divergence's outcome and qualifier to the class it declares. A dropped divergence
// without a qualifier accepts any dropped result (its Qualifier is empty).
func DeclaredOutcome(d *manifest.KnownDivergence) Outcome {
	switch d.Outcome {
	case "halt", "crash", "hang", "wrong_value":
		q := d.Qualifier
		if q == "" {
			q = d.Outcome
		}
		return Outcome{Class: Mishandled, Qualifier: q}
	case "dropped":
		return Outcome{Class: Dropped, Qualifier: d.Qualifier}
	}
	return Outcome{Class: "unknown:" + d.Outcome}
}

func confirmed(d *manifest.KnownDivergence) bool { return d.Observed == "executed" }

// ForEntry finds the divergences of an entry for a target. inRange evaluates one `versions` range for the
// version under test; it returns ok false when the range cannot be evaluated.
func ForEntry(e *manifest.Entry, target string, inRange func(versions string) (in, ok bool)) Expectation {
	var x Expectation
	if e.Conformance == nil {
		return x
	}
	for i := range e.Conformance.KnownDivergences {
		d := &e.Conformance.KnownDivergences[i]
		if d.Target != target || d.Level != "replay" {
			continue
		}
		in, ok := inRange(d.Versions)
		switch {
		case !ok:
			x.Unresolved = append(x.Unresolved, d.Versions)
		case in:
			x.InRange = append(x.InRange, d)
		}
	}
	return x
}

// HasReplayDivergence reports whether an entry has any replay divergence for the target (--assert-known
// selection).
func HasReplayDivergence(e *manifest.Entry, target string) bool {
	if e.Conformance == nil {
		return false
	}
	for _, d := range e.Conformance.KnownDivergences {
		if d.Target == target && d.Level == "replay" {
			return true
		}
	}
	return false
}

// Verdict is whether a result is the expected one, and why.
type Verdict struct {
	Expected   bool
	Divergence *manifest.KnownDivergence // the in-range divergence the result matched, if any
	Note       string
}

// Judge decides whether an outcome is what the manifest expects. assertKnown makes side categories other than
// a planned not_applicable unexpected: the entry was asked to be checked and was not.
func Judge(x Expectation, o Outcome, assertKnown bool) Verdict {
	if len(x.Unresolved) > 0 {
		return Verdict{Note: "cannot decide the expected result: the target's adapter did not resolve " + strings.Join(x.Unresolved, ", ")}
	}
	switch o.Class {
	case HarnessFault:
		return Verdict{Note: "harness fault: no result about the indexer"}
	case Flaky:
		return Verdict{Note: "flaky: repeated runs differ"}
	}
	if o.Class == NotApplicable && o.Row == 1 {
		note := "not run: " + firstNote(o)
		if len(x.InRange) > 0 {
			note += "; the declared divergence cannot be checked against this adapter's declared envelope"
		}
		return Verdict{Expected: true, Note: note}
	}
	if len(x.InRange) > 0 {
		allUnconfirmed := true
		for _, d := range x.InRange {
			if !confirmed(d) {
				continue
			}
			allUnconfirmed = false
			w := DeclaredOutcome(d)
			if w.Class == o.Class && (w.Qualifier == "" || w.Qualifier == o.Qualifier) {
				return Verdict{Expected: true, Divergence: d, Note: "known divergence " + d.Reference}
			}
		}
		if allUnconfirmed {
			return Verdict{Expected: true, Divergence: x.InRange[0], Note: "expected, unconfirmed: the divergence was never executed (" + x.InRange[0].Observed + ")"}
		}
		return Verdict{Note: fmt.Sprintf("inside a declared range the result must be %s; got %s", x.Want(), o)}
	}
	switch {
	case o.Class == Pass:
		return Verdict{Expected: true}
	case o.Class == Dropped && o.Qualifier == Refused:
		return Verdict{Expected: true, Note: "expected (declared gate)"}
	case (o.Class == NotApplicable || o.Class == NotReached) && !assertKnown:
		return Verdict{Expected: true, Note: firstNote(o)}
	}
	return Verdict{Note: fmt.Sprintf("outside every declared range the result must be pass; got %s", o)}
}

func firstNote(o Outcome) string {
	if len(o.Notes) > 0 {
		return o.Notes[0]
	}
	return ""
}

// ---- semver ranges for tagged targets ----

// SemverContains evaluates an npm-style range for a tagged version: alternatives separated by "||", each a
// space-separated list of comparators (=, >, >=, <, <=, or a bare version for equality) or a hyphen range
// "A - B". A leading "v" is ignored. ok is false when the range or the version cannot be read.
func SemverContains(rng, version string) (in, ok bool) {
	v, good := parseSemver(version)
	if !good {
		return false, false
	}
	for _, alt := range strings.Split(rng, "||") {
		alt = strings.TrimSpace(alt)
		if a, b, hyphen := strings.Cut(alt, " - "); hyphen {
			lo, ok1 := parseSemver(a)
			hi, ok2 := parseSemver(b)
			if !ok1 || !ok2 {
				return false, false
			}
			if cmpSemver(v, lo) >= 0 && cmpSemver(v, hi) <= 0 {
				return true, true
			}
			continue
		}
		all := true
		for _, c := range strings.Fields(alt) {
			i := strings.IndexFunc(c, func(r rune) bool { return !strings.ContainsRune("<>=", r) })
			if i < 0 {
				return false, false
			}
			op := c[:i]
			w, good := parseSemver(c[i:])
			if !good {
				return false, false
			}
			k := cmpSemver(v, w)
			var hold bool
			switch op {
			case "", "=":
				hold = k == 0
			case ">":
				hold = k > 0
			case ">=":
				hold = k >= 0
			case "<":
				hold = k < 0
			case "<=":
				hold = k <= 0
			default:
				return false, false
			}
			all = all && hold
		}
		if all && alt != "" {
			return true, true
		}
	}
	return false, true
}

type semver struct {
	n   [3]int
	pre string
}

func parseSemver(s string) (semver, bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	s, _, _ = strings.Cut(s, "+")
	core, pre, _ := strings.Cut(s, "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return semver{}, false
	}
	var v semver
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return semver{}, false
		}
		v.n[i] = n
	}
	v.pre = pre
	return v, true
}

func cmpSemver(a, b semver) int {
	for i := range 3 {
		if a.n[i] != b.n[i] {
			if a.n[i] < b.n[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case a.pre == b.pre:
		return 0
	case a.pre == "":
		return 1
	case b.pre == "":
		return -1
	case a.pre < b.pre:
		return -1
	}
	return 1
}

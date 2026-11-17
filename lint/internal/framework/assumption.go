package framework

// Assumptions: every diagnostic names the assumption about the ledger that
// the reported code makes, as a short stable key ("narrowing:u64->int64",
// "meta-version:v4-only"). The key is written into the JSON, SARIF and
// report outputs, so that a tool can map a diagnostic to the ledger inputs
// that violate it (a catalogue query) without parsing the message.
//
// Keys are registered with the input property that would violate them, in
// plain words; lint/docs/assumptions.md is generated from this table. A rule
// declares the key its reports carry by default (Rule.Assumption) and a
// report may name a more precise one (Report.Assumption). Reporting a key that
// is not registered panics: a test that runs the rule finds it.

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
)

// Assumption is one registered key.
type Assumption struct {
	Key       string // family:detail, lower case
	Violation string // the input property that violates it, in plain words
}

var (
	assumptionsMu sync.Mutex
	assumptions   = map[string]Assumption{}
	assumptionRe  = regexp.MustCompile(`^[a-z0-9-]+:[a-z0-9>._-]+$`)
)

// RegisterAssumption adds a key. Registering a malformed key, or one key with
// two different descriptions, panics.
func RegisterAssumption(key, violation string) string {
	assumptionsMu.Lock()
	defer assumptionsMu.Unlock()
	if !assumptionRe.MatchString(key) {
		panic(fmt.Sprintf("framework: assumption key %q is not family:detail in lower case", key))
	}
	if strings.TrimSpace(violation) == "" {
		panic("framework: assumption " + key + " has no violating input")
	}
	if old, ok := assumptions[key]; ok && old.Violation != violation {
		panic("framework: assumption " + key + " registered twice with different descriptions")
	}
	assumptions[key] = Assumption{Key: key, Violation: violation}
	return key
}

// LookupAssumption returns a registered key.
func LookupAssumption(key string) (Assumption, bool) {
	assumptionsMu.Lock()
	defer assumptionsMu.Unlock()
	a, ok := assumptions[key]
	return a, ok
}

// Assumptions returns every registered key, ordered by key.
func Assumptions() []Assumption {
	assumptionsMu.Lock()
	defer assumptionsMu.Unlock()
	var out []Assumption
	for _, a := range assumptions {
		out = append(out, a)
	}
	slices.SortFunc(out, func(a, b Assumption) int { return strings.Compare(a.Key, b.Key) })
	return out
}

// The default keys of the v1 rules and of XDR000.
var (
	AssumeSuppression = RegisterAssumption("suppression:reviewed",
		"none: XDR000 is about the suppression files, not about an input")
)

// NormaliseMessage removes the line numbers a message names ("line 28",
// "events.go:12", "lines 3-9"), so that a baseline entry keyed by its message
// survives code moving within a file.
func NormaliseMessage(msg string) string {
	msg = msgGoLine.ReplaceAllString(msg, "$1")
	msg = msgLines.ReplaceAllString(msg, "lines")
	msg = msgLine.ReplaceAllString(msg, "line")
	return strings.Join(strings.Fields(msg), " ")
}

var (
	msgGoLine = regexp.MustCompile(`\b([A-Za-z0-9_.\-]+\.go):[0-9]+(?::[0-9]+)?`)
	msgLines  = regexp.MustCompile(`\blines [0-9]+(?:[-–][0-9]+)?`)
	msgLine   = regexp.MustCompile(`\bline [0-9]+`)
)

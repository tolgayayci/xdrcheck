package siblings

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// ManualSchema is the schema ID of a manual evidence file.
const ManualSchema = "xcc.manual-evidence/v1"

// Manual is evidence for an SDK the kit has no conformance driver for: what a person observed for some corpus
// entries, by running the SDK by hand or by reading its source. It stands in for that SDK's matrix column and
// is labelled as such in every draft and record made from it; nothing is inferred beyond the cells it states.
//
// File format (JSON; findings/templates/manual-evidence.example.json is a worked example):
//
//	schema             "xcc.manual-evidence/v1"
//	sdk                short family name, used like a column's sdk (for example "dotnet")
//	project            upstream repository, owner/name
//	package            published package name
//	ecosystem          npm, go, crates, pypi, maven, nuget or source
//	version            the version observed
//	versions_affected  optional range text for a record; default "<version> (range not established)"
//	method             "executed" (run by hand) or "source-reading" (not executed)
//	date               YYYY-MM-DD of the observation
//	basis              what was run or read: file, lines and commit, the call made, the result
//	upstream           optional: issue or pull request URLs a person has confirmed describe this same defect
//	cells              [{entry, variant?, level, verdict, observed}]: verdict is what the conformance runner would
//	                   have judged (conform, reject_valid, accepts_invalid, diverge, crash or n_a); observed says
//	                   what was seen or what the source shows, in words
type Manual struct {
	Schema           string       `json:"schema"`
	SDK              string       `json:"sdk"`
	Project          string       `json:"project"`
	Package          string       `json:"package"`
	Ecosystem        string       `json:"ecosystem"`
	Version          string       `json:"version"`
	VersionsAffected string       `json:"versions_affected,omitempty"`
	Method           string       `json:"method"`
	Date             string       `json:"date"`
	Basis            string       `json:"basis"`
	Upstream         []string     `json:"upstream,omitempty"`
	Cells            []ManualCell `json:"cells"`
	Description      string       `json:"description,omitempty"`

	Path string `json:"-"` // where it was read from
}

// ManualCell is one stated outcome.
type ManualCell struct {
	Entry    string `json:"entry"`
	Variant  string `json:"variant,omitempty"`
	Level    string `json:"level"`
	Verdict  string `json:"verdict"`
	Observed string `json:"observed"`
}

// Column is the pseudo column ID the evidence stands in for, <sdk>@<version>.
func (m *Manual) Column() string { return m.SDK + "@" + m.Version }

// Executed reports whether the evidence was observed by running the SDK.
func (m *Manual) Executed() bool { return m.Method == "executed" }

var (
	repoRe   = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	dateRe   = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
	levelRe  = regexp.MustCompile(`^L[0-4]$`)
	sdkRe    = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	verdicts = map[string]bool{"conform": true, "reject_valid": true, "accepts_invalid": true, "diverge": true, "crash": true, "n_a": true}
	ecos     = map[string]bool{"npm": true, "go": true, "crates": true, "pypi": true, "maven": true, "nuget": true, "source": true}
)

// LoadManual reads and checks a manual evidence file.
func LoadManual(path string) (*Manual, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m Manual
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	m.Path = path
	if err := m.Check(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &m, nil
}

// Check validates the evidence.
func (m *Manual) Check() error {
	var bad []string
	need := func(ok bool, msg string) {
		if !ok {
			bad = append(bad, msg)
		}
	}
	need(m.Schema == ManualSchema, "schema must be "+ManualSchema)
	need(sdkRe.MatchString(m.SDK), "sdk must be a short lower-case name")
	need(repoRe.MatchString(m.Project), "project must be owner/name")
	need(m.Package != "", "package is required")
	need(ecos[m.Ecosystem], "ecosystem must be one of npm, go, crates, pypi, maven, nuget, source")
	need(m.Version != "", "version is required")
	need(m.Method == "executed" || m.Method == "source-reading", "method must be executed or source-reading")
	need(dateRe.MatchString(m.Date), "date must be YYYY-MM-DD")
	need(strings.TrimSpace(m.Basis) != "", "basis is required: what was run or read")
	need(len(m.Cells) > 0, "cells must list at least one entry")
	for _, u := range m.Upstream {
		_, _, _, ok := ParseItemURL(u)
		need(ok, fmt.Sprintf("upstream %q is not a GitHub issue or pull request URL", u))
	}
	seen := map[string]bool{}
	for i, c := range m.Cells {
		k := c.Entry + " " + c.Variant + " " + c.Level
		need(c.Entry != "", fmt.Sprintf("cells[%d]: entry is required", i))
		need(levelRe.MatchString(c.Level), fmt.Sprintf("cells[%d]: level must be L0-L4", i))
		need(verdicts[c.Verdict], fmt.Sprintf("cells[%d]: verdict %q is not one of conform, reject_valid, accepts_invalid, diverge, crash, n_a", i, c.Verdict))
		need(strings.TrimSpace(c.Observed) != "", fmt.Sprintf("cells[%d]: observed is required", i))
		need(!seen[k], fmt.Sprintf("cells[%d]: %s is stated twice", i, k))
		seen[k] = true
	}
	if len(bad) > 0 {
		return errors.New(strings.Join(bad, "; "))
	}
	return nil
}

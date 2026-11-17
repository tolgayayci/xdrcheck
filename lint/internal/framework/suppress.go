package framework

// External suppression files, for code that cannot carry an inline directive
// (third-party code under test, such as a pinned wallet-backend commit).
//
// A file is a YAML list. Each entry:
//
//	- rule: XDR201                       # required
//	  file: internal/indexer/processors/contract_deploy.go   # required, module-relative, slash-separated
//	  function: processDeploy            # enclosing declared function (Type.Method for methods)
//	  anchor: "walkInvocation(inv)"      # or: a substring of the reported source line
//	  line: 143                          # and/or: the reported line, for a list frozen against one commit
//	  message: "…"                       # and/or: the report's message, compared without the line numbers it names
//	  reason: "linear, success-gated walk ..."  # required
//	  finding: F-0014                    # finding record ID, copied into the report row
//	  issue: findings/.../draft.md       # upstream issue or draft path
//	  commit: e967ce8b7362b79c277e700e789181d76fbb5967   # the pin it was reviewed against
//	  reviewer: …
//	  date: 2026-11-12
//
// Matching is rule + file + (function, anchor, line or message); every key
// given must match. Function or anchor alone survive line drift and die when
// the function is renamed; adding line (or anchor) narrows an entry to one
// site, so a new report elsewhere in the same function is not accepted with
// it. Message (compared after NormaliseMessage, so the line numbers a message
// names do not count) narrows an entry to one report without a line number:
// rule + file + function + message is the baseline key that survives code
// moving within a file.
// An entry that is malformed (no reason, unknown rule, none of function,
// anchor and line) suppresses nothing and is reported as XDR000; so is an
// entry that matches no report.

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// Suppression is one entry of an external suppression file.
type Suppression struct {
	Rule     string `yaml:"rule"`
	File     string `yaml:"file"`
	Function string `yaml:"function"`
	Anchor   string `yaml:"anchor"`
	At       int    `yaml:"line"`    // the reported line (0: any)
	Message  string `yaml:"message"` // the report's message, compared normalised ("": any)
	Reason   string `yaml:"reason"`
	Finding  string `yaml:"finding"`
	Issue    string `yaml:"issue"`
	Commit   string `yaml:"commit"`
	Reviewer string `yaml:"reviewer"`
	Date     string `yaml:"date"`

	Source  string `yaml:"-"` // display path of the file
	Line    int    `yaml:"-"` // line of the entry in the file
	Problem string `yaml:"-"` // non-empty: the entry is invalid and suppresses nothing
}

// Key identifies the entry across packages: "file:line".
func (s *Suppression) Key() string { return fmt.Sprintf("%s:%d", s.Source, s.Line) }

// SuppressionFile is a loaded suppression file.
type SuppressionFile struct {
	Source  string
	Entries []*Suppression
}

var (
	suppressionKeys = []string{"rule", "file", "function", "anchor", "line", "message", "reason", "finding", "issue", "commit", "reviewer", "date"}
	findingIDRe     = regexp.MustCompile(`^F-[0-9]{4}$`)
)

func loadSuppressionFile(src source) (*SuppressionFile, error) {
	data, err := src.read()
	if err != nil {
		return nil, fmt.Errorf("suppressions: %w", err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%s: %v", src.display, err)
	}
	sf := &SuppressionFile{Source: src.display}
	if len(doc.Content) == 0 { // empty file: no suppressions
		return sf, nil
	}
	list := doc.Content[0]
	if list.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("%s:%d: a suppression file is a YAML list of entries", src.display, list.Line)
	}
	for _, item := range list.Content {
		s := &Suppression{Source: src.display, Line: item.Line}
		if item.Kind != yaml.MappingNode {
			s.Problem = "entry is not a mapping"
			sf.Entries = append(sf.Entries, s)
			continue
		}
		for i := 0; i+1 < len(item.Content); i += 2 {
			if k := item.Content[i].Value; !slices.Contains(suppressionKeys, k) {
				s.Problem = fmt.Sprintf("unknown key %q", k)
			}
		}
		if err := item.Decode(s); err != nil {
			s.Problem = err.Error()
		}
		if s.Problem == "" {
			s.Problem = s.check()
		}
		sf.Entries = append(sf.Entries, s)
	}
	return sf, nil
}

func (s *Suppression) check() string {
	switch {
	case s.Rule == "":
		return "names no rule"
	case !ruleIDPattern.MatchString(s.Rule):
		return fmt.Sprintf("rule %q is not XDRnnn", s.Rule)
	case s.Rule == XDR000.ID:
		return "XDR000 cannot be suppressed"
	case strings.TrimSpace(s.Reason) == "":
		return "has no reason"
	case s.File == "":
		return "names no file"
	case s.Function == "" && s.Anchor == "" && s.At == 0 && s.Message == "":
		return "names none of a function, an anchor, a line and a message"
	case s.At < 0:
		return fmt.Sprintf("line %d is not a line number", s.At)
	case s.Finding != "" && !findingIDRe.MatchString(s.Finding):
		return fmt.Sprintf("finding %q is not F-nnnn", s.Finding)
	}
	return ""
}

// match returns the first valid entry that suppresses a report of rule at
// file (module-relative), inside function, on line line whose text is
// lineText, with message message.
func (c *Config) matchSuppression(rule, file, function string, line int, lineText, message string) *Suppression {
	if c == nil {
		return nil
	}
	for _, sf := range c.SuppressionFiles {
		for _, s := range sf.Entries {
			if s.Problem != "" || s.Rule != rule || s.File != file {
				continue
			}
			if s.Function != "" && s.Function != function {
				continue
			}
			if s.Anchor != "" && !strings.Contains(lineText, s.Anchor) {
				continue
			}
			if s.At != 0 && s.At != line {
				continue
			}
			if s.Message != "" && NormaliseMessage(s.Message) != NormaliseMessage(message) {
				continue
			}
			return s
		}
	}
	return nil
}

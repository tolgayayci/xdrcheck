package framework

// XDR000 — suppression hygiene. Two halves:
//
//   - runXDR000, an analyzer that runs after every rule analyzer on the same
//     package, checks the inline directives: malformed, no reason, unknown
//     rule, or suppressing nothing of a rule that ran.
//   - SuppressionFindings, called by the standalone driver after all
//     packages ran, checks the external suppression files: a malformed entry
//     or an entry that matched no report anywhere.

import (
	"fmt"
	"go/token"
	"strconv"
	"strings"
)

func (reg *Registry) runXDR000(p *Pass) (any, error) {
	ran := map[string]bool{}
	used := map[token.Pos]map[string]bool{}
	for _, a := range p.Analyzer.Requires {
		res, ok := p.ResultOf[a].(*Result)
		if !ok {
			continue
		}
		for _, id := range res.RulesRun {
			ran[id] = true
		}
		for pos, ids := range res.UsedDirectives {
			if used[pos] == nil {
				used[pos] = map[string]bool{}
			}
			for id := range ids {
				used[pos][id] = true
			}
		}
	}
	at := func(d *Directive, format string, args ...any) {
		p.Report(Report{Rule: XDR000.ID, Pos: d.Pos, Message: fmt.Sprintf(format, args...)})
	}
	for _, d := range p.Directives() {
		if d.Problem != "" {
			at(d, "%s", d.Problem)
			continue
		}
		if d.Verb != "ignore" {
			continue
		}
		for _, id := range d.Rules {
			switch {
			case id == XDR000.ID:
				at(d, "XDR000 cannot be suppressed")
			case !isReserved(id) && reg.Rule(id) == nil:
				at(d, "suppression names unknown rule %s", id)
			case ran[id] && !used[d.Pos][id]:
				at(d, "suppression of %s suppresses nothing", id)
			}
		}
	}
	return nil, nil
}

// SuppressionFindings checks the external suppression files of cfg after a
// run. used holds the keys of the entries that matched a report (the union
// of Result.UsedSuppressions over all packages). Entries of a rule that did
// not run under cfg are reported only when the rule does not exist.
func (reg *Registry) SuppressionFindings(cfg *Config, used map[string]bool) []Finding {
	if cfg == nil || !cfg.Enabled(XDR000) {
		return nil
	}
	var out []Finding
	for _, sf := range cfg.SuppressionFiles {
		for _, s := range sf.Entries {
			msg := ""
			r := reg.Rule(s.Rule)
			switch {
			case s.Problem != "":
				msg = "suppression entry " + s.Problem
			case r == nil && !isReserved(s.Rule):
				msg = "suppression entry names unknown rule " + s.Rule
			case r == nil:
				msg = "suppression entry names " + s.Rule + ", which this build of xdrlint does not provide, so it cannot match"
			case !cfg.Enabled(*r):
				continue
			case !used[s.Key()]:
				msg = fmt.Sprintf("suppression of %s in %s (%s) matches nothing: the site changed or the rule no longer fires", s.Rule, s.File, s.where())
			default:
				continue
			}
			out = append(out, Finding{
				Rule:       XDR000.ID,
				Severity:   cfg.SeverityOf(XDR000, ""),
				Message:    msg,
				Assumption: AssumeSuppression,
				Position:   token.Position{Filename: s.Source, Line: s.Line, Column: 1},
				File:       s.Source,
			})
		}
	}
	return out
}

func (s *Suppression) where() string {
	var parts []string
	if s.Function != "" {
		parts = append(parts, "function "+s.Function)
	}
	if s.Anchor != "" {
		parts = append(parts, "anchor "+strconv.Quote(s.Anchor))
	}
	if s.At != 0 {
		parts = append(parts, "line "+strconv.Itoa(s.At))
	}
	if s.Message != "" {
		parts = append(parts, "message "+strconv.Quote(NormaliseMessage(s.Message)))
	}
	return strings.Join(parts, ", ")
}

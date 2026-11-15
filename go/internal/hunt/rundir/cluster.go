package rundir

import (
	_ "embed"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

// The public dispositions table: only noise that the targets' own documentation or design explains
// (builder defaults, documented refusals, intended behaviour, JSON dialects). It never names a finding.
//
//go:embed dispositions.tsv
var publicDispositions string

// Disposition rule: target and check are full-match regular expressions, class a full-match regular
// expression on the class. The first matching rule wins; overlay rules are tried before public ones.
type rule struct {
	target, check, class *regexp.Regexp
	disposition, note    string
	finding              string
}

// Dispositions decides what a cluster is.
type Dispositions struct {
	rules []rule
}

// Noise is the set of dispositions that are not defects of the target.
var Noise = map[string]bool{"by-design": true, "builder-default": true, "dialect": true, "expected-refusal": true, "recipe-artefact": true, "harness": true}

var validDisposition = map[string]bool{"candidate": true, "known": true, "by-design": true, "builder-default": true, "dialect": true, "expected-refusal": true, "recipe-artefact": true, "harness": true}

// LoadDispositions reads the public table and, when overlay is not empty, a private overlay table in the same
// format whose rules come first. The overlay is the only place a rule may name a finding (sixth column).
func LoadDispositions(overlay string) (*Dispositions, error) {
	d := &Dispositions{}
	if overlay != "" {
		b, err := os.ReadFile(overlay)
		if err != nil {
			return nil, fmt.Errorf("dispositions overlay: %v", err)
		}
		if err := d.parse(string(b), overlay, true); err != nil {
			return nil, err
		}
	}
	if err := d.parse(publicDispositions, "public dispositions", false); err != nil {
		return nil, err
	}
	return d, nil
}

func (d *Dispositions) parse(text, name string, overlay bool) error {
	for n, l := range strings.Split(text, "\n") {
		if strings.TrimSpace(l) == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "target\t") {
			continue
		}
		p := strings.Split(l, "\t")
		if len(p) < 4 {
			return fmt.Errorf("%s:%d: want target, check, class pattern, disposition[, note[, finding]]", name, n+1)
		}
		if !validDisposition[p[3]] {
			return fmt.Errorf("%s:%d: unknown disposition %q", name, n+1, p[3])
		}
		var r rule
		var err error
		for i, dst := range []**regexp.Regexp{&r.target, &r.check, &r.class} {
			if *dst, err = regexp.Compile("^(?:" + p[i] + ")$"); err != nil {
				return fmt.Errorf("%s:%d: %v", name, n+1, err)
			}
		}
		r.disposition = p[3]
		if len(p) > 4 {
			r.note = p[4]
		}
		if len(p) > 5 {
			if !overlay {
				return fmt.Errorf("%s:%d: only an overlay table may name a finding", name, n+1)
			}
			r.finding = p[5]
		}
		d.rules = append(d.rules, r)
	}
	return nil
}

// Of returns the disposition, note and finding of a cluster.
func (d *Dispositions) Of(target, check, class string) (string, string, string) {
	if d != nil {
		for _, r := range d.rules {
			if r.target.MatchString(target) && r.check.MatchString(check) && r.class.MatchString(class) {
				return r.disposition, r.note, r.finding
			}
		}
	}
	return "candidate", "", ""
}

// MaxExamples is the number of examples kept per cluster.
const MaxExamples = 5

// Group groups rows by (check, class). strata maps a ledger to the dataset strata it belongs to (may be nil).
func Group(target string, rows []Verdict, disp *Dispositions, strata func(uint32) []string) []Cluster {
	byKey := map[string]*Cluster{}
	txSeen := map[string]map[string]bool{}
	ledSeen := map[string]map[uint32]bool{}
	for _, r := range rows {
		k := ClusterKey(r.Check, r.Class)
		c := byKey[k]
		if c == nil {
			c = &Cluster{Key: k, Check: r.Check, Class: r.Class, Strata: map[string]int{}, OpTypes: map[string]int{}, FirstLedger: r.Ledger, LastLedger: r.Ledger}
			c.Disposition, c.Note, _ = disp.Of(target, r.Check, r.Class)
			if _, _, f := disp.Of(target, r.Check, r.Class); f != "" {
				ff := f
				c.Finding = &ff
			}
			byKey[k] = c
			txSeen[k] = map[string]bool{}
			ledSeen[k] = map[uint32]bool{}
		}
		c.Count++
		if r.Ledger < c.FirstLedger {
			c.FirstLedger = r.Ledger
		}
		if r.Ledger > c.LastLedger {
			c.LastLedger = r.Ledger
		}
		if r.OpType != "" {
			c.OpTypes[r.OpType]++
		}
		if r.Tx != nil && !txSeen[k][r.TxKey()] {
			txSeen[k][r.TxKey()] = true
			c.Txs++
			var st []string
			if strata != nil {
				st = strata(r.Ledger)
			}
			if len(st) == 0 {
				st = []string{"none"}
			}
			for _, s := range st {
				c.Strata[s]++
			}
			if len(c.Examples) < MaxExamples {
				detail, _ := r.Evidence["detail"].(string)
				c.Examples = append(c.Examples, Example{Ledger: r.Ledger, Tx: r.Tx, Op: r.Op, TxHash: r.TxHash, Detail: clip(detail, 300)})
			}
		}
		if r.Tx == nil && len(c.Examples) < MaxExamples && !ledSeen[k][r.Ledger] {
			detail, _ := r.Evidence["detail"].(string)
			c.Examples = append(c.Examples, Example{Ledger: r.Ledger, Detail: clip(detail, 300)})
		}
		if !ledSeen[k][r.Ledger] {
			ledSeen[k][r.Ledger] = true
			c.Ledgers++
		}
	}
	out := make([]Cluster, 0, len(byKey))
	for _, c := range byKey {
		if len(c.OpTypes) == 0 {
			c.OpTypes = nil
		}
		if c.Examples == nil {
			c.Examples = []Example{}
		}
		out = append(out, *c)
	}
	// candidates first, then by size
	sort.Slice(out, func(i, j int) bool {
		ni, nj := Noise[out[i].Disposition], Noise[out[j].Disposition]
		if ni != nj {
			return !ni
		}
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	return out
}

func clip(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		s = s[:n]
	}
	return s
}

// Summarise fills the counts of a summary from rows and clusters. tested maps a check to the number of times
// it ran (from the target); a check with failures but no tested count gets the failure count.
func Summarise(s *Summary, rows []Verdict, clusters []Cluster, tested map[string]int64) {
	s.Verdicts = map[string]int{}
	s.Checks = map[string]CheckCount{}
	for c, n := range tested {
		s.Checks[c] = CheckCount{Tested: n}
	}
	for _, r := range rows {
		s.Verdicts[r.Verdict]++
		cc := s.Checks[r.Check]
		cc.Failed++
		s.Checks[r.Check] = cc
	}
	for k, cc := range s.Checks {
		if cc.Tested < cc.Failed {
			cc.Tested = cc.Failed
			s.Checks[k] = cc
		}
	}
	s.Clusters = map[string]int{"total": len(clusters)}
	for _, c := range clusters {
		s.Clusters[c.Disposition]++
	}
}

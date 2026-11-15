package mutate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Signature identifies a candidate across runs: the reader (with its version), the verdict, the mutator and
// the value type and generalised path of the mutation.
type Signature struct {
	Reader   string `json:"reader"`
	Verdict  string `json:"verdict"`
	Mutator  string `json:"mutator"`
	XDRType  string `json:"xdr_type"`
	TypePath string `json:"type_path"`
}

func (s Signature) String() string {
	return strings.Join([]string{s.Reader, s.Verdict, s.Mutator, s.XDRType + ":" + s.TypePath}, "|")
}

// Hash is the signature's short hash, used as the candidate record's name.
func (s Signature) Hash() string {
	h := sha256.Sum256([]byte(s.String()))
	return hex.EncodeToString(h[:8])
}

// SignatureOf is the signature of a verdict on a mutant: the first mutation names the mutator and path (after
// minimisation a candidate has one).
func SignatureOf(m *Mutant, v *ReaderVerdict) Signature {
	s := Signature{Reader: v.Reader, Verdict: v.Verdict, XDRType: m.XDRType}
	if len(m.Mutations) > 0 {
		s.Mutator, s.TypePath = m.Mutations[0].Mutator, m.Mutations[0].TypePath
	}
	return s
}

// Rule suppresses the signatures it matches. Every field is a glob (`*` matches anything); an empty field
// matches everything. A rule cites the finding record (public `findings/<id>`, or a private overlay record)
// whose defect the signatures are; a rule whose finding does not exist is refused.
type Rule struct {
	Reader   string `json:"reader"`
	Verdict  string `json:"verdict"`
	Mutator  string `json:"mutator"`
	XDRType  string `json:"xdr_type"`
	TypePath string `json:"type_path"`
	Finding  string `json:"finding"`
	Note     string `json:"note"`

	origin string
}

// Rules is a loaded rule list.
type Rules []Rule

func glob(g, s string) bool {
	if g == "" {
		return true
	}
	re := "^" + strings.ReplaceAll(regexp.QuoteMeta(g), `\*`, ".*") + "$"
	ok, _ := regexp.MatchString(re, s)
	return ok
}

// Match returns the first rule matching the signature.
func (rs Rules) Match(s Signature) *Rule {
	for i := range rs {
		r := &rs[i]
		if glob(r.Reader, s.Reader) && glob(r.Verdict, s.Verdict) && glob(r.Mutator, s.Mutator) &&
			glob(r.XDRType, s.XDRType) && glob(r.TypePath, s.TypePath) {
			return r
		}
	}
	return nil
}

// LoadRules reads a rule file (a JSON object with a "rules" list). findingDirs are the directories finding
// records live in (`<dir>/<id>/finding.json`); each rule's finding must be one of them. A missing file is no
// rules.
func LoadRules(path string, findingDirs ...string) (Rules, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var doc struct {
		Rules []Rule `json:"rules"`
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for i := range doc.Rules {
		r := &doc.Rules[i]
		r.origin = path
		if r.Finding == "" {
			return nil, fmt.Errorf("%s: rule %d cites no finding", path, i)
		}
		found := false
		for _, d := range findingDirs {
			if _, err := os.Stat(filepath.Join(d, r.Finding, "finding.json")); err == nil {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("%s: rule %d cites %s, which has no finding record", path, i, r.Finding)
		}
	}
	return doc.Rules, nil
}

// Candidate is one triaged candidate finding, as stored in the private overlay.
type Candidate struct {
	Schema      string        `json:"schema"`
	Signature   Signature     `json:"signature"`
	SigHash     string        `json:"signature_hash"`
	Verdict     ReaderVerdict `json:"verdict"`
	Line        string        `json:"verdict_line"`
	Mutant      *Mutant       `json:"mutant"`
	Minimised   bool          `json:"minimised"`
	Occurrences int           `json:"occurrences"`
	Mutants     []string      `json:"mutants"`
	Replay      string        `json:"replay"`
	Readers     string        `json:"readers"`
	Run         string        `json:"run"`
}

// CandidateSchema is the candidate record's schema ID.
const CandidateSchema = "xcc.mutate.candidate/v1"

// ReplayCommand is the command that rebuilds the mutant and re-judges it with the readers its verdict needs.
func ReplayCommand(m *Mutant, readers string) string {
	stale := ""
	if m.StaleHashes {
		stale = " --stale-hashes"
	}
	return fmt.Sprintf("xdrcheck mutate replay --entry '%s' --variant %d --seed %d --mutation %s --readers '%s'%s",
		m.Source, m.Variant, m.Seed, strings.Join(m.MutationIDs(), ","), readers, stale)
}

// ReadersFor is the reader set a verdict needs to be decided again: the reader, the stellar-core column (the
// quarantine depends on it) and, for a split, every column the run had (columns, comma-separated).
func ReadersFor(v *ReaderVerdict, core, columns string) string {
	if v.Verdict == Split || v.Verdict == ReaderConsensus {
		return columns
	}
	if core == "" || v.Reader == core {
		return v.Reader
	}
	return v.Reader + "," + core
}

// Inside reports whether path p lies inside dir.
func Inside(dir, p string) bool {
	a, err1 := filepath.Abs(dir)
	b, err2 := filepath.Abs(p)
	if err1 != nil || err2 != nil {
		return true
	}
	rel, err := filepath.Rel(a, b)
	return err == nil && (rel == "." || !strings.HasPrefix(rel, ".."))
}

// WriteCandidates writes one record per candidate into dir (never a path inside the repository root).
func WriteCandidates(dir, repoRoot string, cs []*Candidate) error {
	if Inside(repoRoot, dir) {
		return fmt.Errorf("candidate directory %s is inside the repository; candidates go to the private overlay only", dir)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, c := range cs {
		b, err := json.MarshalIndent(c, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, c.SigHash+".json"), append(b, '\n'), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// SortCandidates orders candidates by verdict severity, then signature.
func SortCandidates(cs []*Candidate) {
	sev := map[string]int{Halt: 0, AcceptsInvalid: 1, WrongFact: 2, OrderDependent: 3, Split: 4, RefusesValid: 5, ReaderConsensus: 6}
	sort.SliceStable(cs, func(i, j int) bool {
		a, b := cs[i], cs[j]
		if sev[a.Signature.Verdict] != sev[b.Signature.Verdict] {
			return sev[a.Signature.Verdict] < sev[b.Signature.Verdict]
		}
		return a.Signature.String() < b.Signature.String()
	})
}

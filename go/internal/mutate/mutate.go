// Package mutate judges what readers do with structure-aware mutants of corpus values (built by the
// xdrcheck-mutate binary, docs/mutation.md) and triages the disagreements.
//
// Each mutant is a value of one class: valid-preserving (the oracle must accept it), metamorphic (the facts
// must not change) or wire-invalid (the oracle must refuse it). The conformance runner and the replay harness
// run it like any corpus entry; this package turns their cells into one verdict per (mutant, reader):
//
//   - accepts-invalid, refuses-valid, wrong-fact: the reader against the oracle (strict decode, byte-exact
//     re-encode, the reference extractor's facts);
//   - halt: the reader crashed, timed out, ran out of memory or stopped ingesting;
//   - order-dependent: a metamorphic mutant changed what the reader reports;
//   - cross-reader-split: the oracle and stellar-core disagree on the mutant, and the readers split too;
//   - reader-consensus: every SDK that ran disagrees with the oracle the same way, but stellar-core sides with
//     the oracle: the SDKs share a mistake against the network's reading (reported apart from the others);
//
// and, for cells that are not findings: conform, n_a, refused (an adapter's declared gate), flaky, inherited
// (the reader fails the unmutated control the same way), oracle-question (the oracle and stellar-core disagree,
// or every SDK agrees against it while stellar-core did not run, so the oracle cannot judge the reader) and
// reference (the stellar-core column itself).
//
// A candidate's signature is (reader, version, verdict, mutator, type path); signatures that match a
// suppression rule citing an existing finding record are not reported again.
package mutate

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Verdicts.
const (
	AcceptsInvalid = "accepts-invalid"
	RefusesValid   = "refuses-valid"
	Halt           = "halt"
	WrongFact      = "wrong-fact"
	OrderDependent = "order-dependent"
	Split          = "cross-reader-split"
	// ReaderConsensus is every SDK against the oracle with stellar-core on the oracle's side.
	ReaderConsensus = "reader-consensus"

	Conform        = "conform"
	NA             = "n_a"
	Refused        = "refused"
	Flaky          = "flaky"
	Inherited      = "inherited"
	OracleQuestion = "oracle-question"
	Reference      = "reference"
)

// Candidates are the verdicts reported as candidate findings.
var Candidates = map[string]bool{AcceptsInvalid: true, RefusesValid: true, Halt: true, WrongFact: true, OrderDependent: true, Split: true,
	ReaderConsensus: true}

// Known is every verdict a cell may end in; anything else is unclassified.
var Known = map[string]bool{
	AcceptsInvalid: true, RefusesValid: true, Halt: true, WrongFact: true, OrderDependent: true, Split: true, ReaderConsensus: true,
	Conform: true, NA: true, Refused: true, Flaky: true, Inherited: true, OracleQuestion: true, Reference: true,
}

// Class names as the mutant records carry them.
const (
	ClassValid       = "valid"
	ClassMetamorphic = "metamorphic"
	ClassWire        = "wire-invalid"
)

// Mutation is one mutation of a mutant record.
type Mutation struct {
	ID       string `json:"id"`
	Mutator  string `json:"mutator"`
	Class    string `json:"class"`
	Loc      string `json:"loc"`
	Path     string `json:"path"`
	TypePath string `json:"type_path"`
	TypeName string `json:"type_name"`
	Arg      int    `json:"arg"`
	Off      int    `json:"off"`
	End      int    `json:"end"`
}

// Oracle is the oracle's answer on a mutant.
type Oracle struct {
	Accepts bool   `json:"accepts"`
	Reason  string `json:"reason,omitempty"`
}

// Mutant is one line of mutants.ndjson.
type Mutant struct {
	ID          string          `json:"id"`
	Source      string          `json:"source"`
	Entry       string          `json:"entry"`
	Variant     int             `json:"variant"`
	Seed        uint64          `json:"seed"`
	Class       string          `json:"class"`
	XDRType     string          `json:"xdr_type"`
	Mutations   []Mutation      `json:"mutations"`
	SHA256      string          `json:"sha256"`
	Oracle      Oracle          `json:"oracle"`
	Reseal      json.RawMessage `json:"reseal,omitempty"`
	StaleHashes bool            `json:"stale_hashes"`
	// ProtocolRule is the rule of the protocol (not of XDR) the mutant's value breaks, if any: a reader may
	// refuse such a value.
	ProtocolRule string   `json:"protocol_rule,omitempty"`
	Notes        []string `json:"notes,omitempty"`
	EntryID      string   `json:"entry_id"`
	Control      *string  `json:"control"`
	BytesLen     int      `json:"bytes_len"`
	Replay       string   `json:"replay"`
}

// MutationIDs is the mutant's mutation IDs in order.
func (m *Mutant) MutationIDs() []string {
	out := make([]string, len(m.Mutations))
	for i, x := range m.Mutations {
		out[i] = x.ID
	}
	return out
}

// ReadMutants reads a mutants.ndjson file.
func ReadMutants(path string) ([]*Mutant, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []*Mutant
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		if len(strings.TrimSpace(sc.Text())) == 0 {
			continue
		}
		var m Mutant
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		out = append(out, &m)
	}
	return out, sc.Err()
}

// Cell is one reader's result on one entry at one level (a replay row is level "replay").
type Cell struct {
	Reader string // column ID, or <adapter>@<version>
	Kind   string // sdk, core, pipeline
	Family string // the SDK or pipeline name, versions apart
	Level  string
	// Verdict is the runner's own verdict, mapped to this package's vocabulary (see FromConform and
	// FromReplay).
	Verdict string
	// Accepted: the reader accepted the input (conformance: outcome ok or diverge).
	Accepted bool
	Refused  bool // the reader refused the input cleanly
	// Reencoded is the sha256 of what the reader re-encoded (conformance L0), when it did.
	Reencoded string
	// Reason is the reader's reason code for a refusal (conformance).
	Reason string
	Detail string
	// OwnFault is set when our own tooling failed on the cell (a driver protocol error, a harness fault): the
	// cell says nothing about the reader.
	OwnFault string
}

// FromConform maps a conformance verdict (conform, diverge, accepts_invalid, reject_valid, crash, n_a).
func FromConform(v string) string {
	switch v {
	case "conform":
		return Conform
	case "n_a":
		return NA
	case "crash":
		return Halt
	case "accepts_invalid":
		return AcceptsInvalid
	case "reject_valid":
		return RefusesValid
	case "diverge":
		return WrongFact
	}
	return "unclassified:" + v
}

// FromReplay maps a replay class and qualifier. refusal says the adapter refused at a gate it declares.
func FromReplay(class, qualifier string, refusal bool) string {
	switch class {
	case "pass":
		return Conform
	case "not_applicable", "not_reached":
		return NA
	case "flaky":
		return Flaky
	case "mishandled":
		switch qualifier {
		case "crash", "hang", "halt":
			if refusal {
				return Refused
			}
			return Halt
		case "wrong_value":
			return WrongFact
		}
	case "dropped":
		switch qualifier {
		case "silent", "partial":
			return WrongFact
		case "refused":
			if refusal {
				return Refused
			}
			return RefusesValid
		}
	}
	return "unclassified:" + class + "·" + qualifier
}

var rank = map[string]int{Conform: 0, NA: 1, Refused: 2, Flaky: 3, WrongFact: 4, RefusesValid: 5, AcceptsInvalid: 6, Halt: 7}

func worse(a, b string) string {
	ra, oka := rank[a]
	rb, okb := rank[b]
	switch {
	case !oka:
		return a
	case !okb:
		return b
	case rb > ra:
		return b
	}
	return a
}

// ReaderVerdict is the verdict on one (mutant, reader). Its JSON is the deterministic line `xdrcheck mutate replay`
// prints and a candidate record stores.
type ReaderVerdict struct {
	Mutant        string   `json:"mutant"`
	Source        string   `json:"source"`
	Variant       int      `json:"variant"`
	Seed          uint64   `json:"seed"`
	Class         string   `json:"class"`
	Mutations     []string `json:"mutations"`
	Reader        string   `json:"reader"`
	Kind          string   `json:"kind"`
	Verdict       string   `json:"verdict"`
	Detail        string   `json:"detail,omitempty"`
	OracleAccepts bool     `json:"oracle_accepts"`
	Core          string   `json:"core"` // accept, refuse, or "" when the stellar-core column did not run
	Quarantined   bool     `json:"quarantined"`
}

// Line is the verdict's canonical JSON.
func (v *ReaderVerdict) Line() string {
	b, _ := json.Marshal(v)
	return string(b)
}

type readerSum struct {
	reader, kind, family string
	verdict              string
	detail               []string
	l0Accept, l0Refuse   bool
	reencoded            string
	own                  []string
}

func summarise(cells []Cell) map[string]*readerSum {
	out := map[string]*readerSum{}
	for _, c := range cells {
		s := out[c.Reader]
		if s == nil {
			s = &readerSum{reader: c.Reader, kind: c.Kind, family: c.Family, verdict: Conform}
			out[c.Reader] = s
		}
		if c.OwnFault != "" {
			s.own = append(s.own, c.Level+": "+c.OwnFault)
			continue
		}
		s.verdict = worse(s.verdict, c.Verdict)
		if c.Detail != "" && c.Verdict != Conform && c.Verdict != NA {
			s.detail = append(s.detail, c.Level+": "+c.Detail)
		}
		if c.Level == "L0" {
			s.l0Accept, s.l0Refuse, s.reencoded = c.Accepted, c.Refused, c.Reencoded
		}
	}
	return out
}

// Judge decides the verdict of every reader on mutant m from its cells, and the cells of the mutant's
// unmutated control (nil for a wire-invalid mutant). own lists failures of our own tooling.
func Judge(m *Mutant, cells, control []Cell) (out []ReaderVerdict, own []string) {
	if m.Class == ClassValid {
		cells = semanticRefusals(cells)
	}
	sums := summarise(cells)
	ctl := summarise(control)
	core := ""
	for _, s := range sums {
		if s.kind == "core" && (s.l0Accept || s.l0Refuse) {
			if s.l0Accept {
				core = "accept"
			} else {
				core = "refuse"
			}
		}
	}
	quarantined := core != "" && (core == "accept") != m.Oracle.Accepts
	splits := map[string]string{}
	if quarantined {
		splits = splitReaders(sums)
	}
	consensus := unanimous(sums, m.Oracle.Accepts)
	readers := make([]string, 0, len(sums))
	for r := range sums {
		readers = append(readers, r)
	}
	sort.Strings(readers)
	for _, r := range readers {
		s := sums[r]
		for _, o := range s.own {
			own = append(own, fmt.Sprintf("%s on %s: %s", r, m.ID, o))
		}
		v := s.verdict
		detail := strings.Join(s.detail, "; ")
		switch {
		case s.kind == "core":
			v = Reference
		case splits[r] != "":
			v, detail = Split, splits[r]
		case quarantined && (v == AcceptsInvalid || v == RefusesValid || v == WrongFact):
			v = OracleQuestion
		case v == RefusesValid && m.ProtocolRule != "":
			v = Refused
			detail = "the value breaks a protocol rule (" + m.ProtocolRule + "); " + detail
		case v == Halt && m.ProtocolRule != "":
			// Still a halt, but on input stellar-core never emits: triage ranks it below a halt on network data.
			detail = "on a value that breaks a protocol rule (" + m.ProtocolRule + "); " + detail
		case consensus != "" && s.kind == "sdk" && v == consensus && core != "":
			// stellar-core ran and sides with the oracle (otherwise the mutant is quarantined above): the
			// network reads the value as the oracle does, so the SDKs' shared answer is theirs, not the oracle's.
			v = ReaderConsensus
			detail = "every SDK that ran gives " + consensus + "; stellar-core sides with the oracle (" + core + "); " + detail
		case consensus != "" && s.kind == "sdk" && v == consensus:
			v = OracleQuestion
			detail = "every SDK that ran gives " + consensus + "; the oracle checks XDR only and stellar-core did not run; " + detail
		}
		if Candidates[v] && v != Split && v != ReaderConsensus && m.Class != ClassWire {
			if c := ctl[r]; c != nil && c.verdict != Conform && c.verdict != NA && len(c.own) == 0 {
				v = Inherited
				detail = "the unmutated control: " + c.verdict + "; " + detail
			} else if m.Class == ClassMetamorphic && (v == WrongFact || v == RefusesValid) {
				v = OrderDependent
			}
		}
		if len(s.own) > 0 && v == Conform {
			continue
		}
		out = append(out, ReaderVerdict{
			Mutant: m.ID, Source: m.Source, Variant: m.Variant, Seed: m.Seed, Class: m.Class, Mutations: m.MutationIDs(),
			Reader: r, Kind: s.kind, Verdict: v, Detail: detail, OracleAccepts: m.Oracle.Accepts, Core: core, Quarantined: quarantined,
		})
	}
	return out, own
}

// SemanticReasons are the refusal reasons of an SDK's object layer (L1) that check a value against a rule of
// the protocol rather than of XDR: a payment amount above zero, a known operation, a time bound in range.
var SemanticReasons = map[string]bool{"object_validation": true, "value_out_of_range": true}

// semanticRefusals turns an L1 refusal for a semantic reason into refused: a valid-preserving mutation makes
// XDR-valid values the network never admits (a zero payment), and an object layer may refuse them. The
// value's XDR (L0) is still judged; a metamorphic mutant, whose values are the network's, keeps the verdict.
func semanticRefusals(cells []Cell) []Cell {
	out := make([]Cell, len(cells))
	for i, c := range cells {
		if c.Level == "L1" && c.Verdict == RefusesValid && SemanticReasons[c.Reason] {
			c.Verdict = Refused
		}
		out[i] = c
	}
	return out
}

// unanimous returns refuses-valid (for a value the oracle accepts) or accepts-invalid (for one it refuses)
// when every column of at least two SDKs that judged the mutant ended in it: SDKs that agree with each other
// against the oracle point at a rule the oracle does not model (an asset code's character set, a protocol
// limit), not at a reader. Otherwise "".
func unanimous(sums map[string]*readerSum, oracleAccepts bool) string {
	want := AcceptsInvalid
	if oracleAccepts {
		want = RefusesValid
	}
	families := map[string]bool{}
	for _, s := range sums {
		if s.kind != "sdk" || len(s.own) > 0 || s.verdict == NA {
			continue
		}
		if s.verdict != want {
			return ""
		}
		families[s.family] = true
	}
	if len(families) < 2 {
		return ""
	}
	return want
}

// splitReaders groups the SDK readers by what they did at L0 (refused, or accepted and re-encoded these
// bytes). With two or more groups, the group spanning the most SDKs (ties: refusal first, then by key) is the
// reference, and every reader of another group is in a split.
func splitReaders(sums map[string]*readerSum) map[string]string {
	groups := map[string][]*readerSum{}
	for _, s := range sums {
		if s.kind != "sdk" || len(s.own) > 0 {
			continue
		}
		key := ""
		switch {
		case s.l0Refuse:
			key = "refuse"
		case s.l0Accept && s.reencoded != "":
			key = "accept:" + s.reencoded
		case s.l0Accept:
			key = "accept"
		default:
			continue
		}
		groups[key] = append(groups[key], s)
	}
	if len(groups) < 2 {
		return map[string]string{}
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	families := func(k string) int {
		f := map[string]bool{}
		for _, s := range groups[k] {
			f[s.family] = true
		}
		return len(f)
	}
	sort.Slice(keys, func(i, j int) bool {
		fi, fj := families(keys[i]), families(keys[j])
		if fi != fj {
			return fi > fj
		}
		if (keys[i] == "refuse") != (keys[j] == "refuse") {
			return keys[i] == "refuse"
		}
		return keys[i] < keys[j]
	})
	ref := keys[0]
	out := map[string]string{}
	for _, k := range keys[1:] {
		for _, s := range groups[k] {
			out[s.reader] = fmt.Sprintf("L0 %s; the readers of %d SDK(s) %s", describe(k), families(ref), describe(ref))
		}
	}
	return out
}

func describe(key string) string {
	switch {
	case key == "refuse":
		return "refuse it"
	case key == "accept":
		return "accept it"
	default:
		return "accept it and re-encode sha256 " + strings.TrimPrefix(key, "accept:")
	}
}

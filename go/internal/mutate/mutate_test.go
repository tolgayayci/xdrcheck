package mutate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mutant(class string, oracle bool, mutators ...string) *Mutant {
	m := &Mutant{ID: "x1", Source: "s", Class: class, XDRType: "ScVal", Oracle: Oracle{Accepts: oracle}}
	for i, mu := range mutators {
		m.Mutations = append(m.Mutations, Mutation{ID: "m" + string(rune('a'+i)), Mutator: mu, TypePath: "/b"})
	}
	return m
}

func l0(reader, family, kind, verdict string, accepted bool, re string) Cell {
	return Cell{Reader: reader, Family: family, Kind: kind, Level: "L0", Verdict: verdict, Accepted: accepted, Refused: !accepted && verdict != NA, Reencoded: re}
}

func byReader(vs []ReaderVerdict) map[string]string {
	out := map[string]string{}
	for _, v := range vs {
		out[v.Reader] = v.Verdict
	}
	return out
}

func TestJudgeAgainstOracle(t *testing.T) {
	m := mutant(ClassWire, false, "disc-unknown")
	cells := []Cell{
		l0("core@30", "core", "core", AcceptsInvalid, false, ""),
		l0("x@1", "x", "sdk", AcceptsInvalid, true, "aa"),
		l0("go@9", "go", "sdk", Conform, false, ""),
		{Reader: "rs@30", Family: "rust", Kind: "sdk", Level: "L0", Verdict: Halt},
	}
	cells[0].Refused, cells[0].Verdict = true, Conform
	got := byReader(must(Judge(m, cells, nil)))
	want := map[string]string{"core@30": Reference, "x@1": AcceptsInvalid, "go@9": Conform, "rs@30": Halt}
	for r, v := range want {
		if got[r] != v {
			t.Errorf("%s: %s, want %s", r, got[r], v)
		}
	}
}

func must(v []ReaderVerdict, own []string) []ReaderVerdict { return v }

// When stellar-core and the oracle disagree, readers are not judged against the oracle; the readers that
// differ from the reference group (the most SDKs) are in a split.
func TestQuarantineAndSplit(t *testing.T) {
	m := mutant(ClassWire, false, "bool-2")
	cells := []Cell{
		l0("core@30", "core", "core", AcceptsInvalid, true, ""),
		l0("rs@28", "rust", "sdk", AcceptsInvalid, true, "00"),
		l0("rs@30", "rust", "sdk", AcceptsInvalid, true, "00"),
		l0("py@17", "python", "sdk", AcceptsInvalid, true, "01"),
		l0("js@17", "js", "sdk", Conform, false, ""),
		l0("go@9", "go", "sdk", Conform, false, ""),
	}
	vs, _ := Judge(m, cells, nil)
	got := byReader(vs)
	for _, r := range []string{"rs@28", "rs@30", "py@17"} {
		if got[r] != Split {
			t.Errorf("%s: %s, want %s", r, got[r], Split)
		}
	}
	if got["js@17"] != Conform || got["core@30"] != Reference {
		t.Errorf("reference group: %v", got)
	}
	for _, v := range vs {
		if !v.Quarantined || v.Core != "accept" {
			t.Errorf("%s: not quarantined: %+v", v.Reader, v)
		}
	}
}

func TestControlAndMetamorphic(t *testing.T) {
	m := mutant(ClassMetamorphic, true, "change-permute")
	cells := []Cell{
		{Reader: "wb", Family: "wb", Kind: "pipeline", Level: "replay", Verdict: WrongFact},
		{Reader: "etl", Family: "etl", Kind: "pipeline", Level: "replay", Verdict: WrongFact},
		{Reader: "base", Family: "base", Kind: "pipeline", Level: "replay", Verdict: Halt},
	}
	control := []Cell{
		{Reader: "wb", Family: "wb", Kind: "pipeline", Level: "replay", Verdict: Conform},
		{Reader: "etl", Family: "etl", Kind: "pipeline", Level: "replay", Verdict: WrongFact},
		{Reader: "base", Family: "base", Kind: "pipeline", Level: "replay", Verdict: Conform},
	}
	got := byReader(must(Judge(m, cells, control)))
	if got["wb"] != OrderDependent || got["etl"] != Inherited || got["base"] != Halt {
		t.Errorf("got %v", got)
	}
}

func TestConsensusAndProtocolRule(t *testing.T) {
	m := mutant(ClassValid, true, "text-bytes")
	cells := []Cell{
		l0("js@17", "js", "sdk", RefusesValid, false, ""),
		l0("go@9", "go", "sdk", RefusesValid, false, ""),
		l0("js@16", "js", "sdk", NA, false, ""),
	}
	if got := byReader(must(Judge(m, cells, nil))); got["js@17"] != OracleQuestion || got["go@9"] != OracleQuestion {
		t.Errorf("unanimous refusal without stellar-core: %v", got)
	}
	// stellar-core sides with the oracle: the SDKs share a mistake, reported apart.
	withCore := append([]Cell{l0("core@30", "core", "core", Conform, true, "")}, cells...)
	if got := byReader(must(Judge(m, withCore, nil))); got["js@17"] != ReaderConsensus || got["go@9"] != ReaderConsensus || got["core@30"] != Reference {
		t.Errorf("unanimous refusal against stellar-core: %v", got)
	}
	// stellar-core sides with the SDKs: the oracle is the odd one out.
	coreRefuses := l0("core@30", "core", "core", Conform, false, "")
	coreRefuses.Refused = true
	withCore[0] = coreRefuses
	if got := byReader(must(Judge(m, withCore, nil))); got["js@17"] != OracleQuestion || got["go@9"] != OracleQuestion {
		t.Errorf("unanimous refusal with stellar-core: %v", got)
	}
	cells = append(cells, l0("rs@30", "rust", "sdk", Conform, true, "aa"))
	if got := byReader(must(Judge(m, cells, nil))); got["js@17"] != RefusesValid {
		t.Errorf("a split refusal is judged: %v", got)
	}
	m.ProtocolRule = "an asset code must be alphanumeric"
	if got := byReader(must(Judge(m, cells, nil))); got["js@17"] != Refused || got["rs@30"] != Conform {
		t.Errorf("protocol rule: %v", got)
	}
}

func TestOwnFaultsAreReported(t *testing.T) {
	m := mutant(ClassValid, true, "int-edge")
	_, own := Judge(m, []Cell{{Reader: "go@9", Kind: "sdk", Level: "L0", OwnFault: "driver protocol error: x"}}, nil)
	if len(own) != 1 || !strings.Contains(own[0], "driver protocol error") {
		t.Errorf("own faults: %v", own)
	}
}

func TestMappings(t *testing.T) {
	cases := map[[3]string]string{
		{"mishandled", "halt", ""}:        Halt,
		{"mishandled", "halt", "refusal"}: Refused,
		{"mishandled", "wrong_value", ""}: WrongFact,
		{"dropped", "partial", ""}:        WrongFact,
		{"dropped", "refused", ""}:        RefusesValid,
		{"pass", "", ""}:                  Conform,
		{"not_applicable", "", ""}:        NA,
		{"flaky", "", ""}:                 Flaky,
		{"harness_fault", "", ""}:         "unclassified:harness_fault·",
	}
	for in, want := range cases {
		if got := FromReplay(in[0], in[1], in[2] != ""); got != want {
			t.Errorf("FromReplay%v = %s, want %s", in, got, want)
		}
	}
	for in, want := range map[string]string{"crash": Halt, "diverge": WrongFact, "reject_valid": RefusesValid, "accepts_invalid": AcceptsInvalid} {
		if got := FromConform(in); got != want {
			t.Errorf("FromConform(%s) = %s", in, got)
		}
	}
}

func TestRules(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "findings", "F-0001"), 0o755)
	os.WriteFile(filepath.Join(dir, "findings", "F-0001", "finding.json"), []byte("{}"), 0o644)
	good := filepath.Join(dir, "rules.json")
	os.WriteFile(good, []byte(`{"rules":[{"reader":"rust@*","mutator":"bool-2","finding":"F-0001","note":"n"}]}`), 0o644)
	rs, err := LoadRules(good, filepath.Join(dir, "findings"))
	if err != nil {
		t.Fatal(err)
	}
	s := Signature{Reader: "rust@30.0.0:limits-none", Verdict: Split, Mutator: "bool-2", XDRType: "ScVal", TypePath: "/b"}
	if rs.Match(s) == nil {
		t.Error("rule does not match")
	}
	s.Reader = "go@v0.9.0"
	if rs.Match(s) != nil {
		t.Error("rule matches another reader")
	}
	bad := filepath.Join(dir, "bad.json")
	os.WriteFile(bad, []byte(`{"rules":[{"reader":"*","finding":"F-9999"}]}`), 0o644)
	if _, err := LoadRules(bad, filepath.Join(dir, "findings")); err == nil {
		t.Error("a rule citing a missing finding loaded")
	}
	if err := WriteCandidates(filepath.Join(dir, "in"), dir, nil); err == nil {
		t.Error("candidates written inside the repository root")
	}
}

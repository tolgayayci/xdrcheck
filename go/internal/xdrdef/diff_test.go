package xdrdef

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func fixtureDiff(t *testing.T, baseF, headF string) *Report {
	t.Helper()
	base, err := LoadInput("testdata/diff/base", nil, "")
	if err != nil {
		t.Fatal(err)
	}
	head, err := LoadInput("testdata/diff/head", nil, "")
	if err != nil {
		t.Fatal(err)
	}
	r, err := DiffInputs(base, head, baseF, headF, DiffOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func find(r *Report, kind, def, member string) *Change {
	for i, c := range r.Changes {
		if c.Kind == kind && c.Def == def && c.Member == member {
			return &r.Changes[i]
		}
	}
	return nil
}

// TestDiffEveryChangeKind checks the fixture pair, which makes one change of every kind, is reported with
// the right kind, gate, CAP and reader reach.
func TestDiffEveryChangeKind(t *testing.T) {
	r := fixtureDiff(t, "none", "all")
	both := []string{"LedgerCloseMetaBatch", "TransactionEnvelope"}
	lcm := []string{"LedgerCloseMetaBatch"}
	cases := []struct {
		kind, def, member string
		old, new          string
		gates, caps       []string
		reach             []string
	}{
		{"const-changed", "LIMIT", "", "10", "20", nil, nil, nil},
		{"typedef-optional-changed", "OptHash", "", "Hash*", "Hash", nil, nil, both},
		{"typedef-size-changed", "Blob", "", "opaque<64>", "opaque<128>", nil, nil, both},
		{"typedef-type-changed", "Alias", "", "int", "hyper", nil, nil, both},
		{"enum-member-added", "Color", "YELLOW", "", "3", []string{"CAP_0099_YELLOW"}, []string{"CAP-0099"}, both},
		{"enum-member-removed", "Color", "BLUE", "2", "", nil, nil, both},
		{"enum-value-changed", "Color", "GREEN", "1", "5", nil, nil, both},
		{"type-removed", "Removed", "", "struct { int x }", "", nil, nil, nil},
		{"kind-changed", "Shape", "", "struct", "union", nil, nil, nil},
		{"field-optional-changed", "Account", "sponsor", "Hash*", "Hash", nil, nil, both},
		{"field-size-changed", "Account", "name", "string<MAX_NAME>", "string<64>", nil, nil, both},
		{"field-type-changed", "Account", "balance", "int32", "int64", nil, nil, both},
		{"field-removed", "Account", "legacy", "int32", "", nil, nil, both},
		{"field-added", "Account", "flags", "", "uint32", []string{"CAP_0097_FLAGS"}, []string{"CAP-0097"}, both},
		{"fields-reordered", "Account", "", "id, sponsor, name, balance, first, second, blob", "id, sponsor, name, balance, second, first, blob", nil, nil, both},
		{"arm-added", "Ext", "v1", "", "ExtV1 v1", []string{"MS_CLOSE_TIME"}, []string{"CAP-0088"}, lcm},
		{"type-added", "ExtV1", "", "", "struct { int64 extra; Hash* note }", []string{"MS_CLOSE_TIME"}, []string{"CAP-0088"}, lcm},
		{"arm-changed", "Body", "GREEN", "Hash g", "int64 g", nil, nil, both},
		{"arm-removed", "Body", "BLUE", "void", "", nil, nil, both},
		{"arm-added", "Body", "YELLOW", "", "BodyYellow yellow", []string{"CAP_0099_YELLOW"}, []string{"CAP-0099"}, both},
		{"type-added", "BodyYellow", "", "", "struct { int32 shade; Hash* tint }", []string{"CAP_0099_YELLOW"}, []string{"CAP-0099"}, both},
		{"discriminant-changed", "Disc", "t", "int32", "uint32", nil, nil, nil},
		{"arm-added", "LedgerCloseMeta", "v1", "", "LedgerCloseMetaV1 v1", []string{"CAP_0098_LCM"}, []string{"CAP-0098"}, lcm},
		// Ungated, but only the gated LedgerCloseMeta v1 arm refers to it: it inherits that gate.
		{"type-added", "LedgerCloseMetaV1", "", "", "struct { TransactionEnvelope tx }", []string{"CAP_0098_LCM"}, []string{"CAP-0098"}, lcm},
		{"field-removed", "Unreached", "r", "Removed", "", nil, nil, nil},
	}
	for _, tc := range cases {
		c := find(r, tc.kind, tc.def, tc.member)
		if c == nil {
			t.Errorf("missing %s %s %s", tc.kind, tc.def, tc.member)
			continue
		}
		if c.Old != tc.old || c.New != tc.new {
			t.Errorf("%s %s %s: old %q new %q, want %q %q", tc.kind, tc.def, tc.member, c.Old, c.New, tc.old, tc.new)
		}
		if !reflect.DeepEqual(nilIfEmpty(c.Gates), tc.gates) || !reflect.DeepEqual(nilIfEmpty(c.CAPs), tc.caps) || !reflect.DeepEqual(nilIfEmpty(c.Reach), tc.reach) {
			t.Errorf("%s %s %s: gates %v caps %v reach %v, want %v %v %v", tc.kind, tc.def, tc.member, c.Gates, c.CAPs, c.Reach, tc.gates, tc.caps, tc.reach)
		}
	}
	if len(r.Changes) != len(cases) {
		for _, c := range r.Changes {
			t.Logf("got %s %s %s", c.Kind, c.Def, c.Member)
		}
		t.Errorf("%d changes, want %d", len(r.Changes), len(cases))
	}
	wantNew := []string{"Body::YELLOW", "BodyYellow.tint?none", "BodyYellow.tint?some", "Ext::v1", "ExtV1.note?none", "ExtV1.note?some", "LedgerCloseMeta::v1"}
	var got []string
	for _, a := range r.NewArms["LedgerCloseMetaBatch"] {
		got = append(got, a.ID)
		if a.ID == "Ext::v1" && (len(a.CAPs) != 1 || a.CAPs[0] != "CAP-0088" || a.Class != "in-ledger") {
			t.Errorf("Ext::v1: %+v", a)
		}
	}
	if !reflect.DeepEqual(got, wantNew) {
		t.Errorf("new arms %v, want %v", got, wantNew)
	}
	wantRemoved := []string{"Account.sponsor?none", "Account.sponsor?some", "Body::BLUE", "TransactionEnvelope.memoHash?none", "TransactionEnvelope.memoHash?some"}
	if !reflect.DeepEqual(r.RemovedArms["LedgerCloseMetaBatch"], wantRemoved) {
		t.Errorf("removed arms %v, want %v", r.RemovedArms["LedgerCloseMetaBatch"], wantRemoved)
	}
	if r.CAPGates["MS_CLOSE_TIME"] != "CAP-0088" || r.CAPGates["CAP_0098_LCM"] != "CAP-0098" {
		t.Errorf("cap gates %v", r.CAPGates)
	}
	// The JSON report round-trips and the Markdown names every CAP section.
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var back Report
	if err := json.Unmarshal(b, &back); err != nil || back.Schema != DiffSchema || len(back.Changes) != len(r.Changes) {
		t.Fatalf("json round trip: %v", err)
	}
	var md bytes.Buffer
	r.WriteMarkdown(&md, "")
	for _, s := range []string{"### CAP-0088", "### CAP-0097", "### CAP-0098", "### CAP-0099", "### Not mapped to a CAP", "`Ext::v1`"} {
		if !strings.Contains(md.String(), s) {
			t.Errorf("markdown lacks %q", s)
		}
	}
}

func nilIfEmpty(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s
}

// TestDiffFeatureSelection: with no feature on the head, the gated elements are absent and the #else branch
// is present; a set diffed with itself is empty.
func TestDiffFeatureSelection(t *testing.T) {
	r := fixtureDiff(t, "none", "none")
	if c := find(r, "field-added", "Account", "oldFlags"); c == nil || !reflect.DeepEqual(c.Gates, []string{"CAP_0097_FLAGS"}) {
		t.Errorf("oldFlags (the #else branch) not reported with its gate: %+v", c)
	}
	for _, c := range r.Changes {
		if c.Member == "YELLOW" || c.Member == "flags" || c.Def == "LedgerCloseMetaV1" && c.Kind != "type-added" {
			t.Errorf("gated element present without its feature: %+v", c)
		}
	}
	r = fixtureDiff(t, "none", "CAP_0099_YELLOW")
	if find(r, "arm-added", "Body", "YELLOW") == nil || find(r, "arm-added", "Ext", "v1") != nil {
		t.Errorf("a feature list enables only the listed features")
	}
	head, _ := LoadInput("testdata/diff/head", nil, "")
	same, err := DiffInputs(head, head, "all", "all", DiffOptions{})
	if err != nil || !same.Empty() {
		t.Errorf("self diff not empty: %v %+v", err, same.Changes)
	}
}

func TestLexConditions(t *testing.T) {
	src := `
#ifdef A
struct X { int a; };
#else
struct X { hyper a; };
#endif
#ifndef B
struct Y {
    int y;
#ifdef C
    int z;
#endif
};
#endif
enum E {
    E0 = 0
#ifdef A
    , E1 = 1
#endif
};`
	defs, err := ParseFile("t.x", src)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSet(defs)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Features(); !reflect.DeepEqual(got, []string{"A", "B", "C"}) {
		t.Errorf("features %v", got)
	}
	none := s.Resolve(map[string]bool{})
	if x := none.Get("X"); x == nil || x.Fields[0].Type.Kind != "hyper" {
		t.Errorf("without A, X is the #else one: %+v", x)
	}
	if y := none.Get("Y"); y == nil || len(y.Fields) != 1 {
		t.Errorf("without B and C, Y has one field: %+v", y)
	}
	if m, _ := none.EnumMax("E"); m != 0 {
		t.Errorf("without A, E's max is 0")
	}
	all := s.Resolve(s.EnableAll())
	if all.Get("Y") != nil {
		t.Errorf("with B, the #ifndef B block is gone")
	}
	if x := all.Get("X"); x == nil || x.Fields[0].Type.Kind != "int" {
		t.Errorf("with A, X is the #ifdef one")
	}
	if m, _ := all.EnumMax("E"); m != 1 {
		t.Errorf("with A, E's max is 1")
	}
	for _, bad := range []string{"#ifdef A\nconst X = 1;", "#endif", "#if A\n#endif", "struct X { int a; "} {
		if _, err := ParseFile("bad.x", bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

func TestCAPOfGate(t *testing.T) {
	for g, want := range map[string]string{
		"CAP_0084_MUXED_CONTRACT": "CAP-0084", "CAP_0071": "CAP-0071", "CAP_0083": "CAP-0083",
		"CAP_0085_EXECUTABLE_REF": "CAP-0085", "MS_CLOSE_TIME": "CAP-0088", "TEST_FEATURE": "", "CAPITAL": "",
	} {
		if got := CAPOfGate(g); got != want {
			t.Errorf("%s: %q, want %q", g, got, want)
		}
	}
}

func TestUpperCamel(t *testing.T) {
	for in, want := range map[string]string{"v0": "V0", "ext": "Ext", "signedMsValue": "SignedMsValue", "nodeID": "NodeId",
		"constantProduct": "ConstantProduct", "fee_bump": "FeeBump", "IPv4": "IPv4"} {
		if got := upperCamel(in); got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
}

package verdict

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tolgayayci/xdrcheck/go/internal/conform"
	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
)

// Each test here feeds the engine a doctored driver answer that used to be scored as a pass and must not be.

// probes returns a describe with these probes and the protocol a driver reports for them: 30, or 29 when a
// Protocol 30 probe fails.
func probes(m map[string]bool) *conform.Describe {
	p := 30
	for _, ok := range m {
		if !ok {
			p = 29
		}
	}
	return &conform.Describe{XDRSchema: &conform.XDRSchema{Protocol: &p, Probes: m}}
}

// signedMsEntry builds a Protocol 30 ledger entry; requires nil means the variant has no `requires` field.
func signedMsEntry(requires *[]string, negative bool) *manifest.Entry {
	var req []string
	if requires != nil {
		req = append([]string{}, *requires...)
	}
	e := &manifest.Entry{ID: "cap-0088/first-ledger-with-signed-ms", Kind: "ledger", Negative: negative, Protocol: manifest.ProtocolRange{Introduced: 30}}
	e.Variants = []*manifest.Variant{{Network: "testnet", Protocol: 30, XDRType: "LedgerCloseMeta", Requires: req,
		Blob: manifest.Blob{SHA256: strings.Repeat("2", 64), Bytes: 10}}}
	return e
}

// Ruling 3e (2): reach is decided by the variant's required features against the describe probes; the
// protocol rule is the fallback only when the variant has no `requires`.
func TestReachByFeature(t *testing.T) {
	signed := []string{"stellar_value_signed_ms"}
	none := []string{}
	old := probes(map[string]bool{"stellar_value_signed_ms": false, "sc_address_type_muxed_contract": false})
	partial := probes(map[string]bool{"stellar_value_signed_ms": true, "sc_address_type_muxed_contract": false})
	cases := []struct {
		name string
		req  *[]string
		d    *conform.Describe
		want bool
	}{
		{"feature probe false", &signed, old, true},
		{"feature probe true, another probe false", &signed, partial, false},
		{"no feature required, protocol above the schema", &none, old, false},
		{"no requires field: protocol fallback", nil, old, true},
		{"feature without a probe is assumed present", &[]string{"some_future_feature"}, old, false},
	}
	for _, c := range cases {
		o := obs(signedMsEntry(c.req, false), col("js", "17.2.0", ""), "L0", "reject", "union_arm_undeclared", "")
		o.Describe = c.d
		if got, _ := outOfReach(o); got != c.want {
			t.Errorf("%s: out of reach %v, want %v", c.name, got, c.want)
		}
	}
}

// Ruling 3e (3)–(5): beyond reach only a clean refusal is expected.
func TestOutOfReachRules(t *testing.T) {
	signed := []string{"stellar_value_signed_ms"}
	old := probes(map[string]bool{"stellar_value_signed_ms": false, "sc_address_type_muxed_contract": false})
	pos := signedMsEntry(&signed, false)
	neg := signedMsEntry(&signed, true)
	at := func(o *conform.Observation) *conform.Observation { o.Describe = old; return o }
	l0 := `{"consumed_bytes":10,"reencoded_sha256":"` + strings.Repeat("2", 64) + `"}`
	l0ok := at(obs(pos, col("js", "17.2.0", ""), "L0", "ok", "", l0))
	l0ok.Judgement = &conform.Judgement{Verdict: "conform", Check: "conform"}
	l1AfterOK := at(obs(pos, col("js", "17.2.0", ""), "L1", "reject", "union_arm_undeclared", ""))
	l1AfterOK.L0 = l0ok
	run(t, []row{
		{"clean refusal: n_a", at(obs(pos, col("js", "17.2.0", ""), "L0", "reject", "enum_undeclared", "")), "n_a", "n_a", ""},
		{"refusal for another reason: failure", at(obs(pos, col("js", "17.2.0", ""), "L0", "reject", "length_exceeds_max", "")), "reject_valid", "undeclared", ""},
		{"go decode_error is not a clean refusal", at(obs(pos, col("go", "v0.7.1", ""), "L0", "reject", "decode_error", "")), "reject_valid", "undeclared", ""},
		{"rust decode_error is accepted", at(obs(pos, col("rust", "28.0.1", "limits-default"), "L0", "reject", "decode_error", "")), "n_a", "n_a", ""},
		{"crash: undeclared", at(obs(pos, col("js", "17.2.0", ""), "L0", "crash", "process_died", "")), "crash", "undeclared", ""},
		{"ok judged normally", at(obs(pos, col("js", "17.2.0", ""), "L0", "ok", "", l0)), "conform", "conform", ""},
		{"ok with wrong bytes judged normally", at(obs(pos, col("js", "17.2.0", ""), "L0", "ok", "", strings.Replace(l0, "2222", "3333", 1))), "diverge", "undeclared", ""},
		{"L1 refusal after L0 accepted: failure", l1AfterOK, "reject_valid", "undeclared", ""},
		{"negative entry beyond reach: n_a, not conform", at(obs(neg, col("js", "17.2.0", ""), "L0", "reject", "bool_range", "")), "n_a", "n_a", ""},
	})
	// A strkey form the SDK does not know is refused cleanly for its version byte; any other refusal fails.
	w := &manifest.Entry{ID: "strkey/sep-0023-v1.4.0-vectors.valid-09", Kind: "strkey", Protocol: manifest.ProtocolRange{Introduced: 30},
		Strkey: &manifest.StrkeyVector{Text: "WA7Q", Type: "muxed_contract", PayloadHex: "00"}}
	run(t, []row{
		{"strkey: unknown version byte beyond reach", at(obs(w, col("go", "v0.7.1", ""), "L4", "reject", "strkey_version", "")), "n_a", "n_a", ""},
		{"strkey: checksum refusal beyond reach", at(obs(w, col("go", "v0.7.1", ""), "L4", "reject", "strkey_checksum", "")), "reject_valid", "undeclared", ""},
	})
}

// The level cascade: L1 and L2 of a variant whose L0 cell is known, or refused beyond reach, are n_a.
func TestLevelCascade(t *testing.T) {
	e := signedMsEntry(nil, false)
	e.Conformance = &manifest.Conformance{KnownDivergences: []manifest.KnownDivergence{kd(goTarget, "0.7.1 - 0.7.3", "L0", "reject")}}
	c := col("go", "v0.7.1", "")
	res := &conform.Result{Observations: []*conform.Observation{
		obs(e, c, "L0", "reject", "union_arm_undeclared", ""),
		obs(e, c, "L1", "reject", "union_arm_undeclared", ""),
		obs(e, c, "L2", "reject", "union_arm_undeclared", ""),
	}}
	for _, o := range res.Observations {
		o.Describe = describe(30) // in reach: the L0 refusal is the known divergence
	}
	res.Apply(Engine{})
	if j := res.Observations[0].Judgement; j.Check != "known" {
		t.Fatalf("L0: %+v", j)
	}
	for _, o := range res.Observations[1:] {
		a := Engine{}.Assess(o)
		if a.Verdict != "n_a" || a.Check != "n_a" || !a.BlockedByL0 {
			t.Errorf("%s: %+v, want n_a blocked by L0", o.Cell.Level, a)
		}
	}
	// Refused at L0 beyond reach.
	res = &conform.Result{Observations: []*conform.Observation{
		obs(e, col("js", "17.2.0", ""), "L0", "reject", "union_arm_undeclared", ""),
		obs(e, col("js", "17.2.0", ""), "L1", "reject", "union_arm_undeclared", ""),
	}}
	res.Apply(Engine{})
	if j := res.Observations[1].Judgement; j.Verdict != "n_a" || j.Check != "n_a" {
		t.Errorf("L1 after an out-of-reach L0 refusal: %+v", j)
	}
	m := matrix(t, res.Observations)
	if !m.Cells[1].BlockedByL0 || Label(&m.Cells[1]) != "n/a (L0)" {
		t.Errorf("matrix cell %+v", m.Cells[1])
	}
}

// Exact or refuse: expect_reject with an exact result accepts a refusal or exactly that result.
func TestExactOrRefuse(t *testing.T) {
	e := apiEntry("classic/api-offer-id-encoding.id-2-pow-53-plus-1-string", "offer.manage_sell", false, `"9007199254740993"`)
	e.API.ExpectReject = true
	run(t, []row{
		{"refusal conforms", obs(e, col("js", "17.3.0", ""), "L4", "reject", "value_out_of_range", ""), "conform", "conform", ""},
		{"exact value conforms", obs(e, col("js", "17.3.0", ""), "L4", "ok", "", apiValue(`"9007199254740993"`)), "conform", "conform", ""},
		{"another value does not", obs(e, col("js", "17.2.1", ""), "L4", "ok", "", apiValue(`"9007199254740992"`)), "diverge", "undeclared", ""},
	})
	if a := (Engine{}).Assess(obs(e, col("js", "17.3.0", ""), "L4", "ok", "", apiValue(`"9007199254740993"`))); a.Expected != "exact-or-refuse" {
		t.Errorf("expected %q", a.Expected)
	}
	plain := apiEntry("classic/api-offer-id-encoding.id-negative", "offer.manage_sell", true, "")
	run(t, []row{{"plain refuse: any acceptance is accepts_invalid", obs(plain, col("js", "17.2.1", ""), "L4", "ok", "", apiValue(`"-5"`)), "accepts_invalid", "undeclared", ""}})
}

// The validity decides what must be refused: malformed and invalid must be refused, acceptable is exact or
// refuse, and a variant's own validity overrides its entry's. Without one, the negative flag and expectations do.
func TestValidityDecidesRefusal(t *testing.T) {
	e := apiEntry("classic/api-offer-id-encoding.id-2-pow-53-plus-1-string", "offer.manage_sell", false, `"9007199254740993"`)
	for _, c := range []struct {
		entry, variant         string
		refuse, exact, negativ bool
	}{
		{"valid", "", false, false, false},
		{"malformed", "", true, false, true},
		{"invalid", "", true, false, true},
		{"acceptable", "", true, true, false},
		{"valid", "malformed", true, false, true},
		{"malformed", "valid", false, false, false},
		{"", "", false, false, false}, // no validity: the entry's negative flag and expect_reject (both false here)
	} {
		e.Validity = c.entry
		v := &manifest.Variant{Validity: c.variant}
		if MustRefuse(e, v) != c.refuse || ExactOrRefuse(e, v) != c.exact || Negative(e, v) != c.negativ {
			t.Errorf("entry %q variant %q: refuse %v exact %v negative %v", c.entry, c.variant, MustRefuse(e, v), ExactOrRefuse(e, v), Negative(e, v))
		}
	}
	// Validity acceptable makes an api entry exact-or-refuse even without expect_reject.
	e.Validity = "acceptable"
	run(t, []row{
		{"acceptable: refusal conforms", obs(e, col("js", "17.3.0", ""), "L4", "reject", "value_out_of_range", ""), "conform", "conform", ""},
		{"acceptable: exact value conforms", obs(e, col("js", "17.3.0", ""), "L4", "ok", "", apiValue(`"9007199254740993"`)), "conform", "conform", ""},
		{"acceptable: another value diverges", obs(e, col("js", "17.3.0", ""), "L4", "ok", "", apiValue(`"9007199254740992"`)), "diverge", "undeclared", ""},
	})
	e.Validity = "valid"
	run(t, []row{{"valid: a refusal is reject_valid", obs(e, col("js", "17.3.0", ""), "L4", "reject", "value_out_of_range", ""), "reject_valid", "undeclared", ""}})
}

// A known divergence matches on its declared detail, not only on the outcome class.
func TestDivergenceDetail(t *testing.T) {
	c, err := manifest.Load(filepath.Join(repoRoot(), "corpus"), manifest.Options{SkipBlobCheck: true})
	if err != nil {
		t.Fatal(err)
	}
	e := c.Entry("cap-0038/pool-issuers-order-by-bytes-not-strkey")
	v := e.Variants[0]
	_, rejected := ledgerL1(t, v)
	js := col("js", "17.2.0", "")
	// Another envelope refused instead of the focus transaction: the class matches, the divergence does not.
	other := strings.Replace(rejected, `"tx_index":2`, `"tx_index":5`, 1)
	other = strings.Replace(other, `"tx_hash":"`+focusTx+`"`, `"tx_hash":"`+strings.Repeat("5", 64)+`"`, 1)
	run(t, []row{
		{"focus transaction rejected: known", obs(e, js, "L1", "reject", "ordering", rejected), "reject_valid", "known", "reject"},
		{"another envelope rejected: known-changed", obs(e, js, "L1", "reject", "ordering", other), "reject_valid", "known-changed", "reject"},
	})
	// Declared detail: reason, envelopes parsed, rejected envelope.
	declared := *e
	declared.Conformance = &manifest.Conformance{KnownDivergences: append([]manifest.KnownDivergence(nil), e.Conformance.KnownDivergences...)}
	k := &declared.Conformance.KnownDivergences[0]
	eighteen, two := 18, 2
	k.Match = &manifest.DivergenceMatch{Reason: "ordering", EnvelopesParsed: &eighteen, RejectedTxIndex: &two}
	run(t, []row{
		{"declared detail observed", obs(&declared, js, "L1", "reject", "ordering", rejected), "reject_valid", "known", "reject"},
		{"declared reason differs", obs(&declared, js, "L1", "reject", "object_validation", rejected), "reject_valid", "known-changed", "reject"},
		{"declared envelopes_parsed differs", obs(&declared, js, "L1", "reject", "ordering", strings.Replace(rejected, `"envelopes_parsed":18`, `"envelopes_parsed":17`, 1)), "reject_valid", "known-changed", "reject"},
	})
}

// An unparsable version range fails the run instead of silently asserting nothing.
func TestUnparsableRange(t *testing.T) {
	e := apiEntry("cap-0038/api-liquidity-pool-issuer-ordering.network-order", "liquidity_pool.id", false, `"`+poolNetwork+`"`,
		kd(jsTarget, ">=17.0.0 <17.2.1 ||| nonsense", "L4", "reject"))
	err := CheckRanges([]*manifest.Entry{e})
	if err == nil || !strings.Contains(err.Error(), e.ID) {
		t.Fatalf("CheckRanges: %v", err)
	}
	if _, err := Applicable(e, col("js", "17.2.0", ""), "L4", ""); err == nil {
		t.Error("Applicable accepted an unparsable range")
	}
	// Replay divergences carry commit ranges and are not conformance ranges.
	wb := apiEntry("cap-0040/x", "liquidity_pool.id", false, "", kd("stellar/wallet-backend", "..79ea2acd", "replay", "dropped"))
	if err := CheckRanges([]*manifest.Entry{wb}); err != nil {
		t.Errorf("replay range: %v", err)
	}
}

// notExercised lists an in-range divergence whose cells are all n_a.
func TestNotExercisedAllNA(t *testing.T) {
	e := apiEntry("cap-0027/api-muxed-account-id-encoding.id-2-pow-64", "muxed_account.encode", true, "", kd(goTarget, "<0.9.0", "L4", "accepts_invalid"))
	m := matrix(t, []*conform.Observation{obs(e, col("go", "v0.8.0", ""), "L4", "n_a", "value_not_representable", "")})
	if len(m.NotExercised) != 1 || m.NotExercised[0].Why != AllCellsNA {
		t.Errorf("not exercised %+v", m.NotExercised)
	}
	m = matrix(t, []*conform.Observation{obs(e, col("go", "v0.8.0", ""), "L4", "ok", "", apiValue(`"M"`))})
	if len(m.NotExercised) != 0 {
		t.Errorf("a judged in-range cell: %+v", m.NotExercised)
	}
}

// The cross-SDK fingerprint compares canonical facts: key order, number spelling, hex case and pinpoint order
// do not split classes; a different value does.
func TestFingerprint(t *testing.T) {
	e := apiEntry("x/api", "transaction.parse", false, "")
	a := obs(e, col("js", "17.4.0", ""), "L4", "ok", "", `{"api":{"value":{"tx_hash":"AB12","operations":1},"xdr_hex":"00","self_decode":"accepted"}}`)
	b := obs(e, col("go", "v0.8.0", ""), "L4", "ok", "", `{"api":{"xdr_hex":"00","value":{"operations":1,"tx_hash":"ab12"}}}`)
	c := obs(e, col("go", "v0.8.0", ""), "L4", "ok", "", `{"api":{"xdr_hex":"00","value":{"operations":2,"tx_hash":"ab12"}}}`)
	if fingerprint(a) != fingerprint(b) || fingerprint(a) == fingerprint(c) {
		t.Errorf("L4 fingerprints %q %q %q", fingerprint(a), fingerprint(b), fingerprint(c))
	}
	x := &manifest.Entry{ID: "x/xdr", Kind: "xdr", Variants: []*manifest.Variant{{Network: "none", XDRType: "ScVal"}}}
	p1 := obs(x, col("js", "17.4.0", ""), "L2", "ok", "", `{"pinpoints":[{"path":"/b","found":true,"value":"10"},{"path":"/a","found":true,"value":1}]}`)
	p2 := obs(x, col("rust", "30.0.0", ""), "L2", "ok", "", `{"pinpoints":[{"path":"/a","found":true,"value":"1"},{"path":"/b","found":true,"value":10}]}`)
	if fingerprint(p1) != fingerprint(p2) {
		t.Errorf("L2 fingerprints %q %q", fingerprint(p1), fingerprint(p2))
	}
	// L1: only the derived keys the manifest states are comparable; one driver reporting more does not split.
	l := signedMsEntry(nil, false)
	l.Variants[0].Derived = map[string]any{"l1": map[string]any{"asset": "native"}}
	f1 := obs(l, col("js", "17.4.0", ""), "L1", "ok", "", `{"object":{"transactions":1,"envelopes_parsed":1,"operations":2,"tx_hashes":["aa"],"focus":{"tx_hash":"aa","operation_types":["payment"],"derived":{"memo_type":"none","asset":"native"}}}}`)
	f2 := obs(l, col("go", "v0.8.0", ""), "L1", "ok", "", `{"object":{"operations":2,"tx_hashes":["AA"],"transactions":1,"envelopes_parsed":1,"focus":{"derived":{"asset":"native"},"operation_types":["payment","x"],"tx_hash":"aa"}}}`)
	f3 := obs(l, col("go", "v0.8.0", ""), "L1", "ok", "", `{"object":{"operations":2,"tx_hashes":["aa"],"transactions":1,"envelopes_parsed":1,"focus":{"derived":{"asset":"USD:G"},"operation_types":["payment"],"tx_hash":"aa"}}}`)
	if fingerprint(f1) != fingerprint(f2) || fingerprint(f1) == fingerprint(f3) {
		t.Errorf("L1 fingerprints %q %q %q", fingerprint(f1), fingerprint(f2), fingerprint(f3))
	}
}

// canon never rewrites digits: integers are compared by value only where the manifest states an integer.
func TestCanonIntegers(t *testing.T) {
	for _, c := range []struct {
		got, want any
		eq        bool
	}{
		{"10", json.Number("10"), true},
		{json.Number("10"), "10", true},
		{"0010", "10", false},
		{"0010", json.Number("10"), false},
		{"+10", json.Number("10"), false},
		{"+10", "10", false},
		{json.Number("10.0"), json.Number("10"), false},
		{"abcd", "ABCD", true},
		{"0a", "0A", true},
		{[]any{"1", "2"}, []any{json.Number("1"), json.Number("2")}, true},
		{map[string]any{"a": "x"}, map[string]any{"a": "x", "b": "y"}, false},
	} {
		if got := equalValues(c.got, c.want); got != c.eq {
			t.Errorf("equalValues(%#v, %#v) = %v", c.got, c.want, got)
		}
	}
	if canon("0010") != "0010" || canon("+10") != "+10" || canon(json.Number("010")) == "10" {
		t.Errorf("canon rewrote digits: %v %v %v", canon("0010"), canon("+10"), canon(json.Number("010")))
	}
}

// L1 derived facts are compared only against variants[].derived.l1, and a stated key must agree.
func TestDerivedL1(t *testing.T) {
	l := signedMsEntry(nil, false)
	l.Variants[0].Derived = map[string]any{"tx_hash": strings.Repeat("a", 64), "l1": map[string]any{"pool_id": poolNetwork, "operation_type": "change_trust"}}
	l.Variants[0].Protocol = 29
	body := func(pool string) string {
		return `{"object":{"transactions":1,"envelopes_parsed":1,"operations":1,"tx_hashes":["` + strings.Repeat("a", 64) + `"],"focus":{"tx_hash":"` + strings.Repeat("a", 64) +
			`","operation_types":["change_trust"],"derived":{"operation_type":"change_trust","pool_id":"` + pool + `","memo_type":"none"}}}}`
	}
	run(t, []row{
		{"stated keys agree", obs(l, col("js", "17.4.0", ""), "L1", "ok", "", body(poolNetwork)), "conform", "conform", ""},
		{"stated pool differs", obs(l, col("js", "17.4.0", ""), "L1", "ok", "", body(poolReversed)), "diverge", "undeclared", ""},
	})
	// Without derived.l1 nothing derived is compared (memo_type above is not stated either way).
	l.Variants[0].Derived = map[string]any{"tx_hash": strings.Repeat("a", 64)}
	run(t, []row{{"no derived.l1", obs(l, col("js", "17.4.0", ""), "L1", "ok", "", body(poolReversed)), "conform", "conform", ""}})
}

// The stellar-core column decodes without re-encoding: its L0 evidence is the consumed byte count, which must
// equal the input; it agrees with the SDKs in the cross-SDK table when it accepts.
func TestCoreColumn(t *testing.T) {
	e := signedMsEntry(nil, false)
	core := &conform.Column{ID: "core@30.0.0", SDK: "core", Kind: "core", Target: "stellar-core", Version: "30.0.0", Role: "extra"}
	good := obs(e, core, "L0", "ok", "", `{"consumed_bytes":10}`)
	short := obs(e, core, "L0", "ok", "", `{"consumed_bytes":9}`)
	l2 := obs(e, core, "L2", "n_a", "other", "")
	sdk := obs(e, col("rust", "30.0.0", "limits-default"), "L0", "ok", "", `{"consumed_bytes":10,"reencoded_sha256":"`+strings.Repeat("2", 64)+`"}`)
	for _, o := range []*conform.Observation{good, short, l2, sdk} {
		o.Describe = describe(30)
	}
	run(t, []row{
		{"core reads the whole input", good, "conform", "conform", ""},
		{"core reads less than the input", short, "diverge", "undeclared", ""},
		{"core L2 n_a/other", l2, "n_a", "n_a", ""},
	})
	m := matrix(t, []*conform.Observation{good, sdk})
	if len(m.CrossSDK) != 1 || !m.CrossSDK[0].Agree {
		t.Errorf("cross-SDK %+v", m.CrossSDK)
	}
}

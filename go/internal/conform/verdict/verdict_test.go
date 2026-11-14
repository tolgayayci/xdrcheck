package verdict

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tolgayayci/xdrcheck/go/internal/conform"
	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
	"github.com/tolgayayci/xdrcheck/go/internal/report"
)

// The table tests feed the engine driver outcomes recorded by the executed SDK probe
// (evidence/sdk-matrix/results/<sdk>_<version>.jsonl), mapped onto corpus entries: the real
// cap-0038 issuer-ordering ledger entry, and in-test entries mirroring the planned api and xdr entries of the
// sdk-regression assertions (pool ID from issuers in network and reversed order, offer and muxed IDs, map-key
// collisions, map sort order). The probe's "wrong" is an acceptance with a value the expectation does not
// hold; the driver reports it as ok with that value and the engine finds the difference.

const (
	poolNetwork  = "c2a730127d006897b021d6fcb279da68b4f65f9b6a408c74eb2cdd85ea862d5e"
	poolReversed = "c1324f878b3d11af9f923abb7d692fc74e0a7bcfd9a4edefd564efe5fdae9fdb"
	focusTx      = "0126748091930959a3aefac9296e1773b947f964a9b73f37ce856c4df32d346f"
	jsTarget     = "@stellar/stellar-sdk"
	goTarget     = "github.com/stellar/go-stellar-sdk"
)

func repoRoot() string {
	wd, _ := os.Getwd()
	return filepath.Clean(filepath.Join(wd, "..", "..", "..", ".."))
}

func col(sdk, version, profile string) *conform.Column {
	targets := map[string]string{"js": jsTarget, "go": goTarget, "rust": "stellar-xdr (crates.io)", "java": "network.lightsail:stellar-sdk (Maven)", "python": "stellar-sdk (PyPI)"}
	id := sdk + "@" + version
	if profile != "" {
		id += ":" + profile
	}
	return &conform.Column{ID: id, SDK: sdk, Kind: "sdk", Target: targets[sdk], Version: version, Profile: profile, Role: "historical"}
}

// describe returns a describe whose XDR schema reaches the given protocol.
func describe(protocol int) *conform.Describe {
	return &conform.Describe{XDRSchema: &conform.XDRSchema{Protocol: &protocol, Probes: map[string]bool{}}}
}

func kd(target, versions, level, outcome string) manifest.KnownDivergence {
	return manifest.KnownDivergence{Target: target, Versions: versions, Level: level, Outcome: outcome, Reference: "https://example.org/" + outcome, Status: "fixed"}
}

func apiEntry(id, op string, rejects bool, value string, kds ...manifest.KnownDivergence) *manifest.Entry {
	e := &manifest.Entry{ID: id, Kind: "api", Protocol: manifest.ProtocolRange{Introduced: 18}, Negative: rejects,
		API: &manifest.APIVector{Op: op, ExpectReject: rejects}, Conformance: &manifest.Conformance{Levels: []string{"L4"}, KnownDivergences: kds}}
	if value != "" {
		e.API.ExpectValue = json.RawMessage(value)
	}
	return e
}

// obs builds an observation: outcome, reason code, and the actual block as JSON.
func obs(e *manifest.Entry, c *conform.Column, level, outcome, reason, actual string) *conform.Observation {
	o := &conform.Observation{Cell: &conform.Cell{Entry: e, Level: level, Column: c}, Outcome: outcome, Reason: reason,
		Source: "driver", Describe: describe(29)}
	if len(e.Variants) > 0 {
		o.Cell.Variant, o.Cell.VariantKey = e.Variants[0], e.VariantKey(e.Variants[0])
	}
	if outcome == "crash" && reason == "process_died" {
		o.Source, o.Crash = "orchestrator", &conform.Crash{Reason: reason, ExitCode: 134, Signal: "aborted"}
		return o
	}
	raw := `{"outcome":"` + outcome + `"`
	if reason != "" {
		raw += `,"reason":{"code":"` + reason + `"}`
	}
	if actual != "" {
		raw += `,"actual":` + actual
	}
	raw += "}"
	o.Response = &conform.RunResponse{}
	if err := json.Unmarshal([]byte(raw), o.Response); err != nil {
		panic(err)
	}
	return o
}

func apiValue(v string) string { return `{"api":{"value":` + v + `}}` }

type row struct {
	name                  string
	o                     *conform.Observation
	verdict, check, known string // known: the matched divergence's outcome, "" for none
}

func run(t *testing.T, rows []row) {
	t.Helper()
	for _, r := range rows {
		a := Engine{}.Assess(r.o)
		got := ""
		if a.Known != nil {
			got = a.Known.Outcome
		}
		if a.Verdict != r.verdict || a.Check != r.check || got != r.known {
			t.Errorf("%s: verdict %s check %s known %q, want %s %s %q (notes %v)", r.name, a.Verdict, a.Check, got, r.verdict, r.check, r.known, a.Notes)
		}
		j := Engine{}.Judge(r.o)
		if j.Expectation != map[bool]string{true: "unexpected", false: "expected"}[FailingCheck(r.check)] {
			t.Errorf("%s: expectation %s for check %s", r.name, j.Expectation, r.check)
		}
	}
}

// sdk-regression/js-1766 on the real corpus entry: L1 over every envelope of testnet ledger 5521432.
func TestIssuerOrderingLedger(t *testing.T) {
	c, err := manifest.Load(filepath.Join(repoRoot(), "corpus"), manifest.Options{SkipBlobCheck: true})
	if err != nil {
		t.Fatal(err)
	}
	e := c.Entry("cap-0038/pool-issuers-order-by-bytes-not-strkey")
	if e == nil {
		t.Fatal("entry missing")
	}
	v := e.Variants[0]
	parsed, rejected := ledgerL1(t, v)
	l0 := `{"consumed_bytes":` + itoa(v.Blob.Bytes) + `,"reencoded_sha256":"` + v.Blob.SHA256 + `"}`
	run(t, []row{
		// js_17.2.0 1c: reject "Assets are not in lexicographic order" (a1).
		{"js 17.2.0 L1 (1c)", obs(e, col("js", "17.2.0", ""), "L1", "reject", "ordering", rejected), "reject_valid", "known", "reject"},
		// js_17.2.1 1c: ok, hash 01267480…346f among the parsed envelopes (a2).
		{"js 17.2.1 L1 (1c)", obs(e, col("js", "17.2.1", ""), "L1", "ok", "", parsed), "conform", "conform", ""},
		{"js 17.3.0 L1", obs(e, col("js", "17.3.0", ""), "L1", "ok", "", parsed), "conform", "conform", ""},
		// a3: the codec is not where the bug is.
		{"js 17.2.0 L0", obs(e, col("js", "17.2.0", ""), "L0", "ok", "", l0), "conform", "conform", ""},
		// go_v0.7.1 1c: reject "AssetA must be <= AssetB"; v0.7.2 parses it.
		{"go v0.7.1 L1 (1c)", obs(e, col("go", "v0.7.1", ""), "L1", "reject", "ordering", rejected), "reject_valid", "known", "reject"},
		{"go v0.7.2 L1 (1c)", obs(e, col("go", "v0.7.2", ""), "L1", "ok", "", parsed), "conform", "conform", ""},
		// java_6.0.0 and python_17.0.0 1c: reject, declared (<=6.0.0 open; 17.0.0 fixed).
		{"java 6.0.0 L1", obs(e, col("java", "6.0.0", ""), "L1", "reject", "ordering", rejected), "reject_valid", "known", "reject"},
		{"python 17.0.0 L1", obs(e, col("python", "17.0.0", ""), "L1", "reject", "ordering", rejected), "reject_valid", "known", "reject"},
		{"python 17.0.1 L1", obs(e, col("python", "17.0.1", ""), "L1", "ok", "", parsed), "conform", "conform", ""},
		// Breaks: a column outside every range that rejects is undeclared; inside a range, conforming is
		// unexpected-conform and a different failure is known-changed.
		{"go v0.7.3 rejects: undeclared", obs(e, col("go", "v0.7.3", ""), "L1", "reject", "ordering", rejected), "reject_valid", "undeclared", ""},
		{"js 17.2.0 parses: unexpected-conform", obs(e, col("js", "17.2.0", ""), "L1", "ok", "", parsed), "conform", "unexpected-conform", "reject"},
		{"js 17.2.0 crashes: known-changed", obs(e, col("js", "17.2.0", ""), "L1", "crash", "process_died", ""), "crash", "known-changed", "reject"},
		{"js 17.4.0 wrong hash: undeclared", obs(e, col("js", "17.4.0", ""), "L1", "ok", "", strings.Replace(parsed, focusTx, strings.Repeat("0", 64), -1)), "diverge", "undeclared", ""},
		{"js 17.4.0 wrong L0 bytes", obs(e, col("js", "17.4.0", ""), "L0", "ok", "", strings.Replace(l0, v.Blob.SHA256, strings.Repeat("a", 64), 1)), "diverge", "undeclared", ""},
		{"go v0.8.0 L2 pinpoints missing", obs(e, col("go", "v0.8.0", ""), "L2", "ok", "", `{"pinpoints":[]}`), "diverge", "undeclared", ""},
	})
	// The hashes are compared as an ordered list: the right hashes in another order diverge.
	h := derivedList(v, "tx_hashes")
	swapped := strings.Replace(strings.Replace(parsed, h[0], "SWAP", 1), h[1], h[0], 1)
	swapped = strings.Replace(swapped, "SWAP", h[1], 1)
	a := Engine{}.Assess(obs(e, col("js", "17.4.0", ""), "L1", "ok", "", swapped))
	if a.Verdict != "diverge" || !strings.Contains(strings.Join(a.Mismatches, " "), "apply order") {
		t.Errorf("hashes out of apply order: %+v", a)
	}
}

// derivedList is a variant's derived list of strings.
func derivedList(v *manifest.Variant, key string) []string {
	var out []string
	for _, x := range v.Derived[key].([]any) {
		out = append(out, x.(string))
	}
	return out
}

// ledgerL1 builds the L1 facts a driver reports for the issuer-ordering ledger from its manifest: parsed (every
// envelope, the focus transaction's facts) and rejected (the focus transaction refused, the rest parsed).
func ledgerL1(t *testing.T, v *manifest.Variant) (parsed, rejected string) {
	t.Helper()
	hashes := derivedList(v, "tx_hashes")
	focus := *v.Focus.TxIndex
	n := len(hashes)
	ops := *v.Resolved.Ledger.Operations
	q := func(xs []string) string {
		b, _ := json.Marshal(xs)
		return string(b)
	}
	// The focus facts a correct SDK reports: the pool ID and operation type, plus whatever else the manifest
	// states for the variant (derived.l1).
	derived := map[string]any{"operation_type": "change_trust", "pool_id": poolNetwork}
	if l1, ok := v.Derived["l1"].(map[string]any); ok {
		for k, x := range l1 {
			derived[k] = x
		}
	}
	db, _ := json.Marshal(derived)
	parsed = fmt.Sprintf(`{"object":{"transactions":%d,"envelopes_parsed":%d,"operations":%d,"tx_hashes":%s,"focus":{"tx_hash":%q,"operation_types":["change_trust","change_trust","change_trust"],"derived":%s}}}`,
		n, n, ops, q(hashes), hashes[focus], db)
	rest := append(append([]string(nil), hashes[:focus]...), hashes[focus+1:]...)
	rejected = fmt.Sprintf(`{"object":{"transactions":%d,"envelopes_parsed":%d,"tx_hashes":%s,"envelopes_rejected":[{"tx_index":%d,"tx_hash":%q,"code":"ordering"}]}}`,
		n, n-1, q(rest), focus, hashes[focus])
	return parsed, rejected
}

func itoa(n int64) string { b, _ := json.Marshal(n); return string(b) }

// L2 pinpoints: values are compared after canonicalising (64-bit numbers as decimal strings, hex case).
func TestPinpoints(t *testing.T) {
	c, err := manifest.Load(filepath.Join(repoRoot(), "corpus"), manifest.Options{SkipBlobCheck: true})
	if err != nil {
		t.Fatal(err)
	}
	e := c.Entry("cap-0038/pool-issuers-order-by-bytes-not-strkey")
	var pins []string
	for _, v := range e.Variants[0].Resolved.Values {
		b, _ := json.Marshal(v.Equals)
		p, _ := json.Marshal(v.Path)
		pins = append(pins, `{"path":`+string(p)+`,"found":true,"value":`+string(b)+`}`)
	}
	good := `{"pinpoints":[` + strings.Join(pins, ",") + `]}`
	if a := (Engine{}).Assess(obs(e, col("js", "17.4.0", ""), "L2", "ok", "", good)); a.Verdict != "conform" {
		t.Fatalf("pinpoints equal to the manifest: %+v", a)
	}
	last := pins[len(pins)-1]
	bad := strings.Replace(good, last, strings.Replace(last, `"found":true`, `"found":false`, 1), 1)
	if a := (Engine{}).Assess(obs(e, col("js", "17.4.0", ""), "L2", "ok", "", bad)); a.Verdict != "diverge" {
		t.Errorf("a pinpoint not found: %+v", a)
	}
	if !equalValues(json.Number("18446744073709551615"), "18446744073709551615") || !equalValues("ABCD", "abcd") ||
		equalValues("GA7Q", "ga7q") || !equalValues(map[string]any{"a": json.Number("1")}, map[string]any{"a": "1"}) {
		t.Error("canonical comparison")
	}
}

// sdk-regression/js-1766 a4/a5 (probe vectors 1a, 1b) on api entries mirroring the planned ones.
func TestPoolIDFromIssuers(t *testing.T) {
	network := apiEntry("cap-0038/api-liquidity-pool-issuer-ordering.network-order", "liquidity_pool.id", false, `"`+poolNetwork+`"`,
		kd(jsTarget, "<16.3.1 || >=17.0.0 <17.2.1", "L4", "reject"), kd(goTarget, ">=0.7.0 <0.7.2", "L4", "reject"))
	reversed := apiEntry("cap-0038/api-liquidity-pool-issuer-ordering.reversed-order", "liquidity_pool.id", true, "",
		kd(jsTarget, "<16.3.1 || >=17.0.0 <17.2.1", "L4", "accepts_invalid"), kd(goTarget, ">=0.7.0 <0.7.2", "L4", "accepts_invalid"))
	run(t, []row{
		{"1a js 17.2.0 reject", obs(network, col("js", "17.2.0", ""), "L4", "reject", "ordering", ""), "reject_valid", "known", "reject"},
		{"1a js 17.2.1 ok c2a7", obs(network, col("js", "17.2.1", ""), "L4", "ok", "", apiValue(`"`+poolNetwork+`"`)), "conform", "conform", ""},
		{"1a js 17.3.0 ok c2a7", obs(network, col("js", "17.3.0", ""), "L4", "ok", "", apiValue(`"`+poolNetwork+`"`)), "conform", "conform", ""},
		{"1a go v0.7.1 reject", obs(network, col("go", "v0.7.1", ""), "L4", "reject", "ordering", ""), "reject_valid", "known", "reject"},
		{"1a go v0.7.2 ok c2a7", obs(network, col("go", "v0.7.2", ""), "L4", "ok", "", apiValue(`"`+poolNetwork+`"`)), "conform", "conform", ""},
		{"1a js 17.4.0 wrong id", obs(network, col("js", "17.4.0", ""), "L4", "ok", "", apiValue(`"`+poolReversed+`"`)), "diverge", "undeclared", ""},
		{"1b js 17.2.0 ok c132 (wrong)", obs(reversed, col("js", "17.2.0", ""), "L4", "ok", "", apiValue(`"`+poolReversed+`"`)), "accepts_invalid", "known", "accepts_invalid"},
		{"1b js 17.2.1 reject", obs(reversed, col("js", "17.2.1", ""), "L4", "reject", "ordering", ""), "conform", "conform", ""},
		{"1b js 17.3.0 reject", obs(reversed, col("js", "17.3.0", ""), "L4", "reject", "ordering", ""), "conform", "conform", ""},
		{"1b go v0.7.1 ok c132 (wrong)", obs(reversed, col("go", "v0.7.1", ""), "L4", "ok", "", apiValue(`"`+poolReversed+`"`)), "accepts_invalid", "known", "accepts_invalid"},
		{"1b go v0.7.2 reject", obs(reversed, col("go", "v0.7.2", ""), "L4", "reject", "ordering", ""), "conform", "conform", ""},
		// A known divergence whose range has ended but which still diverges is a regression outside every range.
		{"1b js 17.4.0 accepts: undeclared", obs(reversed, col("js", "17.4.0", ""), "L4", "ok", "", apiValue(`"`+poolReversed+`"`)), "accepts_invalid", "undeclared", ""},
		{"1b js 17.2.0 refuses: unexpected-conform", obs(reversed, col("js", "17.2.0", ""), "L4", "reject", "ordering", ""), "conform", "unexpected-conform", "accepts_invalid"},
		{"1b js 17.2.0 crash: known-changed", obs(reversed, col("js", "17.2.0", ""), "L4", "crash", "panic", ""), "crash", "known-changed", "accepts_invalid"},
	})
}

// sdk-regression/js-1785 (probe vectors 2o1, 2o4, 2o5): the SDK accepts values that cannot be the ID meant. 2^53+1 is a valid
// int64 offer ID that other SDKs encode exactly, so its vector is exact or refuse: the exact ID or a refusal
// conforms, and JavaScript's 2^53 (the unsafe number already rounded) is a wrong value.
func TestOfferAndMuxedIDs(t *testing.T) {
	jsBefore173 := kd(jsTarget, "<17.3.0", "L4", "accepts_invalid")
	unsafe := apiEntry("classic/api-offer-id-encoding.id-2-pow-53-plus-1-number", "offer.manage_sell", true, `"9007199254740993"`, kd(jsTarget, "<17.3.0", "L4", "wrong_value"))
	negative := apiEntry("classic/api-offer-id-encoding.id-negative", "offer.manage_sell", true, "", jsBefore173)
	hexID := apiEntry("cap-0027/api-muxed-account-id-encoding.id-hex-string", "muxed_account.encode", true, "", jsBefore173)
	run(t, []row{
		{"2o1 js 17.2.1 ok 9007199254740992", obs(unsafe, col("js", "17.2.1", ""), "L4", "ok", "", apiValue(`"9007199254740992"`)), "diverge", "known", "wrong_value"},
		{"2o1 js 17.2.0 ok", obs(unsafe, col("js", "17.2.0", ""), "L4", "ok", "", apiValue(`"9007199254740992"`)), "diverge", "known", "wrong_value"},
		{"2o1 js 17.3.0 reject", obs(unsafe, col("js", "17.3.0", ""), "L4", "reject", "value_out_of_range", ""), "conform", "conform", ""},
		{"2o1 go v0.8.0 exact", obs(unsafe, col("go", "v0.8.0", ""), "L4", "ok", "", apiValue(`"9007199254740993"`)), "conform", "conform", ""},
		{"2o1 python 17.0.1 exact as an int", obs(unsafe, col("python", "17.0.1", ""), "L4", "ok", "", apiValue(`"9007199254740993"`)), "conform", "conform", ""},
		{"2o1 js 17.2.1 refuses: unexpected-conform", obs(unsafe, col("js", "17.2.1", ""), "L4", "reject", "value_out_of_range", ""), "conform", "unexpected-conform", "wrong_value"},
		{"2o4 js 17.2.1 ok -1", obs(negative, col("js", "17.2.1", ""), "L4", "ok", "", apiValue(`"-1"`)), "accepts_invalid", "known", "accepts_invalid"},
		{"2o4 js 17.3.0 reject", obs(negative, col("js", "17.3.0", ""), "L4", "reject", "value_out_of_range", ""), "conform", "conform", ""},
		{"2o4 go v0.7.1 reject", obs(negative, col("go", "v0.7.1", ""), "L4", "reject", "value_out_of_range", ""), "conform", "conform", ""},
		{"2o5 js 17.2.1 ok 16", obs(hexID, col("js", "17.2.1", ""), "L4", "ok", "", apiValue(`"16"`)), "accepts_invalid", "known", "accepts_invalid"},
		{"2o5 js 17.3.0 reject", obs(hexID, col("js", "17.3.0", ""), "L4", "reject", "value_out_of_range", ""), "conform", "conform", ""},
		{"2o5 go v0.7.1 n_a", obs(hexID, col("go", "v0.7.1", ""), "L4", "n_a", "value_not_representable", ""), "n_a", "n_a", ""},
		{"2o5 python takes no string ID: n_a", obs(hexID, col("python", "17.0.1", ""), "L4", "n_a", "argument_type_not_accepted", ""), "n_a", "n_a", ""},
	})
}

// sdk-regression/js-1789 (probe vector 4a) and the map-ordering half of #1766 (5a).
func TestMapCollisionsAndOrder(t *testing.T) {
	three := 3
	collide := &manifest.Entry{ID: "cap-0046/scval-map-keys-collide-three-types.u32-string-symbol", Kind: "xdr", Protocol: manifest.ProtocolRange{Introduced: 20},
		Expect:      manifest.Expect{Native: &manifest.NativeExpect{MapEntries: &three, OnLossyConversion: "error"}},
		Conformance: &manifest.Conformance{Levels: []string{"L0", "L3"}, KnownDivergences: []manifest.KnownDivergence{kd(jsTarget, "<17.3.0", "L3", "wrong_value")}}}
	collide.Variants = []*manifest.Variant{{Network: "none", Protocol: 20, XDRType: "ScVal", Blob: manifest.Blob{SHA256: strings.Repeat("1", 64), Bytes: 68}}}
	order := apiEntry("cap-0046/api-scval-map-sort-order.u32-keys", "scval.from_native", false, `["u32:9","u32:10"]`, kd(jsTarget, "<17.2.1", "L4", "wrong_value"))
	run(t, []row{
		{"4a js 17.2.0 entries=1", obs(collide, col("js", "17.2.0", ""), "L3", "ok", "", `{"native":{"map_entries":1}}`), "diverge", "known", "wrong_value"},
		{"4a js 17.2.1 entries=1", obs(collide, col("js", "17.2.1", ""), "L3", "ok", "", `{"native":{"map_entries":1}}`), "diverge", "known", "wrong_value"},
		{"4a js 17.3.0 refuses lossy", obs(collide, col("js", "17.3.0", ""), "L3", "reject", "lossy_conversion_refused", ""), "conform", "conform", ""},
		{"4a js 17.3.0 L0 control", obs(collide, col("js", "17.3.0", ""), "L0", "ok", "", `{"consumed_bytes":68,"reencoded_sha256":"`+strings.Repeat("1", 64)+`"}`), "conform", "conform", ""},
		{"4a go v0.7.1 n_a", obs(collide, col("go", "v0.7.1", ""), "L3", "n_a", "no_native_layer", ""), "n_a", "n_a", ""},
		{"4a js 17.4.0 entries=3", obs(collide, col("js", "17.4.0", ""), "L3", "ok", "", `{"native":{"map_entries":3}}`), "conform", "conform", ""},
		{"5a js 17.2.0 10,9", obs(order, col("js", "17.2.0", ""), "L4", "ok", "", apiValue(`["u32:10","u32:9"]`)), "diverge", "known", "wrong_value"},
		{"5a js 17.2.1 9,10", obs(order, col("js", "17.2.1", ""), "L4", "ok", "", apiValue(`["u32:9","u32:10"]`)), "conform", "conform", ""},
	})
}

// Variants beyond a column's schema, profiles, statuses, core leniency.
func TestReachProfilesStatus(t *testing.T) {
	p30 := &manifest.Entry{ID: "cap-0088/first-ledger-with-signed-ms", Kind: "ledger", Protocol: manifest.ProtocolRange{Introduced: 30},
		Conformance: &manifest.Conformance{KnownDivergences: []manifest.KnownDivergence{kd("stellar-xdr (crates.io)", "28.0.0 - 28.0.1", "L0", "reject")}}}
	p30.Variants = []*manifest.Variant{{Network: "testnet", Protocol: 30, XDRType: "LedgerCloseMeta", Blob: manifest.Blob{SHA256: strings.Repeat("2", 64)}}}
	reach := func(o *conform.Observation, p int) *conform.Observation { o.Describe = describe(p); return o }
	run(t, []row{
		{"js 17.2.0 refuses a P30 ledger cleanly", reach(obs(p30, col("js", "17.2.0", ""), "L0", "reject", "union_arm_undeclared", ""), 29), "n_a", "n_a", ""},
		{"rust 28 refuses: known divergence not evaluated beyond reach", reach(obs(p30, col("rust", "28.0.1", "limits-default"), "L0", "reject", "union_arm_undeclared", ""), 29), "n_a", "n_a", ""},
		{"rust 28 with a P30 schema refuses: known", reach(obs(p30, col("rust", "28.0.1", "limits-default"), "L0", "reject", "union_arm_undeclared", ""), 30), "reject_valid", "known", "reject"},
		{"js 17.2.0 crashes on a P30 ledger", reach(obs(p30, col("js", "17.2.0", ""), "L0", "crash", "process_died", ""), 29), "crash", "undeclared", ""},
		{"js 17.4.0 refuses a P30 ledger", reach(obs(p30, col("js", "17.4.0", ""), "L0", "reject", "union_arm_undeclared", ""), 30), "reject_valid", "undeclared", ""},
	})

	limits := kd("stellar-xdr (crates.io)", "28.0.0 - 30.0.0", "L0", "crash")
	limits.Profile, limits.Status = "limits-none", "open"
	bigLen := &manifest.Entry{ID: "xdr-strict/length-prefix-exceeds-input", Kind: "xdr", Negative: true, Protocol: manifest.ProtocolRange{Introduced: 1},
		Expect:      manifest.Expect{Reject: &manifest.Reject{Reason: "length_exceeds_input"}},
		Conformance: &manifest.Conformance{KnownDivergences: []manifest.KnownDivergence{limits}}}
	bigLen.Variants = []*manifest.Variant{{Network: "none", Protocol: 1, XDRType: "ScVal"}}
	javaOpen := kd("network.lightsail:stellar-sdk (Maven)", "<=6.0.0", "L0", "accepts_invalid")
	javaOpen.Status = "fixed_unreleased"
	bool2 := &manifest.Entry{ID: "xdr-strict/bool-value-2", Kind: "xdr", Negative: true, Protocol: manifest.ProtocolRange{Introduced: 1},
		CoreBehaviour: &manifest.CoreBehaviour{Accepts: true, Value: "TRUE", Observed: "executed"},
		Conformance:   &manifest.Conformance{KnownDivergences: []manifest.KnownDivergence{javaOpen}}}
	bool2.Variants = []*manifest.Variant{{Network: "none", Protocol: 1, XDRType: "ScVal", Blob: manifest.Blob{Bytes: 8}}}
	core := &conform.Column{ID: "core@30.0.0", SDK: "core", Kind: "core", Target: "stellar-core", Version: "30.0.0", Role: "extra"}
	run(t, []row{
		{"rust limits-none crash: known on its profile", obs(bigLen, col("rust", "30.0.0", "limits-none"), "L0", "crash", "process_died", ""), "crash", "known", "crash"},
		{"rust limits-default crash: undeclared", obs(bigLen, col("rust", "30.0.0", "limits-default"), "L0", "crash", "process_died", ""), "crash", "undeclared", ""},
		{"rust limits-default refuses", obs(bigLen, col("rust", "30.0.0", "limits-default"), "L0", "reject", "length_exceeds_input", ""), "conform", "conform", ""},
		{"java fixed_unreleased asserted like open", obs(bool2, col("java", "6.0.0", ""), "L0", "ok", "", ""), "accepts_invalid", "known", "accepts_invalid"},
		{"an undeclared acceptance of bool 2", obs(bool2, col("rust", "30.0.0", "limits-default"), "L0", "ok", "", ""), "accepts_invalid", "undeclared", ""},
		{"go refuses bool 2 (6a)", obs(bool2, col("go", "v0.8.0", ""), "L0", "reject", "bool_range", ""), "conform", "conform", ""},
		{"core accepts bool 2, as its core_behaviour records", obs(bool2, core, "L0", "ok", "", `{"consumed_bytes":8}`), "conform", "conform", ""},
		{"core reads bool 2 short of its bytes", obs(bool2, core, "L0", "ok", "", `{"consumed_bytes":4}`), "diverge", "undeclared", ""},
		{"core accepts trailing bytes, which it does not record accepting", obs(bigLen, core, "L0", "ok", "", ""), "accepts_invalid", "undeclared", ""},
	})
	if a := (Engine{}).Assess(obs(bool2, core, "L0", "ok", "", `{"consumed_bytes":8}`)); a.Expected != "accept" || !a.CoreLenient {
		t.Errorf("core column on bool 2: %+v", a)
	}
	if a := (Engine{}).Assess(obs(bool2, col("go", "v0.8.0", ""), "L0", "reject", "bool_range", "")); !a.CoreLenient || a.Reference != "spec" {
		t.Errorf("bool 2: %+v", a)
	}
	j := Engine{}.Judge(obs(bool2, col("java", "6.0.0", ""), "L0", "ok", "", ""))
	if j.KnownDivergence == nil || j.KnownDivergence.Status != "fixed_unreleased" || !j.KnownDivergence.InRange || j.Expected.Source != "known_divergence" {
		t.Errorf("judgement %+v %+v", j, j.KnownDivergence)
	}
}

func TestInRange(t *testing.T) {
	for _, c := range []struct {
		v, r string
		want bool
	}{
		{"17.2.0", "<16.3.1 || >=17.0.0 <17.2.1", true},
		{"17.2.1", "<16.3.1 || >=17.0.0 <17.2.1", false},
		{"16.3.0", "<16.3.1 || >=17.0.0 <17.2.1", true},
		{"16.4.1", "<16.3.1 || >=17.0.0 <17.2.1", false},
		{"v0.7.1", ">=0.7.0 <0.7.2", true},
		{"v0.7.2", ">=0.7.0 <0.7.2", false},
		{"v0.7.3", "0.7.1 - 0.7.3", true},
		{"v0.8.0", "0.7.1 - 0.7.3", false},
		{"17.0.0", "17.0.0", true},
		{"17.0.1", "17.0.0", false},
		{"6.0.0", "<=6.0.0", true},
		{"28.0.1", "28.0.0 - 28.0.1", true},
		{"30.0.0", "*", true},
		{"1.0.0-rc.1", "<1.0.0", true},
		{"17.2.1", "16.3.0 - 16.3.1 || 17.2.0 - 17.2.1", true},
	} {
		got, err := InRange(c.v, c.r)
		if err != nil || got != c.want {
			t.Errorf("%s in %q: %v %v", c.v, c.r, got, err)
		}
	}
	if _, err := InRange("1.0.0", "..abc"); err == nil {
		t.Error("a commit range was accepted")
	}
}

// matrix builds a matrix from observations judged by the engine.
func matrix(t *testing.T, observations []*conform.Observation) *Matrix {
	t.Helper()
	res := &conform.Result{Observations: observations}
	seen := map[string]bool{}
	for _, o := range observations {
		if !seen[o.Cell.Column.ID] {
			seen[o.Cell.Column.ID] = true
			res.Columns = append(res.Columns, &conform.ColumnRun{Column: o.Cell.Column, Describe: o.Describe})
		}
	}
	res.Apply(Engine{})
	return Build(res, report.Header{Corpus: report.CorpusRef{Version: "30.0.0-dev", ManifestSHA256: strings.Repeat("0", 64)}}, nil)
}

func TestMatrixCheckDiffReadiness(t *testing.T) {
	reversed := apiEntry("cap-0038/api-liquidity-pool-issuer-ordering.reversed-order", "liquidity_pool.id", true, "",
		kd(jsTarget, "<17.2.1", "L4", "accepts_invalid"), kd("network.lightsail:stellar-sdk (Maven)", "<=5.0.0", "L4", "accepts_invalid"))
	muxed := apiEntry("strkey/api-encode-muxed-contract", "strkey.encode", false, `"W"`)
	muxed.Protocol.Introduced = 30
	before := []*conform.Observation{
		obs(reversed, col("js", "17.2.0", ""), "L4", "ok", "", apiValue(`"`+poolReversed+`"`)),
		obs(reversed, col("js", "17.4.0", ""), "L4", "reject", "ordering", ""),
		obs(reversed, col("go", "v0.8.0", ""), "L4", "reject", "ordering", ""),
		obs(muxed, col("js", "17.4.0", ""), "L4", "ok", "", apiValue(`"W"`)),
		obs(muxed, col("js", "17.2.0", ""), "L4", "n_a", "op_not_supported", ""),
	}
	a := matrix(t, before)
	if f := a.Failing(); len(f) != 0 {
		t.Fatalf("clean matrix fails check: %+v", f)
	}
	if len(a.NotExercised) != 0 {
		t.Errorf("not exercised: %+v", a.NotExercised)
	}
	// The same run where JS 17.4.0 regressed: an undeclared divergence.
	after := append([]*conform.Observation(nil), before...)
	after[1] = obs(reversed, col("js", "17.4.0", ""), "L4", "ok", "", apiValue(`"`+poolReversed+`"`))
	b := matrix(t, after)
	f := b.Failing()
	if len(f) != 1 || f[0].Column != "js@17.4.0" || f[0].Check != "undeclared" || f[0].Verdict != "accepts_invalid" {
		t.Fatalf("check: %+v", f)
	}
	if b.Summary["undeclared"] != 1 || b.Summary["known"] != 1 {
		t.Errorf("summary %v", b.Summary)
	}
	ch := Diff(a, b)
	if len(ch) != 1 || ch[0].WhatMoved != "verdict" || ch[0].From.Verdict != "conform" || ch[0].To.Verdict != "accepts_invalid" {
		t.Errorf("diff %+v", ch)
	}
	if d := Diff(a, a); len(d) != 0 {
		t.Errorf("self diff %+v", d)
	}
	// Cross-SDK: js 17.4.0 accepts with a value, go refuses.
	var x *CrossSDK
	for i := range b.CrossSDK {
		if b.CrossSDK[i].Entry == reversed.ID {
			x = &b.CrossSDK[i]
		}
	}
	if x == nil || x.Agree || len(x.Classes["reject"]) != 1 {
		t.Errorf("cross-SDK %+v", b.CrossSDK)
	}
	// Readiness at Protocol 30: only the muxed-contract entry, only the latest JS column.
	r := a.Readiness(30)
	if len(r.Entries) != 1 || len(r.Cells) != 1 || r.Cells[0].Column != "js@17.4.0" {
		t.Errorf("readiness: %+v", r.Cells)
	}

	// Round trip through the files.
	dir := t.TempDir()
	if err := b.Write(dir); err != nil {
		t.Fatal(err)
	}
	back, err := ReadMatrix(filepath.Join(dir, MatrixFile))
	if err != nil {
		t.Fatal(err)
	}
	if len(Diff(b, back)) != 0 || len(back.Failing()) != 1 {
		t.Errorf("matrix did not survive the round trip")
	}
	md, _ := os.ReadFile(filepath.Join(dir, MarkdownFile))
	for _, want := range []string{"## cap-0038", "**WRONG** (known)", "**WRONG** !undeclared", "protocol-rule → refuse"} {
		if !strings.Contains(string(md), want) {
			t.Errorf("matrix.md lacks %q:\n%s", want, md)
		}
	}
	xs, _ := os.ReadFile(filepath.Join(dir, CrossSDKFile))
	if !strings.Contains(string(xs), "reject: go@v0.8.0") {
		t.Errorf("cross-sdk.md:\n%s", xs)
	}
}

func TestNotExercised(t *testing.T) {
	e := apiEntry("cap-0038/api-liquidity-pool-issuer-ordering.network-order", "liquidity_pool.id", false, `"`+poolNetwork+`"`,
		kd(goTarget, "<0.6.1", "L4", "reject"))
	e.Conformance.KnownDivergences[0].Observed = "reported"
	m := matrix(t, []*conform.Observation{obs(e, col("go", "v0.8.0", ""), "L4", "ok", "", apiValue(`"`+poolNetwork+`"`))})
	if len(m.NotExercised) != 1 || m.NotExercised[0].Versions != "<0.6.1" {
		t.Errorf("not exercised %+v", m.NotExercised)
	}
}

// The rebuild fact is judged against the network's transaction hash: a rebuilt transaction with another hash and
// a builder refusal diverge; not_rebuilt is not judged.
func TestCompareRebuild(t *testing.T) {
	want := strings.Repeat("a", 64)
	other := strings.Repeat("b", 64)
	s := func(v string) *string { return &v }
	cases := []struct {
		name string
		r    *conform.RebuildFacts
		bad  string
	}{
		{"absent", nil, ""},
		{"rebuilt, same hash", &conform.RebuildFacts{EntryPoint: s("b"), Outcome: s("rebuilt"), TxHash: s(want)}, ""},
		{"rebuilt, another hash", &conform.RebuildFacts{EntryPoint: s("b"), Outcome: s("rebuilt"), TxHash: s(other), Differs: []string{"ext"}}, "(ext differ)"},
		{"refused", &conform.RebuildFacts{EntryPoint: s("b"), Outcome: s("refused"), Message: "no"}, "refuses to rebuild"},
		{"not rebuilt", &conform.RebuildFacts{EntryPoint: s("b"), Outcome: s("not_rebuilt"), Reason: "fee_bump"}, ""},
	}
	for _, c := range cases {
		var got []string
		compareRebuild("focus.rebuild", c.r, want, func(f string, a ...any) { got = append(got, fmt.Sprintf(f, a...)) })
		switch {
		case c.bad == "" && len(got) > 0:
			t.Errorf("%s: %v", c.name, got)
		case c.bad != "" && (len(got) != 1 || !strings.Contains(got[0], c.bad)):
			t.Errorf("%s: %v, want one mismatch mentioning %q", c.name, got, c.bad)
		}
	}
}

// The native error fact: an scvError's native value must carry both the ScErrorType and the ScErrorCode the
// manifest states (the js-stellar-sdk 17.4.0 shape {type: "system", code, value} carries only the code).
func TestCompareNativeError(t *testing.T) {
	s := func(v string) *string { return &v }
	e := &manifest.Entry{ID: "x/err", Kind: "xdr", Expect: manifest.Expect{Native: &manifest.NativeExpect{
		Error: &manifest.NativeErrorExpect{Type: "storage", Code: "exceeded_limit"}}}}
	cases := []struct {
		name string
		got  *conform.NativeError
		bad  string
	}{
		{"both kept", &conform.NativeError{Type: s("storage"), Code: s("exceeded_limit")}, ""},
		{"type dropped", &conform.NativeError{Code: s("exceeded_limit")}, "carries type none"},
		{"another type", &conform.NativeError{Type: s("budget"), Code: s("exceeded_limit")}, "carries type budget"},
		{"no fact", nil, "no native error facts"},
	}
	for _, c := range cases {
		o := &conform.Observation{Cell: &conform.Cell{Entry: e, Level: "L3"},
			Response: &conform.RunResponse{Actual: &conform.Actual{Native: &conform.NativeFacts{Error: c.got}}}}
		got := compare(o)
		switch {
		case c.bad == "" && len(got) > 0:
			t.Errorf("%s: %v", c.name, got)
		case c.bad != "" && (len(got) != 1 || !strings.Contains(got[0], c.bad)):
			t.Errorf("%s: %v, want one mismatch mentioning %q", c.name, got, c.bad)
		}
	}
}

// The json level compares the converter's own JSON at each pinpoint with expect.values exactly as JSON: a
// 64-bit integer written as a number where the manifest states a string is a wrong value.
func TestCompareJSONValues(t *testing.T) {
	s := func(v string) *string { return &v }
	yes := true
	v := &manifest.Variant{Resolved: &manifest.Expect{Values: []manifest.Value{{Path: "", Equals: "1054439020873472865"}}}}
	cases := []struct {
		name string
		got  string
		bad  string
	}{
		{"string as stated", `"1054439020873472865"`, ""},
		{"a bare number", `1054439020873472865`, "the manifest says"},
	}
	for _, c := range cases {
		var got []string
		compareJSONValues([]conform.PinpointResult{{Path: s(""), Found: &yes, Value: json.RawMessage(c.got)}}, v,
			func(f string, a ...any) { got = append(got, fmt.Sprintf(f, a...)) })
		switch {
		case c.bad == "" && len(got) > 0:
			t.Errorf("%s: %v", c.name, got)
		case c.bad != "" && (len(got) != 1 || !strings.Contains(got[0], c.bad)):
			t.Errorf("%s: %v, want one mismatch mentioning %q", c.name, got, c.bad)
		}
	}
}

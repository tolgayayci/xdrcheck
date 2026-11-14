package match

// Focused tests, one or more per rule of docs/manifest.md §6. Each builds a small ledger of two transactions
// (the focus transaction H0 at index 0, another one H1 at index 1) and changes one thing.

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/tolgayayci/xdrcheck/go/internal/adapter"
	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
)

const testnet = "Test SDF Network ; September 2015"

var (
	h0 = strings.Repeat("a0", 32)
	h1 = strings.Repeat("b1", 32)

	alice  = key(VersionAccount, "alice")
	bob    = key(VersionAccount, "bob")
	carol  = key(VersionAccount, "carol")
	issuer = key(VersionAccount, "issuer")
	other  = key(VersionContract, "some other token contract")

	usdc    = "USDC:" + issuer.String()
	usdcSAC = func() string { a, _ := SACAddress(usdc, testnet); return a.String() }()
)

func key(v byte, seed string) Address {
	k := sha256.Sum256([]byte(seed))
	return Address{Version: v, Payload: k[:]}
}

func muxed(base Address, id uint64) Address {
	p := binary.BigEndian.AppendUint64(append([]byte{}, base.Payload...), id)
	return Address{Version: VersionMuxedAccount, Payload: p}
}

func vbp(a Address) string { return hex.EncodeToString(append([]byte{a.Version}, a.Payload...)) }

// stored is an account object as an indexer storing version_byte_payload_hex reports it.
func stored(a Address) *adapter.ObsAccount {
	return &adapter.ObsAccount{AsStored: &adapter.Stored{Encoding: "version_byte_payload_hex", Value: vbp(a)}}
}

func at(h string) adapter.Locator { return adapter.Locator{TxHash: h} }

func allSupported() *adapter.Observations {
	c := adapter.Capability{Supported: true}
	return &adapter.Observations{Receipts: c, Transactions: c, Participants: c, StateChanges: c, Movements: c, Addresses: c}
}

func baseExpect() *manifest.Expect {
	two := 2
	return &manifest.Expect{
		Ledger:       &manifest.LedgerCounts{Transactions: &two},
		Transactions: []manifest.Transaction{{Index: 0, Hash: h0, Successful: true, ResultCode: "tx_success"}, {Index: 1, Hash: h1, Successful: false, ResultCode: "tx_failed"}},
	}
}

func baseObs() *adapter.Observation {
	obs := newObservation(100)
	obs.Kinds.Receipts.Subkinds = nil
	obs.Kinds.Movements = adapter.KindStatus{Status: "provided"}
	t, f := true, false
	obs.Ledgers = []adapter.Ledger{{
		LedgerSeq:    100,
		Receipt:      &adapter.Receipt{Transactions: i64(2)},
		Transactions: []adapter.ObsTransaction{{Hash: h0, Successful: &t, ResultCode: "tx_success"}, {Hash: h1, Successful: &f, ResultCode: "tx_failed"}},
	}}
	return obs
}

type fixture struct {
	exp      *manifest.Expect
	obs      *adapter.Observation
	declared *adapter.Observations
}

func newFixture() *fixture {
	return &fixture{exp: baseExpect(), obs: baseObs(), declared: allSupported()}
}

func (f *fixture) l() *adapter.Ledger { return &f.obs.Ledgers[0] }

func (f *fixture) run(t *testing.T) *Result {
	t.Helper()
	zero := 0
	r, err := Match(Input{Expect: f.exp, LedgerSeq: 100, FocusTxHash: h0, FocusTxIndex: &zero, Passphrase: testnet, Declared: f.declared, Observation: f.obs})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func fact(t *testing.T, r *Result, kind string, index int) Fact {
	t.Helper()
	for _, f := range r.Facts {
		if f.Kind == kind && f.Index == index && (kind != FactReceipt || f.Field == "transactions") {
			return f
		}
	}
	t.Fatalf("no %s fact %d in %+v", kind, index, r.Facts)
	return Fact{}
}

func wantStatus(t *testing.T, r *Result, kind string, index int, st Status) Fact {
	t.Helper()
	f := fact(t, r, kind, index)
	if f.Status != st {
		t.Errorf("%s #%d: %s (%s %v), want %s", kind, index, f.Status, f.Reason, f.Diffs, st)
	}
	return f
}

func extra(r *Result, kind string, index int) ExtraStatus {
	for _, e := range r.Extras {
		if e.Kind == kind && e.Index == index {
			return e.Status
		}
	}
	return ""
}

func wantExtra(t *testing.T, r *Result, kind string, index int, st ExtraStatus) {
	t.Helper()
	if got := extra(r, kind, index); got != st {
		t.Errorf("extra %s #%d: %q, want %q (all: %+v)", kind, index, got, st, r.Extras)
	}
}

func tlCreated(acct Address, asset string, detail map[string]any) manifest.StateChange {
	return manifest.StateChange{Kind: "trustline_created", Account: manifest.Account{Address: acct.String()}, Asset: asset, Detail: detail}
}

func obsSC(h, kind string, acct Address, asset string, detail map[string]any) adapter.ObsStateChange {
	return adapter.ObsStateChange{Locator: at(h), Kind: kind, Account: stored(acct), Asset: asset, Detail: detail}
}

// ---- scope ----

func TestScopeFocusTransactionOnly(t *testing.T) {
	f := newFixture()
	f.exp.StateChanges = []manifest.StateChange{tlCreated(alice, usdc, nil)}
	f.exp.StateChangesExact = true
	f.l().StateChanges = []adapter.ObsStateChange{
		obsSC(h1, "trustline_created", alice, usdc, nil), // the same fact in another transaction
		obsSC(h1, "signer_added", bob, "", nil),          // an extra in another transaction
	}
	r := f.run(t)
	wantStatus(t, r, FactStateChange, 0, Missing)
	if len(r.Extras) != 0 {
		t.Errorf("facts of another transaction became extras: %+v", r.Extras)
	}
}

func TestScopeItemTxIndex(t *testing.T) {
	f := newFixture()
	one := 1
	sc := tlCreated(alice, usdc, nil)
	sc.TxIndex = &one
	f.exp.StateChanges = []manifest.StateChange{sc}
	f.l().StateChanges = []adapter.ObsStateChange{obsSC(h1, "trustline_created", alice, usdc, nil)}
	wantStatus(t, f.run(t), FactStateChange, 0, Matched)

	// An observed fact located by tx_index only is placed through the same table.
	f.l().StateChanges[0].Locator = adapter.Locator{TxIndex: ip(1)}
	wantStatus(t, f.run(t), FactStateChange, 0, Matched)

	// A tx_index the expectations cannot resolve is a corpus fault.
	five := 5
	f.exp.StateChanges[0].TxIndex = &five
	zero := 0
	if _, err := Match(Input{Expect: f.exp, LedgerSeq: 100, FocusTxHash: h0, FocusTxIndex: &zero, Passphrase: testnet, Declared: f.declared, Observation: f.obs}); err == nil {
		t.Error("an unresolvable tx_index matched")
	}
}

func TestScopeUnattributedFacts(t *testing.T) {
	f := newFixture()
	f.exp.StateChanges = []manifest.StateChange{tlCreated(alice, usdc, nil)}
	f.exp.StateChangesExact = true
	f.l().StateChanges = []adapter.ObsStateChange{obsSC("", "trustline_created", alice, usdc, nil), obsSC("", "signer_added", bob, "", nil)}
	r := f.run(t)
	wantStatus(t, r, FactStateChange, 0, Missing)
	if len(r.Unattributed) != 2 || len(r.Extras) != 0 {
		t.Errorf("unattributed %+v extras %+v", r.Unattributed, r.Extras)
	}

	// In a ledger of one transaction, a fact without a locator is in scope.
	one := 1
	f.exp.Ledger.Transactions = &one
	f.exp.Transactions = f.exp.Transactions[:1]
	f.l().Receipt.Transactions = i64(1)
	f.l().Transactions = f.l().Transactions[:1]
	r = f.run(t)
	wantStatus(t, r, FactStateChange, 0, Matched)
	wantExtra(t, r, adapter.KindStateChanges, 1, ExtraInScope)
	if len(r.Unattributed) != 0 {
		t.Errorf("unattributed in a one-transaction ledger: %+v", r.Unattributed)
	}
}

// ---- receipts and transactions ----

func TestReceipts(t *testing.T) {
	ops, ev := 3, 4
	f := newFixture()
	f.exp.Ledger.Operations, f.exp.Ledger.Events = &ops, &ev
	f.obs.Kinds.Receipts.Subkinds = []string{"transactions", "operations"}
	f.l().Receipt.Operations = i64(2)
	r := f.run(t)
	byField := map[string]Fact{}
	for _, x := range r.Facts {
		if x.Kind == FactReceipt {
			byField[x.Field] = x
		}
	}
	if byField["transactions"].Status != Matched {
		t.Errorf("transactions: %+v", byField["transactions"])
	}
	if x := byField["operations"]; x.Status != Missing || !x.Shortfall {
		t.Errorf("a lower count: %+v", x)
	}
	if byField["events"].Status != NotApplicable {
		t.Errorf("events not modelled: %+v", byField["events"])
	}
	f.l().Receipt.Operations = i64(4)
	r = f.run(t)
	for _, x := range r.Facts {
		if x.Field == "operations" && (x.Status != Wrong || x.Shortfall) {
			t.Errorf("a higher count: %+v", x)
		}
	}
	if s := r.Summary(); !s.ReceiptExcess || s.ReceiptShortfall {
		t.Errorf("summary %+v", s)
	}
	// A counter the receipt does not carry, though the kind says it is modelled.
	f.l().Receipt.Operations = nil
	for _, x := range f.run(t).Facts {
		if x.Field == "operations" && x.Status != Missing {
			t.Errorf("an absent counter: %+v", x)
		}
	}
}

func TestLedgerAbsent(t *testing.T) {
	f := newFixture()
	f.obs.Ledgers = nil
	r := f.run(t)
	if r.LedgerObserved {
		t.Error("ledger reported observed")
	}
	if x := fact(t, r, FactReceipt, 0); x.Status != Missing || !x.Shortfall {
		t.Errorf("receipt: %+v", x)
	}
	wantStatus(t, r, FactTransaction, 0, Missing)
	if r.FocusTxSeen != "absent" {
		t.Errorf("focus tx %s", r.FocusTxSeen)
	}
}

func TestTransactions(t *testing.T) {
	f := newFixture()
	f.exp.Transactions[0].FeeCharged = "100"
	r := f.run(t)
	wantStatus(t, r, FactTransaction, 0, Matched) // fee_charged not held: not compared
	wantStatus(t, r, FactTransaction, 1, Matched)

	// A reader that marks the failed transaction successful.
	yes := true
	f.l().Transactions[1].Successful = &yes
	wantStatus(t, f.run(t), FactTransaction, 1, Wrong)

	f = newFixture()
	f.exp.Transactions[0].FeeCharged = "100"
	f.l().Transactions[0].FeeCharged = "1000"
	wantStatus(t, f.run(t), FactTransaction, 0, Wrong)

	// A reader that skips the failed transaction.
	f = newFixture()
	f.l().Transactions = f.l().Transactions[:1]
	r = f.run(t)
	wantStatus(t, r, FactTransaction, 1, Missing)
	if r.FocusTxSeen != "present" {
		t.Errorf("focus tx %s", r.FocusTxSeen)
	}
}

// ---- participants ----

func TestParticipantsByBaseAddress(t *testing.T) {
	m7 := muxed(alice, 7)
	cases := []struct {
		name     string
		mode     string
		item     manifest.Account
		observed adapter.ObsAccount
		want     Status
	}{
		{"base stored", "base_only", manifest.Account{Address: alice.String()}, *stored(alice), Matched},
		{"base given as strkey text", "base_only", manifest.Account{Address: alice.String()}, adapter.ObsAccount{Address: alice.String()}, Matched},
		{"raw key", "base_only", manifest.Account{Address: alice.String()}, adapter.ObsAccount{AsStored: &adapter.Stored{Encoding: "raw_key_hex", Value: hex.EncodeToString(alice.Payload)}}, Matched},
		{"only the muxed form (P-3)", "base_and_alias", manifest.Account{Address: alice.String(), MuxedID: "7"}, *stored(m7), Wrong},
		{"only the muxed form, as on_chain_form", "base_and_alias", manifest.Account{Address: alice.String()}, adapter.ObsAccount{OnChainForm: m7.String()}, Wrong},
		{"muxed stored beside the base", "base_and_alias", manifest.Account{Address: alice.String(), MuxedID: "7"}, adapter.ObsAccount{Address: alice.String(), AsStored: stored(m7).AsStored}, Matched},
		{"alias with another muxed ID", "base_and_alias", manifest.Account{Address: alice.String(), MuxedID: "7"}, adapter.ObsAccount{Address: alice.String(), MuxedID: "9"}, Wrong},
		{"base_only ignores the muxed ID", "base_only", manifest.Account{Address: alice.String(), MuxedID: "7"}, adapter.ObsAccount{Address: alice.String(), MuxedID: "9"}, Matched},
		{"no muxed ID reported, muxed mode undeclared (P-2)", "", manifest.Account{Address: alice.String(), MuxedID: "7"}, *stored(alice), Matched},
		{"another muxed ID reported, muxed mode undeclared", "", manifest.Account{Address: alice.String(), MuxedID: "7"}, adapter.ObsAccount{Address: alice.String(), MuxedID: "9"}, Wrong},
		{"base_and_alias drops the verified muxed ID (P-2)", "base_and_alias", manifest.Account{Address: alice.String(), MuxedID: "7"}, *stored(alice), Wrong},
		{"base_and_alias reports it as the on-chain form", "base_and_alias", manifest.Account{Address: alice.String(), MuxedID: "7"}, adapter.ObsAccount{Address: alice.String(), OnChainForm: m7.String()}, Matched},
		{"base_and_alias, no muxed ID expected", "base_and_alias", manifest.Account{Address: alice.String()}, *stored(alice), Matched},
		{"another account", "base_only", manifest.Account{Address: alice.String()}, *stored(bob), Missing},
		{"truncated stored value", "base_only", manifest.Account{Address: alice.String()}, adapter.ObsAccount{AsStored: &adapter.Stored{Encoding: "version_byte_payload_hex", Value: vbp(alice)[:40]}}, Missing},
		{"padded stored value carrying the key", "base_only", manifest.Account{Address: alice.String()}, adapter.ObsAccount{AsStored: &adapter.Stored{Encoding: "version_byte_payload_hex", Value: vbp(alice) + "00"}}, Wrong},
		{"roles are advisory (P-4)", "base_only", manifest.Account{Address: alice.String(), Roles: []string{"source", "fee_payer"}}, adapter.ObsAccount{Address: alice.String(), Roles: []string{"destination"}}, Matched},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture()
			f.declared.Participants.Muxed = tc.mode
			f.exp.Participants = &manifest.Participants{MustInclude: []manifest.Account{tc.item}}
			f.l().Participants = []adapter.ObsParticipant{{Locator: at(h0), Account: tc.observed}}
			wantStatus(t, f.run(t), FactParticipant, 0, tc.want)
		})
	}
}

func TestParticipantsExact(t *testing.T) {
	f := newFixture()
	f.exp.Participants = &manifest.Participants{MustInclude: []manifest.Account{{Address: alice.String()}}}
	f.l().Participants = []adapter.ObsParticipant{{Locator: at(h0), Account: *stored(alice)}, {Locator: at(h0), Account: *stored(bob)}, {Locator: at(h1), Account: *stored(carol)}}
	r := f.run(t)
	wantExtra(t, r, adapter.KindParticipants, 1, Ignored)
	f.exp.Participants.Exact = true
	r = f.run(t)
	wantStatus(t, r, FactParticipant, 0, Matched)
	wantExtra(t, r, adapter.KindParticipants, 1, ExtraInScope)
	if extra(r, adapter.KindParticipants, 2) != "" {
		t.Error("a participant of another transaction is an extra")
	}
	if !r.Summary().AnyWrong() {
		t.Error("an exactness extra does not count as wrong")
	}
}

func TestMustNotInclude(t *testing.T) {
	m9 := muxed(alice, 9)
	forbidBob := manifest.Forbidden{Address: bob.String(), Because: "named only in an unmatched authorization entry"}
	forbidM9 := manifest.Forbidden{Address: m9.String(), Because: "fabricated from a memo"}
	cases := []struct {
		name   string
		forbid manifest.Forbidden
		setup  func(l *adapter.Ledger)
		want   Status
		extra  string
	}{
		{"absent", forbidBob, func(l *adapter.Ledger) {}, Matched, ""},
		{"as a participant", forbidBob, func(l *adapter.Ledger) {
			l.Participants = []adapter.ObsParticipant{{Locator: at(h0), Account: *stored(bob)}}
		}, Wrong, adapter.KindParticipants},
		{"as a state-change account", forbidBob, func(l *adapter.Ledger) {
			l.StateChanges = []adapter.ObsStateChange{obsSC(h0, "balance_changed", bob, "native", nil)}
		}, Wrong, adapter.KindStateChanges},
		{"as a movement endpoint, muxed", forbidBob, func(l *adapter.Ledger) {
			l.Movements = []adapter.ObsMovement{{Locator: at(h0), Kind: "transfer", Asset: "native", Amount: "1", From: stored(alice), To: stored(muxed(bob, 3))}}
		}, Wrong, adapter.KindMovements},
		{"as a stored address", forbidBob, func(l *adapter.Ledger) {
			l.Addresses = []adapter.ObsAddress{{Locator: at(h0), Field: "t.c", AsStored: adapter.Stored{Encoding: "strkey_text", Value: bob.String()}}}
		}, Wrong, adapter.KindAddresses},
		{"in another transaction", forbidBob, func(l *adapter.Ledger) {
			l.Participants = []adapter.ObsParticipant{{Locator: at(h1), Account: *stored(bob)}}
		}, Matched, ""},
		{"fabricated muxed address present", forbidM9, func(l *adapter.Ledger) {
			l.Participants = []adapter.ObsParticipant{{Locator: at(h0), Account: adapter.ObsAccount{Address: alice.String(), OnChainForm: m9.String()}}}
		}, Wrong, adapter.KindParticipants},
		{"the base of a forbidden muxed address is fine", forbidM9, func(l *adapter.Ledger) {
			l.Participants = []adapter.ObsParticipant{{Locator: at(h0), Account: *stored(alice)}}
		}, Matched, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture()
			f.exp.Participants = &manifest.Participants{MustNotInclude: []manifest.Forbidden{tc.forbid}}
			tc.setup(f.l())
			r := f.run(t)
			x := wantStatus(t, r, FactMustNot, 0, tc.want)
			if tc.want == Wrong && !strings.Contains(x.Reason, tc.forbid.Because) {
				t.Errorf("reason %q does not carry because", x.Reason)
			}
			if tc.extra != "" {
				wantExtra(t, r, tc.extra, 0, Forbidden)
			}
		})
	}
}

// A forged event (M-7): `other` emits a transfer naming USDC from alice to bob. The entry pins USDC with count 0,
// forbids both addresses, and allows the emitter's own-token movement as an unverified item. Only that listed
// movement is exempt from must_not_include; USDC in either form, an unlisted movement, a participant or a state
// change still hit.
func TestMustNotIncludeSparesListedMovement(t *testing.T) {
	zero := 0
	emitterMv := expMv("transfer", other.String(), "500", &alice, &bob, nil)
	emitterMv.Unverified = "the emitter's claim about its own token; a reader may record it"
	cases := []struct {
		name   string
		listed bool
		setup  func(l *adapter.Ledger)
		want   Status
		extra  string
	}{
		{"emitter's own token, listed", true, func(l *adapter.Ledger) {
			l.Movements = []adapter.ObsMovement{mv("transfer", other.String(), "500", &alice, &bob)}
		}, Matched, ""},
		{"emitter's own token, another amount", true, func(l *adapter.Ledger) {
			l.Movements = []adapter.ObsMovement{mv("transfer", other.String(), "501", &alice, &bob)}
		}, Wrong, adapter.KindMovements},
		{"emitter's own token, not listed", false, func(l *adapter.Ledger) {
			l.Movements = []adapter.ObsMovement{mv("transfer", other.String(), "500", &alice, &bob)}
		}, Wrong, adapter.KindMovements},
		{"the forged asset", true, func(l *adapter.Ledger) {
			l.Movements = []adapter.ObsMovement{mv("transfer", usdc, "500", &alice, &bob)}
		}, Wrong, adapter.KindMovements},
		{"the forged asset as its SAC address", true, func(l *adapter.Ledger) {
			l.Movements = []adapter.ObsMovement{mv("transfer", usdcSAC, "500", &alice, &bob)}
		}, Wrong, adapter.KindMovements},
		{"listed movement, recipient as a participant", true, func(l *adapter.Ledger) {
			l.Movements = []adapter.ObsMovement{mv("transfer", other.String(), "500", &alice, &bob)}
			l.Participants = []adapter.ObsParticipant{{Locator: at(h0), Account: *stored(bob)}}
		}, Wrong, adapter.KindParticipants},
		{"listed movement, recipient in a state change", true, func(l *adapter.Ledger) {
			l.Movements = []adapter.ObsMovement{mv("transfer", other.String(), "500", &alice, &bob)}
			l.StateChanges = []adapter.ObsStateChange{obsSC(h0, "balance_changed", bob, usdc, nil)}
		}, Wrong, adapter.KindStateChanges},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture()
			f.exp.Participants = &manifest.Participants{MustNotInclude: []manifest.Forbidden{{Address: bob.String(), Because: "named only by a forged event"}}}
			f.exp.Movements = []manifest.Movement{expMv("transfer", usdc, "500", &alice, &bob, &zero)}
			if tc.listed {
				f.exp.Movements = append(f.exp.Movements, emitterMv)
			}
			tc.setup(f.l())
			r := f.run(t)
			wantStatus(t, r, FactMustNot, 0, tc.want)
			if tc.extra != "" {
				wantExtra(t, r, tc.extra, 0, Forbidden)
			} else if len(r.Extras) != 0 {
				for _, e := range r.Extras {
					if e.Status == Forbidden {
						t.Errorf("forbidden extra %+v", e)
					}
				}
			}
			if tc.listed {
				wantStatus(t, r, FactMovement, 1, NotApplicable)
			}
		})
	}
}

// Only an item that states the forbidden address itself spares a record: an unstated endpoint, or the base of a
// forbidden muxed address (M-3), does not.
func TestMustNotIncludeListedMovementNamesTheAddress(t *testing.T) {
	m9 := muxed(bob, 9)
	cases := []struct {
		name   string
		forbid Address
		item   manifest.Movement
		obs    adapter.ObsMovement
	}{
		{"item leaves the endpoint unstated", bob, expMv("fee", "native", "100", &alice, nil, nil), mv("fee", "native", "100", &alice, &bob)},
		{"item states the base of a forbidden muxed address", m9, expMv("transfer", usdc, "500", &alice, &bob, nil), mv("transfer", usdc, "500", &alice, &m9)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture()
			f.exp.Participants = &manifest.Participants{MustNotInclude: []manifest.Forbidden{{Address: tc.forbid.String(), Because: "must not appear"}}}
			f.exp.Movements = []manifest.Movement{tc.item}
			f.l().Movements = []adapter.ObsMovement{tc.obs}
			r := f.run(t)
			wantStatus(t, r, FactMustNot, 0, Wrong)
			wantExtra(t, r, adapter.KindMovements, 0, Forbidden)
		})
	}
}

// ---- state changes ----

func TestStateChangeAssetEitherForm(t *testing.T) {
	for _, tc := range []struct {
		name, observed string
		want           Status
	}{
		{"classic", usdc, Matched},
		{"derived SAC address", usdcSAC, Matched},
		{"another contract", other.String(), Missing},
		{"no asset held", "", Matched},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture()
			f.exp.StateChanges = []manifest.StateChange{tlCreated(alice, usdc, nil)}
			f.l().StateChanges = []adapter.ObsStateChange{obsSC(h0, "trustline_created", alice, tc.observed, nil)}
			wantStatus(t, f.run(t), FactStateChange, 0, tc.want)
		})
	}
	// Under another passphrase the testnet SAC address is another asset.
	f := newFixture()
	f.exp.StateChanges = []manifest.StateChange{tlCreated(alice, usdc, nil)}
	f.l().StateChanges = []adapter.ObsStateChange{obsSC(h0, "trustline_created", alice, usdcSAC, nil)}
	zero := 0
	r, err := Match(Input{Expect: f.exp, LedgerSeq: 100, FocusTxHash: h0, FocusTxIndex: &zero, Passphrase: "Public Global Stellar Network ; September 2015", Declared: f.declared, Observation: f.obs})
	if err != nil {
		t.Fatal(err)
	}
	wantStatus(t, r, FactStateChange, 0, Missing)
}

func TestStateChangeDetail(t *testing.T) {
	exp := map[string]any{"balance": "0", "limit": "9223372036854775807", "flags": json.Number("1"), "authorized": true}
	cases := []struct {
		name     string
		observed map[string]any
		want     Status
	}{
		{"keys not held are skipped", map[string]any{"limit_as_stored": "922337203685.4775807"}, Matched},
		{"equal values", map[string]any{"flags": json.Number("1"), "authorized": true, "limit": "9223372036854775807"}, Matched},
		{"number written differently", map[string]any{"flags": json.Number("1.0")}, Matched},
		{"different value", map[string]any{"flags": json.Number("0")}, Wrong},
		{"number where a string is expected", map[string]any{"balance": json.Number("0")}, Wrong},
		{"string where a boolean is expected", map[string]any{"authorized": "true"}, Wrong},
		{"_as_stored is never compared", map[string]any{"limit_as_stored": "0", "balance_as_stored": "x"}, Matched},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture()
			f.exp.StateChanges = []manifest.StateChange{tlCreated(alice, usdc, exp)}
			f.l().StateChanges = []adapter.ObsStateChange{obsSC(h0, "trustline_created", alice, usdc, tc.observed)}
			x := wantStatus(t, f.run(t), FactStateChange, 0, tc.want)
			if tc.want == Wrong && (len(x.Diffs) != 1 || !strings.HasPrefix(x.Diffs[0].Field, "detail.")) {
				t.Errorf("diffs %+v", x.Diffs)
			}
		})
	}
}

func TestStateChangeSignerInFull(t *testing.T) {
	pkey := Address{Version: VersionSignedPayload, Payload: append(append(append([]byte{}, alice.Payload...), 0, 0, 0, 3), 0xde, 0xad, 0xbe, 0)}
	one, two := 1, 2
	exp := manifest.StateChange{Kind: "signer_added", Account: manifest.Account{Address: alice.String()},
		Signer: &manifest.Signer{Type: "ed25519_signed_payload", Key: pkey.String(), PayloadHex: "deadbe", Weight: &one}}
	full := vbp(pkey)
	cases := []struct {
		name   string
		signer adapter.ObsSigner
		want   Status
	}{
		{"stored in full", adapter.ObsSigner{Weight: &one, AsStored: &adapter.Stored{Encoding: "version_byte_payload_hex", Value: full}}, Matched},
		{"stored as SignerKey XDR", adapter.ObsSigner{AsStored: &adapter.Stored{Encoding: "xdr_hex", Value: "00000003" + full[2:]}}, Matched},
		{"payload dropped (#716)", adapter.ObsSigner{Weight: &one, AsStored: &adapter.Stored{Encoding: "version_byte_payload_hex", Value: full[:66]}}, Wrong},
		{"a prefix of the strkey", adapter.ObsSigner{Key: pkey.String()[:60]}, Wrong},
		{"the strkey in full", adapter.ObsSigner{Key: pkey.String(), Type: "ed25519_signed_payload", PayloadHex: "deadbe"}, Matched},
		{"another weight", adapter.ObsSigner{Weight: &two, AsStored: &adapter.Stored{Encoding: "version_byte_payload_hex", Value: full}}, Wrong},
		{"another type", adapter.ObsSigner{Type: "ed25519"}, Wrong},
		{"the account key instead of the signer", adapter.ObsSigner{AsStored: &adapter.Stored{Encoding: "version_byte_payload_hex", Value: vbp(alice)}}, Wrong},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture()
			f.exp.StateChanges = []manifest.StateChange{exp}
			s := tc.signer
			f.l().StateChanges = []adapter.ObsStateChange{{Locator: at(h0), Kind: "signer_added", Account: stored(alice), Signer: &s}}
			wantStatus(t, f.run(t), FactStateChange, 0, tc.want)
		})
	}
}

func TestStateChangeOnlyIf(t *testing.T) {
	flags := manifest.StateChange{Kind: "trustline_flags_changed", OnlyIf: "initial_authorization_separate", Account: manifest.Account{Address: alice.String()}, Asset: usdc,
		Detail: map[string]any{"flags": json.Number("1"), "authorized": true, "initial": true}}
	created := tlCreated(alice, usdc, nil)
	auth := obsSC(h0, "trustline_flags_changed", alice, usdcSAC, map[string]any{"flags": json.Number("1")})
	cases := []struct {
		name     string
		declared bool
		rows     []adapter.ObsStateChange
		want     Status
	}{
		{"declared, row present", true, []adapter.ObsStateChange{obsSC(h0, "trustline_created", alice, usdc, nil), auth}, Matched},
		{"declared, row absent", true, []adapter.ObsStateChange{obsSC(h0, "trustline_created", alice, usdc, nil)}, Missing},
		{"not declared, row absent", false, []adapter.ObsStateChange{obsSC(h0, "trustline_created", alice, usdc, nil)}, NotApplicable},
		{"not declared, row present anyway", false, []adapter.ObsStateChange{obsSC(h0, "trustline_created", alice, usdc, nil), auth}, Matched},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture()
			if tc.declared {
				f.declared.StateChanges.Modelling = []string{"initial_authorization_separate"}
			}
			f.exp.StateChanges = []manifest.StateChange{created, flags}
			f.exp.StateChangesExact = true
			f.l().StateChanges = tc.rows
			r := f.run(t)
			wantStatus(t, r, FactStateChange, 1, tc.want)
			if s := r.Summary(); s.ExtraInScope != 0 {
				t.Errorf("a row matching an only_if item is an extra: %+v", r.Extras)
			}
		})
	}
}

// The account-field, TTL and contract-code kinds match like any other; ttl_extended is ambient, so an exact list
// never has to enumerate the TTL extensions the host makes on access.
func TestAccountFieldAndTTLKinds(t *testing.T) {
	f := newFixture()
	f.exp.StateChanges = []manifest.StateChange{
		{Kind: "account_flags_changed", Account: manifest.Account{Address: alice.String()},
			Detail: map[string]any{"flags": json.Number("10"), "auth_clawback_enabled": true}},
		{Kind: "home_domain_changed", Account: manifest.Account{Address: alice.String()},
			Detail: map[string]any{"home_domain": "example.org"}},
	}
	f.exp.StateChangesExact = true
	f.l().StateChanges = []adapter.ObsStateChange{
		obsSC(h0, "account_flags_changed", alice, "", map[string]any{"flags": json.Number("10"), "auth_clawback_enabled": true}),
		obsSC(h0, "home_domain_changed", alice, "", map[string]any{"home_domain_as_stored": "example.org"}),
		obsSC(h0, "ttl_extended", bob, "", map[string]any{"live_until_ledger": json.Number("100")}),
		obsSC(h0, "contract_code_created", alice, "", map[string]any{"wasm_hash": strings.Repeat("ab", 32)}),
	}
	r := f.run(t)
	wantStatus(t, r, FactStateChange, 0, Matched)
	wantStatus(t, r, FactStateChange, 1, Matched)
	wantExtra(t, r, adapter.KindStateChanges, 2, Ignored)
	wantExtra(t, r, adapter.KindStateChanges, 3, ExtraInScope)
	// A differing flag mask is wrong.
	f.l().StateChanges[0].Detail["flags"] = json.Number("8")
	wantStatus(t, f.run(t), FactStateChange, 0, Wrong)
}

func TestStateChangesExactScope(t *testing.T) {
	f := newFixture()
	f.declared.StateChanges.Subkinds = []string{"trustline_created", "balance_changed", "sequence_bumped", "signer_added"}
	f.exp.StateChanges = []manifest.StateChange{tlCreated(alice, usdc, nil)}
	f.l().StateChanges = []adapter.ObsStateChange{
		obsSC(h0, "trustline_created", alice, usdc, nil),
		obsSC(h0, "balance_changed", alice, "native", map[string]any{"delta": "-100", "reason": "fee"}),
		obsSC(h0, "sequence_bumped", alice, "", nil),
		obsSC(h0, "signer_added", bob, "", nil),
		obsSC(h0, "data_entry_changed", bob, "", nil), // a kind the adapter does not declare
	}
	r := f.run(t)
	for i := 1; i <= 4; i++ {
		wantExtra(t, r, adapter.KindStateChanges, i, Ignored)
	}
	f.exp.StateChangesExact = true
	r = f.run(t)
	wantStatus(t, r, FactStateChange, 0, Matched)
	wantExtra(t, r, adapter.KindStateChanges, 1, Ignored)
	wantExtra(t, r, adapter.KindStateChanges, 2, Ignored)
	wantExtra(t, r, adapter.KindStateChanges, 3, ExtraInScope)
	wantExtra(t, r, adapter.KindStateChanges, 4, Ignored)

	// A candidate that differs is the item's failure, not also an extra.
	f.l().StateChanges[0].Detail = map[string]any{"flags": json.Number("2")}
	f.exp.StateChanges[0].Detail = map[string]any{"flags": json.Number("1")}
	r = f.run(t)
	wantStatus(t, r, FactStateChange, 0, Wrong)
	if extra(r, adapter.KindStateChanges, 0) != "" {
		t.Error("the differing candidate is also an extra")
	}

	// Ambient kinds still satisfy an item that lists them.
	f = newFixture()
	f.exp.StateChanges = []manifest.StateChange{{Kind: "balance_changed", Account: manifest.Account{Address: alice.String()}, Asset: "native", Detail: map[string]any{"delta": "-100"}}}
	f.l().StateChanges = []adapter.ObsStateChange{obsSC(h0, "balance_changed", alice, "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC", map[string]any{"delta": "-100"})}
	wantStatus(t, f.run(t), FactStateChange, 0, Matched)
	// A sub-kind the adapter does not model is not applicable.
	f.declared.StateChanges.Subkinds = []string{"trustline_created"}
	wantStatus(t, f.run(t), FactStateChange, 0, NotApplicable)
}

func TestStateChangeAccountForms(t *testing.T) {
	for _, tc := range []struct {
		name string
		acct *adapter.ObsAccount
		want Status
	}{
		{"base", stored(alice), Matched},
		{"strkey text", &adapter.ObsAccount{AsStored: &adapter.Stored{Encoding: "strkey_text", Value: alice.String()}}, Matched},
		{"held only as a muxed account", stored(muxed(alice, 7)), Wrong},
		{"bytes that carry the key but do not decode", &adapter.ObsAccount{AsStored: &adapter.Stored{Encoding: "version_byte_payload_hex", Value: "60" + hex.EncodeToString(alice.Payload)}}, Wrong},
		{"another account", stored(bob), Missing},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture()
			f.exp.StateChanges = []manifest.StateChange{tlCreated(alice, usdc, nil)}
			f.l().StateChanges = []adapter.ObsStateChange{{Locator: at(h0), Kind: "trustline_created", Account: tc.acct, Asset: usdc}}
			wantStatus(t, f.run(t), FactStateChange, 0, tc.want)
		})
	}
}

// ---- movements ----

func mv(kind, asset, amount string, from, to *Address) adapter.ObsMovement {
	m := adapter.ObsMovement{Locator: at(h0), Kind: kind, Asset: asset, Amount: amount}
	if from != nil {
		m.From = stored(*from)
	}
	if to != nil {
		m.To = stored(*to)
	}
	return m
}

func expMv(kind, asset, amount string, from, to *Address, count *int) manifest.Movement {
	m := manifest.Movement{Kind: kind, Asset: asset, Amount: amount, Count: count}
	if from != nil {
		m.From = &manifest.Account{Address: from.String()}
	}
	if to != nil {
		m.To = &manifest.Account{Address: to.String()}
	}
	return m
}

func TestMovements(t *testing.T) {
	zero, two := 0, 2
	pay := expMv("transfer", usdc, "500", &alice, &bob, nil)
	str := func(s string) *string { return &s }
	cases := []struct {
		name string
		exp  manifest.Movement
		obs  []adapter.ObsMovement
		want Status
	}{
		{"one record", pay, []adapter.ObsMovement{mv("transfer", usdc, "500", &alice, &bob)}, Matched},
		{"the asset as its SAC address", pay, []adapter.ObsMovement{mv("transfer", usdcSAC, "500", &alice, &bob)}, Matched},
		{"a muxed destination is its base", pay, []adapter.ObsMovement{mv("transfer", usdc, "500", &alice, ptr(muxed(bob, 4)))}, Matched},
		{"double-counted", pay, []adapter.ObsMovement{mv("transfer", usdc, "500", &alice, &bob), mv("transfer", usdc, "500", &alice, &bob)}, Wrong},
		{"count 2", expMv("transfer", usdc, "500", &alice, &bob, &two), []adapter.ObsMovement{mv("transfer", usdc, "500", &alice, &bob), mv("transfer", usdc, "500", &alice, &bob)}, Matched},
		{"count 2, one record", expMv("transfer", usdc, "500", &alice, &bob, &two), []adapter.ObsMovement{mv("transfer", usdc, "500", &alice, &bob)}, Missing},
		{"absent", pay, nil, Missing},
		{"wrong amount", pay, []adapter.ObsMovement{mv("transfer", usdc, "50", &alice, &bob)}, Wrong},
		{"amount as an integer token", pay, []adapter.ObsMovement{{Locator: at(h0), Kind: "transfer", Asset: usdc, AmountAsStored: str("500"), From: stored(alice), To: stored(bob)}}, Matched},
		{"amount as a decimal token", pay, []adapter.ObsMovement{{Locator: at(h0), Kind: "transfer", Asset: usdc, AmountAsStored: str("0.0000500"), From: stored(alice), To: stored(bob)}}, Wrong},
		{"amount as a float token", pay, []adapter.ObsMovement{{Locator: at(h0), Kind: "transfer", Asset: usdc, AmountAsStored: str("500.0"), From: stored(alice), To: stored(bob)}}, Wrong},
		{"another sender", pay, []adapter.ObsMovement{mv("transfer", usdc, "500", &carol, &bob)}, Missing},
		{"emitted by another contract (M-7)", pay, []adapter.ObsMovement{mv("transfer", other.String(), "500", &alice, &bob)}, Missing},
		{"count 0, none", expMv("mint", usdc, "1000", nil, &bob, &zero), []adapter.ObsMovement{mv("mint", other.String(), "1000", nil, &bob)}, Matched},
		{"count 0, credited from a forged event", expMv("mint", usdc, "1000", nil, &bob, &zero), []adapter.ObsMovement{mv("mint", usdc, "1000", nil, &bob)}, Wrong},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture()
			f.exp.Movements = []manifest.Movement{tc.exp}
			f.l().Movements = tc.obs
			r := f.run(t)
			wantStatus(t, r, FactMovement, 0, tc.want)
			if tc.name == "count 0, credited from a forged event" {
				wantExtra(t, r, adapter.KindMovements, 0, Forbidden)
			}
		})
	}
}

func ptr(a Address) *Address { return &a }

func TestMovementRouting(t *testing.T) {
	s := func(v string) *string { return &v }
	cases := []struct {
		name string
		exp  *manifest.Routing
		obs  *adapter.ObsRouting
		want Status
	}{
		{"absent, none reported", &manifest.Routing{Type: "absent"}, nil, Matched},
		{"absent, void reported", &manifest.Routing{Type: "absent"}, &adapter.ObsRouting{Type: "void"}, Matched},
		{"void, absent reported", &manifest.Routing{Type: "void"}, &adapter.ObsRouting{Type: "absent"}, Matched},
		{"absent, an ID reported", &manifest.Routing{Type: "absent"}, &adapter.ObsRouting{Type: "u64", Value: s("5")}, Wrong},
		{"u64, same", &manifest.Routing{Type: "u64", Value: "5"}, &adapter.ObsRouting{Type: "u64", Value: s("5")}, Matched},
		{"u64, none reported", &manifest.Routing{Type: "u64", Value: "5"}, nil, Matched},
		{"u64, reported as text", &manifest.Routing{Type: "u64", Value: "5"}, &adapter.ObsRouting{Type: "text", Value: s("5")}, Wrong},
		{"text, other value", &manifest.Routing{Type: "text", Value: "memo"}, &adapter.ObsRouting{Type: "text", Value: s("meme")}, Wrong},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture()
			e := expMv("transfer", "native", "5", &alice, &bob, nil)
			e.Routing = tc.exp
			f.exp.Movements = []manifest.Movement{e}
			o := mv("transfer", "native", "5", &alice, &bob)
			o.Routing = tc.obs
			f.l().Movements = []adapter.ObsMovement{o}
			wantStatus(t, f.run(t), FactMovement, 0, tc.want)
		})
	}
}

func TestMovementsExactAndFees(t *testing.T) {
	f := newFixture()
	f.exp.Movements = []manifest.Movement{expMv("transfer", "native", "5", &alice, &bob, nil), expMv("fee", "native", "100", &alice, nil, nil)}
	f.exp.MovementsExact = true
	f.l().Movements = []adapter.ObsMovement{
		mv("transfer", "native", "5", &alice, &bob),
		mv("fee", "native", "100", &alice, nil),
		mv("fee_refund", "native", "40", nil, &alice),
		mv("transfer", "native", "7", &bob, &carol),
	}
	r := f.run(t)
	wantStatus(t, r, FactMovement, 0, Matched)
	wantStatus(t, r, FactMovement, 1, Matched)
	wantExtra(t, r, adapter.KindMovements, 2, Ignored)
	wantExtra(t, r, adapter.KindMovements, 3, ExtraInScope)

	// An adapter that does not model fees (M-6): the fee item is not applicable, fee rows are never extras.
	f.declared.Movements.Subkinds = []string{"transfer"}
	r = f.run(t)
	wantStatus(t, r, FactMovement, 1, NotApplicable)
	wantExtra(t, r, adapter.KindMovements, 1, Ignored)

	// Movements not provided at all.
	f.obs.Kinds.Movements = adapter.KindStatus{Status: "not_applicable", Reason: "not modelled"}
	r = f.run(t)
	wantStatus(t, r, FactMovement, 0, NotApplicable)
	if len(r.Extras) != 0 && r.Summary().ExtraInScope != 0 {
		t.Errorf("extras of an unprovided kind: %+v", r.Extras)
	}
}

// ---- addresses ----

func TestAddresses(t *testing.T) {
	m := muxed(alice, 1<<63)
	cases := []struct {
		name   string
		stored adapter.ObsAddress
		want   Status
	}{
		{"strkey text", adapter.ObsAddress{Locator: at(h0), Field: "f", AsStored: adapter.Stored{Encoding: "strkey_text", Value: m.String()}}, Matched},
		{"version byte and payload", adapter.ObsAddress{Locator: at(h0), Field: "f", AsStored: adapter.Stored{Encoding: "version_byte_payload_hex", Value: vbp(m)}}, Matched},
		{"MuxedAccount XDR", adapter.ObsAddress{Locator: at(h0), Field: "f", AsStored: adapter.Stored{Encoding: "xdr_hex", Value: "00000100" + "8000000000000000" + hex.EncodeToString(alice.Payload)}}, Matched},
		{"ID dropped (truncated)", adapter.ObsAddress{Locator: at(h0), Field: "f", AsStored: adapter.Stored{Encoding: "version_byte_payload_hex", Value: vbp(m)[:66]}}, Wrong},
		{"text truncated to a checksum-valid 56 chars", adapter.ObsAddress{Locator: at(h0), Field: "f", AsStored: adapter.Stored{Encoding: "strkey_text", Value: Address{Version: VersionMuxedAccount, Payload: alice.Payload}.String()}}, Wrong},
		{"declared muxed, decodes as the base", adapter.ObsAddress{Locator: at(h0), Field: "f", Type: "muxed_account", AsStored: adapter.Stored{Encoding: "version_byte_payload_hex", Value: vbp(alice)}}, Wrong},
		{"only the base account stored elsewhere", adapter.ObsAddress{Locator: at(h0), Field: "f", AsStored: adapter.Stored{Encoding: "version_byte_payload_hex", Value: vbp(alice)}}, Missing},
		{"in another transaction", adapter.ObsAddress{Locator: at(h1), Field: "f", AsStored: adapter.Stored{Encoding: "strkey_text", Value: m.String()}}, Missing},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture()
			f.exp.Addresses = []manifest.Address{{Strkey: m.String(), Type: "muxed_account"}}
			f.l().Addresses = []adapter.ObsAddress{tc.stored}
			wantStatus(t, f.run(t), FactAddress, 0, tc.want)
		})
	}
	f := newFixture()
	f.exp.Addresses = []manifest.Address{{Strkey: m.String(), Type: "muxed_account"}}
	f.declared.Addresses = adapter.Capability{Supported: false, Reason: "no address columns"}
	wantStatus(t, f.run(t), FactAddress, 0, NotApplicable)
}

// ---- kinds ----

func TestKindDeclarationsCombine(t *testing.T) {
	f := newFixture()
	f.exp.StateChanges = []manifest.StateChange{tlCreated(alice, usdc, nil)}
	f.l().StateChanges = []adapter.ObsStateChange{obsSC(h0, "trustline_created", alice, usdc, nil)}
	// describe says unsupported, observe says provided: not applicable.
	f.declared.StateChanges = adapter.Capability{Supported: false, Reason: "not yet"}
	wantStatus(t, f.run(t), FactStateChange, 0, NotApplicable)
	// sub-kinds are the intersection of both lists.
	f.declared.StateChanges = adapter.Capability{Supported: true, Subkinds: []string{"trustline_created", "signer_added"}}
	f.obs.Kinds.StateChanges.Subkinds = []string{"signer_added"}
	wantStatus(t, f.run(t), FactStateChange, 0, NotApplicable)
	f.obs.Kinds.StateChanges.Subkinds = nil
	wantStatus(t, f.run(t), FactStateChange, 0, Matched)
	// a provided kind that comes back empty is how drops are seen.
	f.l().StateChanges = nil
	wantStatus(t, f.run(t), FactStateChange, 0, Missing)
}

func TestBadExpectationsAreErrors(t *testing.T) {
	f := newFixture()
	f.exp.Participants = &manifest.Participants{MustInclude: []manifest.Account{{Address: "GNOTANADDRESS"}}}
	zero := 0
	if _, err := Match(Input{Expect: f.exp, LedgerSeq: 100, FocusTxHash: h0, FocusTxIndex: &zero, Passphrase: testnet, Declared: f.declared, Observation: f.obs}); err == nil {
		t.Error("an undecodable expected address matched")
	}
	f = newFixture()
	f.exp.Movements = []manifest.Movement{expMv("transfer", "USDC", "1", nil, nil, nil)}
	if _, err := Match(Input{Expect: f.exp, LedgerSeq: 100, FocusTxHash: h0, FocusTxIndex: &zero, Passphrase: testnet, Declared: f.declared, Observation: f.obs}); err == nil {
		t.Error("an unreadable expected asset matched")
	}
}

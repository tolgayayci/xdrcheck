package match

// Regression tests for paths where a reader that is wrong, or that holds nothing, could be scored as if it were
// right. Each test fails on the matcher before the fix it names.

import (
	"testing"

	"github.com/tolgayayci/xdrcheck/go/internal/adapter"
	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
)

// movements_exact: a matched item accounts only its matching records. A second record of the same transfer with
// another amount is an extra in scope, not part of the matched item (docs/manifest.md §6.4, M-1).
func TestMovementsExactSameTransferOtherAmount(t *testing.T) {
	f := newFixture()
	f.exp.Movements = []manifest.Movement{expMv("transfer", usdc, "100", &alice, &bob, nil)}
	f.l().Movements = []adapter.ObsMovement{
		mv("transfer", usdc, "100", &alice, &bob),
		mv("transfer", usdc, "999999", &alice, &bob),
	}
	r := f.run(t)
	wantStatus(t, r, FactMovement, 0, Matched)
	wantExtra(t, r, adapter.KindMovements, 1, Ignored) // no exactness flag: a reader may hold more

	f.exp.MovementsExact = true
	r = f.run(t)
	x := wantStatus(t, r, FactMovement, 0, Matched)
	if len(x.Observed) != 1 || x.Observed[0].Index != 0 {
		t.Errorf("the matched item claims %+v", x.Observed)
	}
	wantExtra(t, r, adapter.KindMovements, 1, ExtraInScope)
	if !r.Summary().AnyWrong() {
		t.Error("an extra record of the same transfer under movements_exact is not wrong")
	}

	// Two items that share endpoints each claim their own record; nothing is left over.
	f.exp.Movements = append(f.exp.Movements, expMv("transfer", usdc, "999999", &alice, &bob, nil))
	r = f.run(t)
	wantStatus(t, r, FactMovement, 0, Matched)
	wantStatus(t, r, FactMovement, 1, Matched)
	if s := r.Summary(); s.AnyWrong() {
		t.Errorf("two listed transfers: %+v extras %+v", s, r.Extras)
	}
}

// A must_not_include item and a count: 0 movement hold vacuously for a reader that holds nothing for the
// transaction: they are not_applicable until the transaction is positively observed, and never count as the
// matched fact a pass needs.
func TestNegativeFactsNeedTheTransaction(t *testing.T) {
	zero := 0
	setup := func() *fixture {
		f := newFixture()
		f.exp.Ledger, f.exp.Transactions = nil, nil
		f.exp.Movements = []manifest.Movement{expMv("transfer", usdc, "100", nil, &bob, &zero)}
		f.exp.Participants = &manifest.Participants{MustNotInclude: []manifest.Forbidden{{Address: carol.String(), Because: "named only in the memo"}}}
		f.l().Transactions, f.l().Receipt = nil, nil
		return f
	}

	// Nothing held for the transaction.
	r := setup().run(t)
	x := wantStatus(t, r, FactMovement, 0, NotApplicable)
	if !x.Negative {
		t.Error("a count: 0 movement is not marked negative")
	}
	if x := wantStatus(t, r, FactMustNot, 0, NotApplicable); !x.Negative {
		t.Error("a must_not_include item is not marked negative")
	}
	if s := r.Summary(); s.Matched != 0 || s.MatchedPositive != 0 {
		t.Errorf("vacuous negative facts counted as matched: %+v", s)
	}

	// The transaction in the reader's transaction list: the negative facts now say something.
	f := setup()
	f.l().Transactions = []adapter.ObsTransaction{{Hash: h0}}
	r = f.run(t)
	wantStatus(t, r, FactMovement, 0, Matched)
	wantStatus(t, r, FactMustNot, 0, Matched)
	if s := r.Summary(); s.Matched != 2 || s.MatchedPositive != 0 {
		t.Errorf("negative facts only: %+v", s)
	}

	// Transactions not provided, but a fact of a provided kind is located in the transaction.
	f = setup()
	f.obs.Kinds.Transactions = adapter.KindStatus{Status: "not_applicable", Reason: "x"}
	f.l().Participants = []adapter.ObsParticipant{{Locator: at(h0), Account: *stored(alice)}}
	r = f.run(t)
	wantStatus(t, r, FactMustNot, 0, Matched)
	// A fact of another transaction is no evidence for this one.
	f.l().Participants[0].Locator = at(h1)
	r = f.run(t)
	wantStatus(t, r, FactMustNot, 0, NotApplicable)
}

// count: 0 forbids any record of that kind, asset and endpoints, whatever its amount (M-4).
func TestCountZeroForbidsAnyAmount(t *testing.T) {
	zero := 0
	f := newFixture()
	f.exp.Movements = []manifest.Movement{expMv("mint", usdc, "1000", nil, &bob, &zero)}
	f.l().Movements = []adapter.ObsMovement{mv("mint", usdc, "7", nil, &bob)}
	r := f.run(t)
	wantStatus(t, r, FactMovement, 0, Wrong)
	wantExtra(t, r, adapter.KindMovements, 0, Forbidden)

	// Another asset's movement (the forging contract's own token, M-7) is not the forbidden record.
	f.l().Movements = []adapter.ObsMovement{mv("mint", other.String(), "1000", nil, &bob)}
	wantStatus(t, f.run(t), FactMovement, 0, Matched)
}

// A signer expectation needs the signer: a state change of a declared signer kind that carries none, or carries
// one without a key, is wrong (S-2).
func TestStateChangeSignerRequired(t *testing.T) {
	w := 1
	pkey := Address{Version: VersionSignedPayload, Payload: append(append(append([]byte{}, alice.Payload...), 0, 0, 0, 3), 0xde, 0xad, 0xbe, 0)}
	exp := manifest.StateChange{Kind: "signer_added", Account: manifest.Account{Address: alice.String()},
		Signer: &manifest.Signer{Type: "ed25519_signed_payload", Key: pkey.String(), PayloadHex: "deadbe", Weight: &w}}
	for _, tc := range []struct {
		name   string
		signer *adapter.ObsSigner
		want   Status
	}{
		{"no signer at all", nil, Wrong},
		{"a signer with a weight and no key", &adapter.ObsSigner{Weight: &w}, Wrong},
		{"the signer in full", &adapter.ObsSigner{Weight: &w, AsStored: &adapter.Stored{Encoding: "version_byte_payload_hex", Value: vbp(pkey)}}, Matched},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture()
			f.exp.StateChanges = []manifest.StateChange{exp}
			f.l().StateChanges = []adapter.ObsStateChange{{Locator: at(h0), Kind: "signer_added", Account: stored(alice), Signer: tc.signer}}
			wantStatus(t, f.run(t), FactStateChange, 0, tc.want)
		})
	}
	// An adapter that does not declare signer changes: not applicable, whatever it holds.
	f := newFixture()
	f.declared.StateChanges.Subkinds = []string{"trustline_created"}
	f.exp.StateChanges = []manifest.StateChange{exp}
	f.l().StateChanges = []adapter.ObsStateChange{{Locator: at(h0), Kind: "signer_added", Account: stored(alice)}}
	wantStatus(t, f.run(t), FactStateChange, 0, NotApplicable)
}

// A base_and_alias reader that holds the base row and the alias row for one account passes on the alias row.
func TestParticipantsAliasBesideBase(t *testing.T) {
	f := newFixture()
	f.declared.Participants.Muxed = "base_and_alias"
	f.exp.Participants = &manifest.Participants{MustInclude: []manifest.Account{{Address: alice.String(), MuxedID: "42"}}}
	f.l().Participants = []adapter.ObsParticipant{
		{Locator: at(h0), Account: *stored(alice)},
		{Locator: at(h0), Account: adapter.ObsAccount{Address: alice.String(), AsStored: stored(muxed(alice, 42)).AsStored}},
	}
	wantStatus(t, f.run(t), FactParticipant, 0, Matched)
	f.l().Participants = f.l().Participants[:1]
	x := wantStatus(t, f.run(t), FactParticipant, 0, Wrong)
	if len(x.Diffs) != 1 || x.Diffs[0].Field != "muxed_id" {
		t.Errorf("diffs %+v", x.Diffs)
	}
}

// An item marked unverified (a stated value the reference extractor cannot derive) is excluded from matching:
// not_applicable, and its candidates are not extras.
func TestUnverifiedItemsAreNotApplicable(t *testing.T) {
	f := newFixture()
	f.declared.Participants.Muxed = "base_and_alias"
	f.exp.Participants = &manifest.Participants{Exact: true, MustInclude: []manifest.Account{{Address: alice.String(), MuxedID: "42", Unverified: "hand-written muxed ID"}}}
	f.l().Participants = []adapter.ObsParticipant{{Locator: at(h0), Account: *stored(alice)}}
	r := f.run(t)
	wantStatus(t, r, FactParticipant, 0, NotApplicable)
	if r.Summary().AnyWrong() {
		t.Errorf("an unverified item's candidate became an extra: %+v", r.Extras)
	}
	f.exp.Participants.MustInclude[0].Unverified = ""
	wantStatus(t, f.run(t), FactParticipant, 0, Wrong)

	f = newFixture()
	f.exp.MovementsExact = true
	m := expMv("transfer", usdc, "100", &alice, &bob, nil)
	m.Unverified = "amount not derived"
	f.exp.Movements = []manifest.Movement{m}
	f.l().Movements = []adapter.ObsMovement{mv("transfer", usdc, "7", &alice, &bob)}
	r = f.run(t)
	wantStatus(t, r, FactMovement, 0, NotApplicable)
	if r.Summary().AnyWrong() {
		t.Errorf("movement extras: %+v", r.Extras)
	}

	f = newFixture()
	sc := tlCreated(alice, usdc, map[string]any{"limit": "1"})
	sc.Unverified = "detail key not derived"
	f.exp.StateChanges = []manifest.StateChange{sc}
	f.l().StateChanges = []adapter.ObsStateChange{obsSC(h0, "trustline_created", alice, usdc, map[string]any{"limit": "2"})}
	wantStatus(t, f.run(t), FactStateChange, 0, NotApplicable)
}

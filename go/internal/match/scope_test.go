package match

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/tolgayayci/xdrcheck/go/internal/adapter"
	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
)

// declare puts rules in a capability's open out_of_scope property.
func declare(t *testing.T, c *adapter.Capability, rules string) {
	t.Helper()
	if !json.Valid([]byte(rules)) {
		t.Fatalf("invalid rules %s", rules)
	}
	if c.Extra == nil {
		c.Extra = map[string]json.RawMessage{}
	}
	c.Extra["out_of_scope"] = json.RawMessage(rules)
}

// A participant the adapter declares out of scope (by address type, or because every role it has is listed) is
// not_applicable with the basis as its reason; any other participant is judged as before.
func TestDeclaredScopeParticipants(t *testing.T) {
	pool := key(VersionLiquidityPool, "pool")
	contract := key(VersionContract, "invoked")
	cases := []struct {
		name string
		item manifest.Account
		want Status
	}{
		{"pool by address type", manifest.Account{Address: pool.String(), Roles: []string{"counterparty"}}, NotApplicable},
		{"contract whose only role is listed", manifest.Account{Address: contract.String(), Roles: []string{"contract"}}, NotApplicable},
		{"contract with a role not listed", manifest.Account{Address: contract.String(), Roles: []string{"contract", "source"}}, Missing},
		{"no roles never match a role rule", manifest.Account{Address: contract.String()}, Missing},
		{"a role rule applies to any address type", manifest.Account{Address: alice.String(), Roles: []string{"contract"}}, NotApplicable},
		{"an account without the role is judged", manifest.Account{Address: bob.String(), Roles: []string{"source"}}, Missing},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture()
			declare(t, &f.declared.Participants, `[{"address_types": ["liquidity_pool"], "basis": "pools are not accounts"},
				{"roles": ["contract"], "basis": "invoked contracts are not participants"}]`)
			f.exp.Participants = &manifest.Participants{MustInclude: []manifest.Account{tc.item}}
			f.l().Participants = []adapter.ObsParticipant{{Locator: at(h0), Account: *stored(carol)}}
			got := wantStatus(t, f.run(t), FactParticipant, 0, tc.want)
			if tc.want == NotApplicable && !strings.HasPrefix(got.Reason, "outside the adapter's declared scope: ") {
				t.Errorf("reason %q", got.Reason)
			}
		})
	}
}

// movement_asset_types: a counterparty is excused only when every expected movement it sends or receives moves a
// token named by its contract address; a counterparty of a classic or native movement, or of none, is judged.
func TestDeclaredScopeMovementAssetTypes(t *testing.T) {
	token := key(VersionContract, "token").String()
	cases := []struct {
		name      string
		movements []manifest.Movement
		want      Status
	}{
		{"receiver of a contract token only", []manifest.Movement{{Kind: "transfer", Asset: token, Amount: "1", To: &manifest.Account{Address: bob.String()}}}, NotApplicable},
		{"receiver of a classic asset", []manifest.Movement{{Kind: "transfer", Asset: usdc, Amount: "1", To: &manifest.Account{Address: bob.String()}}}, Missing},
		{"sender of a contract token and receiver of native", []manifest.Movement{
			{Kind: "transfer", Asset: token, Amount: "1", From: &manifest.Account{Address: bob.String()}},
			{Kind: "transfer", Asset: "native", Amount: "1", To: &manifest.Account{Address: bob.String()}}}, Missing},
		{"in no movement", nil, Missing},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture()
			declare(t, &f.declared.Participants, `[{"roles": ["counterparty"], "movement_asset_types": ["contract"], "basis": "SEP-41 rows add no participants"}]`)
			f.exp.Movements = tc.movements
			f.exp.Participants = &manifest.Participants{MustInclude: []manifest.Account{{Address: bob.String(), Roles: []string{"counterparty"}}}}
			f.l().Participants = []adapter.ObsParticipant{{Locator: at(h0), Account: *stored(carol)}}
			wantStatus(t, f.run(t), FactParticipant, 0, tc.want)
		})
	}
}

// An out-of-scope rule never excuses a forbidden participant.
func TestDeclaredScopeLeavesNegativeFacts(t *testing.T) {
	f := newFixture()
	declare(t, &f.declared.Participants, `[{"roles": ["contract"], "basis": "b"}]`)
	f.exp.Participants = &manifest.Participants{MustNotInclude: []manifest.Forbidden{{Address: bob.String(), Because: "only named"}}}
	f.l().Participants = []adapter.ObsParticipant{{Locator: at(h0), Account: *stored(bob)}}
	wantStatus(t, f.run(t), FactMustNot, 0, Wrong)
}

// Addresses are scoped by the manifest's type; state changes by kind, asset type, detail and cause, all named
// criteria together.
func TestDeclaredScopeAddressesAndStateChanges(t *testing.T) {
	m7 := muxed(alice, 7)
	f := newFixture()
	declare(t, &f.declared.Addresses, `[{"address_types": ["muxed_account"], "basis": "stored as the base"}]`)
	declare(t, &f.declared.StateChanges, `[
		{"kinds": ["balance_changed"], "asset_types": ["liquidity_pool"], "basis": "pool shares are not balances"},
		{"kinds": ["contract_deployed"], "detail": {"executable": "stellar_asset"}, "basis": "SAC deploys"},
		{"kinds": ["account_created"], "cause": "contract-call", "basis": "create_account only"}]`)
	poolAsset := "liquidity_pool:" + strings.Repeat("10", 32)
	f.exp.Addresses = []manifest.Address{{Strkey: m7.String(), Type: "muxed_account"}, {Strkey: bob.String(), Type: "account"}}
	f.exp.StateChanges = []manifest.StateChange{
		{Kind: "balance_changed", Account: manifest.Account{Address: alice.String()}, Asset: poolAsset},
		{Kind: "balance_changed", Account: manifest.Account{Address: alice.String()}, Asset: usdc},
		{Kind: "contract_deployed", Account: manifest.Account{Address: other.String()}, Detail: map[string]any{"executable": "stellar_asset"}},
		{Kind: "contract_deployed", Account: manifest.Account{Address: other.String()}, Detail: map[string]any{"executable": "wasm"}},
		{Kind: "account_created", Account: manifest.Account{Address: carol.String()}, Cause: "contract-call"},
		{Kind: "account_created", Account: manifest.Account{Address: carol.String()}},
	}
	r := f.run(t)
	wantStatus(t, r, FactAddress, 0, NotApplicable)
	wantStatus(t, r, FactAddress, 1, Missing)
	for i, want := range []Status{NotApplicable, Missing, NotApplicable, Missing, NotApplicable, Missing} {
		wantStatus(t, r, FactStateChange, i, want)
	}
}

// A malformed declaration fails the match instead of excusing anything.
func TestDeclaredScopeMalformed(t *testing.T) {
	for name, rules := range map[string]string{
		"no basis":           `[{"roles": ["contract"]}]`,
		"no criterion":       `[{"basis": "everything"}]`,
		"unknown criterion":  `[{"kinds": ["x"], "basis": "b"}]`,
		"not a list":         `{"roles": ["contract"]}`,
		"criterion mistyped": `[{"roles": "contract", "basis": "b"}]`,
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture()
			declare(t, &f.declared.Participants, rules)
			f.exp.Participants = &manifest.Participants{MustInclude: []manifest.Account{{Address: alice.String()}}}
			zero := 0
			if _, err := Match(Input{Expect: f.exp, LedgerSeq: 100, FocusTxHash: h0, FocusTxIndex: &zero, Passphrase: testnet, Declared: f.declared, Observation: f.obs}); err == nil {
				t.Error("accepted")
			}
		})
	}
}

package walletbackend

// scope: the facts wallet-backend does not claim to index, declared in describe so that the harness can report
// them not_applicable instead of judging wallet-backend against a model it never stated.
//
// Each rule cites where wallet-backend itself says what it indexes, at the commit the rule was read at
// (ScopeSourceCommit, the pinned current commit). The rules are declared at that commit and at any other commit
// where every cited file is byte-identical (scopeHolds); elsewhere none are declared. A fact wallet-backend does claim stays in scope and fails when
// it is missing or wrong; a rule is added here only with such a citation. The rules travel in the open
// `out_of_scope` property of a kind's capability (docs/adapter-protocol.md, "wallet-backend's declared scope"):
// a rule names criteria, and an expected fact matches it when it meets every criterion the rule names.
//
//	participants  address_types  the expected participant's address type (liquidity_pool, claimable_balance, …)
//	              roles          every role the manifest gives the participant is in this list
//	              movement_asset_types
//	                             the asset types of every expected movement it sends or receives (contract: a token
//	                             named by its contract address, not a classic asset's SAC)
//	addresses     address_types  the expected stored address's type
//	state_changes kinds          the expected change's kind
//	              asset_types    the type of its asset (liquidity_pool for a pool share)
//	              detail         detail key → value
//	              cause          its cause
//
// Not declared, although wallet-backend states it: "a failed transaction changes no state beyond its fee"
// (internal/indexer/processors/participants.go:167). A failed transaction does remove the pre-authorized
// transaction signers it carries (CAP-28), a real ledger change, and the other changes it could leave out are
// ones the ledger does not make on failure; so no fact is excused for belonging to a failed transaction.
//
// Not declared either: an account created by a contract call (a native Stellar Asset Contract transfer, CAP-73)
// gets no ACCOUNT/CREATE, because internal/indexer/processors/token_transfer.go:289-298 writes it for the
// create_account operation only. That is a reported defect (https://github.com/stellar/wallet-backend/issues/804),
// recorded as a known divergence of the entries that show it, so the fact stays in scope and fails.

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"

	"github.com/tolgayayci/xdrcheck/go/adapterkit"
)

// ScopeSourceCommit is the wallet-backend commit the rules' citations were read at.
const ScopeSourceCommit = "f0c00cf5242048d0438d07151cc1ef1a4b98d7c7"

// ScopeRule is one declared exclusion.
type ScopeRule struct {
	AddressTypes []string `json:"address_types,omitempty"`
	Roles        []string `json:"roles,omitempty"`
	// MovementAssetTypes (participants): every expected movement the participant sends or receives moves an
	// asset of these types.
	MovementAssetTypes []string          `json:"movement_asset_types,omitempty"`
	Kinds              []string          `json:"kinds,omitempty"`
	AssetTypes         []string          `json:"asset_types,omitempty"`
	Detail             map[string]string `json:"detail,omitempty"`
	Cause              string            `json:"cause,omitempty"`
	// Basis cites wallet-backend's own statement: commit, path and line.
	Basis string `json:"basis"`
}

func cite(path, what string) string {
	return "wallet-backend " + ScopeSourceCommit[:12] + " " + path + ": " + what
}

// ParticipantScope: wallet-backend lists accounts as participants, and of a Soroban operation only the source,
// the verified authorisers and the accounts of its own state changes; a SEP-41 (non-SAC) token's transfer events
// write state changes but add no participants.
var ParticipantScope = []ScopeRule{
	{AddressTypes: []string{"liquidity_pool", "claimable_balance"},
		Basis: cite("internal/indexer/processors/participants.go:49", "participants are taken from account ledger entries only") +
			"; " + cite("internal/indexer/processors/token_transfer.go:260-261", "liquidity pool and claimable balance IDs are not recorded as accounts")},
	{Roles: []string{"contract"},
		Basis: cite("docs/architecture/state-changes.md:130", "a Soroban operation's participants are its source account and the addresses that authorised it; the invoked contract is a participant only as the account of a state change it writes (line 126)")},
	{Roles: []string{"counterparty"}, MovementAssetTypes: []string{"contract"},
		Basis: cite("docs/architecture/state-changes.md:134", "SEP-41 rows add no participants; an address that only receives a SEP-41 transfer is not listed under the transaction") +
			"; " + cite("docs/architecture/state-changes.md:100", "token transfer events from a contract call count only for the native asset or the asset's SAC") +
			"; " + cite("docs/architecture/state-changes.md:130", "a Soroban operation's participants are its source account and the addresses that authorised it")},
}

// AddressScope: wallet-backend stores G- and C-addresses; a muxed address is stored as its base with the mux ID
// in its own column, and pool and claimable balance IDs are not stored as addresses.
var AddressScope = []ScopeRule{
	{AddressTypes: []string{"muxed_account", "muxed_contract"},
		Basis: cite("docs/architecture/token-tracking.md:160", "muxed M- and W-addresses are stored as their G- or C-base; the mux id is recorded as toMuxedId")},
	{AddressTypes: []string{"liquidity_pool", "claimable_balance"},
		Basis: cite("internal/indexer/processors/token_transfer.go:260-261", "liquidity pool and claimable balance IDs are not recorded as accounts")},
}

// StateChangeScope: changes wallet-backend's processors do not emit by design.
var StateChangeScope = []ScopeRule{
	{Kinds: []string{"balance_changed"}, AssetTypes: []string{"liquidity_pool"},
		Basis: cite("docs/architecture/state-changes.md:100", "BALANCE rows come from token transfer events only") +
			"; " + cite("docs/architecture/token-tracking.md:29,55", "pool shares are tracked in the liquidity pool balance tables, not as state changes")},
	{Kinds: []string{"contract_deployed"}, Detail: map[string]string{"executable": "stellar_asset"},
		Basis: cite("internal/indexer/processors/contract_deploy.go:158-159", "FromAsset preimages deploy a SAC, which has no creator account, and are not recorded")},
}

var citedRe = regexp.MustCompile(`wallet-backend [0-9a-f]{12} ([^:;]+):`)

// ScopeCitedFiles lists the files the rules cite, sorted.
func ScopeCitedFiles() []string {
	set := map[string]bool{}
	for _, rules := range [][]ScopeRule{ParticipantScope, AddressScope, StateChangeScope} {
		for _, r := range rules {
			for _, m := range citedRe.FindAllStringSubmatch(r.Basis, -1) {
				set[m[1]] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for f := range set {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// scopeHolds reports whether the rules read at ScopeSourceCommit hold at commit: it is that commit, or every file
// the rules cite has the same content at both (so the cited statements and line numbers are unchanged). A file
// that cannot be read at commit makes the scope not hold; one that cannot be read at ScopeSourceCommit is an error.
func scopeHolds(ctx context.Context, commit string, file func(commit, path string) (string, error)) (bool, error) {
	if commit == ScopeSourceCommit {
		return true, nil
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	for _, path := range ScopeCitedFiles() {
		want, err := file(ScopeSourceCommit, path)
		if err != nil {
			return false, fmt.Errorf("scope: %s at %s: %w", path, ScopeSourceCommit[:12], err)
		}
		got, err := file(commit, path)
		if err != nil || got != want {
			return false, nil
		}
	}
	return true, nil
}

// withScope returns c with the rules in its open out_of_scope property.
func withScope(c adapterkit.Capability, rules []ScopeRule) adapterkit.Capability {
	b, err := json.Marshal(rules)
	if err != nil {
		panic(err) // static data
	}
	if c.Extra == nil {
		c.Extra = map[string]json.RawMessage{}
	}
	c.Extra["out_of_scope"] = b
	return c
}

package match

// Declared scope (docs/adapter-protocol.md §8.1). An adapter may list, in the open `out_of_scope` property of
// the participants, addresses or state_changes capability, rules naming expected facts its indexer does not
// claim to index, each with the indexer's own statement as `basis`. An expected fact that meets every criterion
// a rule names is not_applicable, with "outside the adapter's declared scope: <basis>" as its reason, and is
// neither matched nor penalised. Negative facts (must_not_include) and extras are not affected: a declared
// scope never turns something the indexer holds into a pass. A malformed rule list is an error of the match.
//
// Criteria:
//
//	address_types  participants, addresses: the expected address's type (account, muxed_account, contract,
//	               liquidity_pool, claimable_balance; for addresses the manifest's `type`, which also knows
//	               muxed_contract)
//	roles          participants: every role the manifest gives the participant is listed (a participant
//	               without roles never matches)
//	movement_asset_types
//	               participants: the participant is the sender or receiver of at least one expected movement, and
//	               every expected movement it sends or receives moves an asset of a listed type (native, credit,
//	               liquidity_pool, or contract: a token named by its contract address, which is not a classic
//	               asset's Stellar Asset Contract)
//	kinds          state_changes: the expected change's kind
//	asset_types    state_changes: the type of its asset (native, credit, liquidity_pool)
//	detail         state_changes: detail key → value, compared as text
//	cause          state_changes: its cause

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/tolgayayci/xdrcheck/go/internal/adapter"
	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
)

type scopeRule struct {
	AddressTypes       []string          `json:"address_types"`
	Roles              []string          `json:"roles"`
	MovementAssetTypes []string          `json:"movement_asset_types"`
	Kinds              []string          `json:"kinds"`
	AssetTypes         []string          `json:"asset_types"`
	Detail             map[string]string `json:"detail"`
	Cause              string            `json:"cause"`
	Basis              string            `json:"basis"`
}

// criteria are the criteria each kind's rules may use.
var criteria = map[string][]string{
	adapter.KindParticipants: {"address_types", "roles", "movement_asset_types"},
	adapter.KindAddresses:    {"address_types"},
	adapter.KindStateChanges: {"kinds", "asset_types", "detail", "cause"},
}

// scopeRules reads a kind's declared rules.
func (m *matcher) scopeRules(kind string) ([]scopeRule, error) {
	if m.in.Declared == nil {
		return nil, nil
	}
	c := m.in.Declared.Kind(kind)
	if c == nil {
		return nil, nil
	}
	raw, ok := c.Extra["out_of_scope"]
	if !ok {
		return nil, nil
	}
	var list []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("%s.out_of_scope: %v", kind, err)
	}
	rules := make([]scopeRule, len(list))
	for i, r := range list {
		named := 0
		for k := range r {
			switch {
			case k == "basis":
			case slices.Contains(criteria[kind], k):
				named++
			default:
				return nil, fmt.Errorf("%s.out_of_scope[%d]: %q is not a criterion of %s", kind, i, k, kind)
			}
		}
		b, _ := json.Marshal(r)
		if err := json.Unmarshal(b, &rules[i]); err != nil {
			return nil, fmt.Errorf("%s.out_of_scope[%d]: %v", kind, i, err)
		}
		if rules[i].Basis == "" || named == 0 {
			return nil, fmt.Errorf("%s.out_of_scope[%d]: a rule needs a basis and at least one criterion", kind, i)
		}
	}
	return rules, nil
}

// addressType is the type of a strkey by its version character.
func addressType(s string) string {
	switch {
	case strings.HasPrefix(s, "G"):
		return "account"
	case strings.HasPrefix(s, "M"):
		return "muxed_account"
	case strings.HasPrefix(s, "C"):
		return "contract"
	case strings.HasPrefix(s, "L"):
		return "liquidity_pool"
	case strings.HasPrefix(s, "B"):
		return "claimable_balance"
	case strings.HasPrefix(s, "W"):
		return "muxed_contract"
	}
	return ""
}

func assetType(a string) string {
	switch {
	case a == "":
		return ""
	case strings.HasPrefix(a, "liquidity_pool:"):
		return "liquidity_pool"
	case a == "native":
		return "native"
	}
	return "credit"
}

// allIn reports whether xs is non-empty and every element is in set.
func allIn(xs, set []string) bool {
	if len(xs) == 0 {
		return false
	}
	for _, x := range xs {
		if !slices.Contains(set, x) {
			return false
		}
	}
	return true
}

func scopeReason(r scopeRule) string { return "outside the adapter's declared scope: " + r.Basis }

// participantOutOfScope returns the reason an expected participant is outside the declared scope, or "".
func (m *matcher) participantOutOfScope(item manifest.Account) (string, error) {
	rules, err := m.scopeRules(adapter.KindParticipants)
	if err != nil {
		return "", err
	}
	for _, r := range rules {
		if (r.AddressTypes == nil || slices.Contains(r.AddressTypes, addressType(item.Address))) &&
			(r.Roles == nil || allIn(item.Roles, r.Roles)) &&
			(r.MovementAssetTypes == nil || allIn(m.movementAssetTypes(item.Address), r.MovementAssetTypes)) {
			return scopeReason(r), nil
		}
	}
	return "", nil
}

// movementAssetTypes lists the asset type of every expected movement address sends or receives: a movement's
// asset is native, a classic asset (credit), a pool share, or a contract address (a token that is not a classic
// asset's Stellar Asset Contract, which the manifest names by its classic asset).
func (m *matcher) movementAssetTypes(address string) []string {
	if m.exp == nil {
		return nil
	}
	var out []string
	for _, mv := range m.exp.Movements {
		if (mv.From == nil || mv.From.Address != address) && (mv.To == nil || mv.To.Address != address) {
			continue
		}
		t := assetType(mv.Asset)
		if addressType(mv.Asset) == "contract" {
			t = "contract"
		}
		out = append(out, t)
	}
	return out
}

// addressOutOfScope returns the reason an expected stored address is outside the declared scope, or "".
func (m *matcher) addressOutOfScope(item manifest.Address) (string, error) {
	rules, err := m.scopeRules(adapter.KindAddresses)
	if err != nil {
		return "", err
	}
	t := item.Type
	if t == "" {
		t = addressType(item.Strkey)
	}
	for _, r := range rules {
		if slices.Contains(r.AddressTypes, t) {
			return scopeReason(r), nil
		}
	}
	return "", nil
}

// stateChangeOutOfScope returns the reason an expected state change is outside the declared scope, or "".
func (m *matcher) stateChangeOutOfScope(item manifest.StateChange) (string, error) {
	rules, err := m.scopeRules(adapter.KindStateChanges)
	if err != nil {
		return "", err
	}
	for _, r := range rules {
		ok := (r.Kinds == nil || slices.Contains(r.Kinds, item.Kind)) &&
			(r.AssetTypes == nil || slices.Contains(r.AssetTypes, assetType(item.Asset))) &&
			(r.Cause == "" || r.Cause == item.Cause)
		for k, v := range r.Detail {
			ok = ok && item.Detail[k] != nil && fmt.Sprint(item.Detail[k]) == v
		}
		if ok {
			return scopeReason(r), nil
		}
	}
	return "", nil
}

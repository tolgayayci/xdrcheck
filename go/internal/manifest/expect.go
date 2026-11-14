package manifest

import (
	"fmt"
	"sort"
)

// Expect is layer 3 of an entry's expected values: semantic facts in a neutral vocabulary, shared by all
// variants (manifest.md §6). Strings anywhere inside may carry ${derived.<path>} tokens; Variant.Resolved holds
// the block with the tokens replaced.
type Expect struct {
	Reject            *Reject       `json:"reject,omitempty"`
	Values            []Value       `json:"values,omitempty"`
	Ledger            *LedgerCounts `json:"ledger,omitempty"`
	Transactions      []Transaction `json:"transactions,omitempty"`
	Participants      *Participants `json:"participants,omitempty"`
	StateChanges      []StateChange `json:"state_changes,omitempty"`
	Movements         []Movement    `json:"movements,omitempty"`
	Addresses         []Address     `json:"addresses,omitempty"`
	Native            *NativeExpect `json:"native,omitempty"`
	StateChangesExact bool          `json:"state_changes_exact,omitempty"`
	MovementsExact    bool          `json:"movements_exact,omitempty"`
	Spec              *SpecExpect   `json:"spec,omitempty"`
}

// SpecExpect is what the corpus's own section reader reads from a spec entry's bytes: the number of
// contractspecv0 sections (Wasm only), every whole entry in stream order, and whether the stream ends cleanly.
type SpecExpect struct {
	Sections *int        `json:"sections,omitempty"`
	Entries  []SpecEntry `json:"entries"`
	CleanEnd bool        `json:"clean_end"`
}

// SpecEntry is one SCSpecEntry in the neutral rendering (docs/conformance-protocol.md, spec level).
type SpecEntry struct {
	Kind    string    `json:"kind"`
	Name    string    `json:"name"`
	Args    []SpecArg `json:"args"`
	Outputs []string  `json:"outputs,omitempty"`
}

// SpecArg is a function input, struct field, union or enum case, or event param.
type SpecArg struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// Reject says a negative input must be refused, with the reason class.
type Reject struct {
	Reason string        `json:"reason"`
	Note   string        `json:"note,omitempty"`
	Limits *RejectLimits `json:"limits,omitempty"`
}

// RejectLimits are the decode limits the oracle's reject check uses for the entry: Depth in stellar-xdr depth
// units, the boundary of the reader the vector is measured against.
type RejectLimits struct {
	Depth int `json:"depth"`
}

// Value is a pinpointed decoded value: an RFC 6901 pointer into the SEP-51 sidecar and the JSON value found
// there (string, bool, json.Number, []any, map[string]any or nil). With Select, Path is relative to the array
// element the selection names; Load resolves it per variant (Variant.Resolved) to a plain pointer and clears
// Select, so consumers of a loaded corpus only ever see plain pointers.
type Value struct {
	Path   string  `json:"path"`
	Select *Select `json:"select,omitempty"`
	Equals any     `json:"equals"`
	Note   string  `json:"note,omitempty"`
}

// Select names one element of the array at the pointer In by its ledger key (SEP-51 JSON of a LedgerKey) and,
// optionally, its LedgerEntryChange arm (created, updated, removed, state, restored). See ResolveSelect.
type Select struct {
	In     string `json:"in"`
	Key    any    `json:"key"`
	Change string `json:"change,omitempty"`
}

// LedgerCounts are the whole-ledger receipts (manifest.md §6.2). A nil field is not asserted.
type LedgerCounts struct {
	Transactions *int `json:"transactions,omitempty"`
	Operations   *int `json:"operations,omitempty"`
	Events       *int `json:"events,omitempty"`
	EntryChanges *int `json:"entry_changes,omitempty"`
}

// Transaction is one expected transaction of the ledger, in apply order.
type Transaction struct {
	Index                int      `json:"index"`
	Hash                 string   `json:"hash,omitempty"`
	Successful           bool     `json:"successful"`
	ResultCode           string   `json:"result_code,omitempty"`
	OperationResultCodes []string `json:"operation_result_codes,omitempty"`
	FeeCharged           string   `json:"fee_charged,omitempty"`
	InnerHash            string   `json:"inner_hash,omitempty"`
	InnerSuccessful      *bool    `json:"inner_successful,omitempty"`
	InnerResultCode      string   `json:"inner_result_code,omitempty"`
}

// Participants are who the ledger meta shows was affected (docs/manifest.md §6.5).
type Participants struct {
	MustInclude    []Account   `json:"must_include,omitempty"`
	MustNotInclude []Forbidden `json:"must_not_include,omitempty"`
	Exact          bool        `json:"exact,omitempty"`
}

// Account is an address as a reader should record it: the base address is the identity.
type Account struct {
	Address     string   `json:"address"`
	MuxedID     string   `json:"muxed_id,omitempty"`
	OnChainForm string   `json:"on_chain_form,omitempty"`
	Roles       []string `json:"roles,omitempty"`
	Unverified  string   `json:"unverified,omitempty"` // why the reference extractor cannot derive this item; excluded from matching
}

// Forbidden is an address that must not appear anywhere in what a reader holds for the transaction, except as an
// endpoint of a movement the entry lists itself with that address (docs/manifest.md §6.5 P-5).
type Forbidden struct {
	Address string `json:"address"`
	Because string `json:"because"`
}

// StateChange is one expected state change (docs/manifest.md §6.6). Detail keys are fixed per kind (DetailKeys);
// values are strings, booleans or json.Number.
type StateChange struct {
	Kind    string         `json:"kind"`
	Account Account        `json:"account"`
	Asset   string         `json:"asset,omitempty"`
	Signer  *Signer        `json:"signer,omitempty"`
	Detail  map[string]any `json:"detail,omitempty"`
	Cause   string         `json:"cause,omitempty"`
	TxIndex *int           `json:"tx_index,omitempty"`
	OpIndex *int           `json:"op_index,omitempty"`
	OnlyIf  string         `json:"only_if,omitempty"`
	// Unverified says why the reference extractor cannot derive this item; it is excluded from matching.
	Unverified string `json:"unverified,omitempty"`
}

// Signer is a signer compared in full: type, canonical strkey, payload and weight.
type Signer struct {
	Type       string `json:"type"` // ed25519, pre_auth_tx, hash_x, ed25519_signed_payload
	Key        string `json:"key"`
	PayloadHex string `json:"payload_hex,omitempty"`
	Weight     *int   `json:"weight,omitempty"`
}

// Movement is one expected value movement (docs/manifest.md §6.7).
type Movement struct {
	Kind    string   `json:"kind"` // transfer, mint, burn, clawback, fee, fee_refund
	Asset   string   `json:"asset"`
	Amount  string   `json:"amount"`
	From    *Account `json:"from,omitempty"`
	To      *Account `json:"to,omitempty"`
	Routing *Routing `json:"routing,omitempty"`
	Count   *int     `json:"count,omitempty"`
	TxIndex *int     `json:"tx_index,omitempty"`
	OpIndex *int     `json:"op_index,omitempty"`
	// Unverified says why the reference extractor cannot derive this item; it is excluded from matching.
	Unverified string `json:"unverified,omitempty"`
}

// Want returns how many matching records a reader must hold (count, default 1).
func (m *Movement) Want() int {
	if m.Count == nil {
		return 1
	}
	return *m.Count
}

// Routing is an event's to_muxed_id, typed.
type Routing struct {
	Type  string `json:"type"` // absent, void, u64, text, bytes
	Value string `json:"value,omitempty"`
}

// Address is an address a reader must be able to store and return unchanged.
type Address struct {
	Strkey   string `json:"strkey"`
	Type     string `json:"type"`
	XDRBytes int    `json:"xdr_bytes,omitempty"`
	Chars    int    `json:"chars,omitempty"`
}

// NativeExpect is what a lossless native conversion must preserve (level L3).
type NativeExpect struct {
	MapEntries        *int   `json:"map_entries,omitempty"`
	OnLossyConversion string `json:"on_lossy_conversion,omitempty"` // error, preserve_all
	BytesPreserved    *bool  `json:"bytes_preserved,omitempty"`
	// Error is the ScError an scvError value holds, as XDR-JSON names (type "storage", code "exceeded_limit"; a
	// contract error's code is its decimal number): the native value must carry both.
	Error *NativeErrorExpect `json:"error,omitempty"`
}

// NativeErrorExpect is the ScError a native conversion must keep (level L3).
type NativeErrorExpect struct {
	Type string `json:"type"`
	Code string `json:"code"`
}

// DetailKeys is the closed set of detail keys per state-change kind (docs/manifest.md §6.6). Its key set is the
// closed list of state-change kinds.
var DetailKeys = map[string][]string{
	"account_created":               {"starting_balance", "sponsor"},
	"account_removed":               {"merged_into", "balance_transferred"},
	"balance_changed":               {"delta", "balance_after", "reason"},
	"trustline_created":             {"balance", "limit", "flags", "authorized", "authorized_to_maintain_liabilities", "clawback_enabled", "sponsor", "num_sub_entries_after", "pool_strkey"},
	"trustline_removed":             {"balance", "pool_strkey"},
	"trustline_flags_changed":       {"flags", "authorized", "authorized_to_maintain_liabilities", "clawback_enabled", "initial"},
	"trustline_limit_changed":       {"limit", "limit_before"},
	"signer_added":                  {"signer_key_xdr_hex", "signer_ed25519_key", "payload_bytes", "weight_before", "sponsor"},
	"signer_removed":                {"signer_key_xdr_hex", "signer_ed25519_key", "payload_bytes", "weight_before", "sponsor"},
	"signer_changed":                {"signer_key_xdr_hex", "signer_ed25519_key", "payload_bytes", "weight_before", "sponsor"},
	"sponsorship_changed":           {"entry_type", "sponsor_before", "sponsor_after"},
	"offer_changed":                 {"offer_id", "change", "selling", "buying", "amount", "price_n", "price_d"},
	"liquidity_pool_created":        {"pool_id", "pool_strkey", "asset_a", "asset_b", "fee_bp", "reserve_a", "reserve_b", "total_shares", "pool_shares_trust_line_count", "asset_a_issuer_key_hex", "asset_b_issuer_key_hex"},
	"liquidity_pool_removed":        {"pool_id", "pool_strkey"},
	"liquidity_pool_changed":        {"pool_id", "pool_strkey", "asset_a", "asset_b", "fee_bp", "reserve_a", "reserve_b", "total_shares", "pool_shares_trust_line_count", "asset_a_issuer_key_hex", "asset_b_issuer_key_hex"},
	"claimable_balance_created":     {"balance_id", "amount", "claimants", "sponsor"},
	"claimable_balance_claimed":     {"balance_id", "amount"},
	"contract_data_changed":         {"contract", "key_xdr_hex", "durability", "change"},
	"contract_deployed":             {"contract", "executable", "wasm_hash", "asset"},
	"entry_restored":                {"entry_type", "key_xdr_hex", "wasm_hash"},
	"entry_evicted":                 {"entry_type", "key_xdr_hex", "wasm_hash"},
	"data_entry_changed":            {"name", "value_hex", "change"},
	"thresholds_changed":            {"master_weight", "low", "medium", "high"},
	"sequence_bumped":               {"sequence_after"},
	"account_flags_changed":         {"flags", "flags_before", "auth_required", "auth_revocable", "auth_immutable", "auth_clawback_enabled"},
	"home_domain_changed":           {"home_domain", "home_domain_hex", "home_domain_before"},
	"inflation_destination_changed": {"inflation_destination", "inflation_destination_before", "cleared"},
	"ttl_extended":                  {"entry_type", "key_xdr_hex", "key_hash", "contract", "wasm_hash", "live_until_ledger", "live_until_ledger_before"},
	"contract_code_created":         {"wasm_hash", "code_bytes"},
}

// OnlyIfChoices is the closed list of modelling choices an expectation can be conditional on.
var OnlyIfChoices = []string{"initial_authorization_separate"}

// AmbientStateChangeKinds are never counted as extras: balance_changed and sequence_bumped are caused by every
// transaction, ttl_extended by the host as a side effect of access.
var AmbientStateChangeKinds = []string{"balance_changed", "sequence_bumped", "ttl_extended"}

// AmbientMovementKinds are the fee movements, outside movements_exact.
var AmbientMovementKinds = []string{"fee", "fee_refund"}

// StateChangeKinds returns the closed list of state-change kinds, sorted.
func StateChangeKinds() []string {
	kinds := make([]string, 0, len(DetailKeys))
	for k := range DetailKeys {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	return kinds
}

// checkStateChanges enforces the closed kind list, the fixed detail keys and the only_if vocabulary.
func (e *Expect) checkStateChanges() error {
	for i, sc := range e.StateChanges {
		keys, ok := DetailKeys[sc.Kind]
		if !ok {
			return fmt.Errorf("expect.state_changes[%d]: unknown kind %q", i, sc.Kind)
		}
		for k := range sc.Detail {
			if !contains(keys, k) {
				return fmt.Errorf("expect.state_changes[%d] (%s): detail key %q is not one of %v", i, sc.Kind, k, keys)
			}
		}
		if sc.OnlyIf != "" && !contains(OnlyIfChoices, sc.OnlyIf) {
			return fmt.Errorf("expect.state_changes[%d]: unknown only_if %q", i, sc.OnlyIf)
		}
	}
	return nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

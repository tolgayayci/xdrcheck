package indexer

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/tolgayayci/xdrcheck/go/internal/adapter"
	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
)

// ledgerOf returns an entry's first variant decoded, its passphrase and its focus transaction.
func ledgerOf(t *testing.T, id string) (xdr.LedgerCloseMeta, string, int) {
	t.Helper()
	c, err := manifest.Load(corpusRoot, manifest.Options{})
	if err != nil {
		t.Fatal(err)
	}
	e := c.Entry(id)
	if e == nil {
		t.Fatalf("no entry %s", id)
	}
	v := e.Variants[0]
	raw, err := os.ReadFile(c.BlobPath(v))
	if err != nil {
		t.Fatal(err)
	}
	var lcm xdr.LedgerCloseMeta
	if err := lcm.UnmarshalBinary(raw); err != nil {
		t.Fatal(err)
	}
	focus := 0
	if v.Focus != nil && v.Focus.TxIndex != nil {
		focus = *v.Focus.TxIndex
	}
	return lcm, v.Passphrase, focus
}

func factsOf(t *testing.T, lcm xdr.LedgerCloseMeta, passphrase string) adapter.Ledger {
	t.Helper()
	doc, err := Derive(lcm, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	return doc.Facts
}

// changesOf returns the state changes of `kind` in transaction `tx`.
func changesOf(l adapter.Ledger, tx int, kind string) []adapter.ObsStateChange {
	var out []adapter.ObsStateChange
	for _, c := range l.StateChanges {
		if c.Kind == kind && c.TxIndex != nil && *c.TxIndex == tx {
			out = append(out, c)
		}
	}
	return out
}

func sourceOf(l adapter.Ledger, tx int) string {
	for _, p := range l.Participants {
		if p.TxIndex != nil && *p.TxIndex == tx && contains(p.Account.Roles, "source") {
			return p.Account.Address
		}
	}
	return ""
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// opChanges returns operation op's change list of transaction tx, for editing.
func opChanges(t *testing.T, lcm *xdr.LedgerCloseMeta, tx, op int) *xdr.LedgerEntryChanges {
	t.Helper()
	var meta *xdr.TransactionMeta
	switch lcm.V {
	case 1:
		meta = &lcm.V1.TxProcessing[tx].TxApplyProcessing
	case 2:
		meta = &lcm.V2.TxProcessing[tx].TxApplyProcessing
	default:
		meta = &lcm.V0.TxProcessing[tx].TxApplyProcessing
	}
	switch meta.V {
	case 3:
		return &meta.V3.Operations[op].Changes
	case 4:
		return &meta.V4.Operations[op].Changes
	case 2:
		return &meta.V2.Operations[op].Changes
	}
	t.Fatalf("transaction meta v%d", meta.V)
	return nil
}

func TestTTLExtensionIsTheContracts(t *testing.T) {
	lcm, pass, tx := ledgerOf(t, "cap-0046/extend-footprint-ttl-golden")
	l := factsOf(t, lcm, pass)
	ttl := changesOf(l, tx, "ttl_extended")
	if len(ttl) == 0 {
		t.Fatal("no ttl_extended")
	}
	for _, c := range ttl {
		d := c.Detail
		if d["entry_type"] != "contract_data" || d["contract"] != c.Account.Address {
			t.Errorf("ttl_extended %+v", d)
		}
		key, _ := hex.DecodeString(d["key_xdr_hex"].(string))
		sum := sha256.Sum256(key)
		if d["key_hash"] != hex.EncodeToString(sum[:]) {
			t.Errorf("key_hash %v is not the sha256 of the key", d["key_hash"])
		}
		if d["live_until_ledger"].(uint32) <= d["live_until_ledger_before"].(uint32) {
			t.Errorf("not an extension: %+v", d)
		}
	}
}

func TestContractCodeUploadIsTheSources(t *testing.T) {
	lcm, pass, tx := ledgerOf(t, "cap-0046/fee-bump-soroban-refund-to-fee-source-golden")
	l := factsOf(t, lcm, pass)
	code := changesOf(l, tx, "contract_code_created")
	if len(code) != 1 || code[0].Account.Address != sourceOf(l, tx) {
		t.Fatalf("contract_code_created %+v, source %s", code, sourceOf(l, tx))
	}
	if h, _ := code[0].Detail["wasm_hash"].(string); len(h) != 64 || code[0].Detail["code_bytes"].(int) == 0 {
		t.Errorf("detail %+v", code[0].Detail)
	}
}

func TestAccountFieldsFromAnEditedLedger(t *testing.T) {
	lcm, pass, tx := ledgerOf(t, "cap-0040/signed-payload-signer-added")
	dest := xdr.MustAddress("GBCK2RYYLIYOSHBEL2FQLAVRSHRH3GP3ID476SGKBV7BEZHMQ6NSBB7B")
	var before *uint32
	ch := opChanges(t, &lcm, tx, 0)
	for i := range *ch {
		c := &(*ch)[i]
		if c.Type == xdr.LedgerEntryChangeTypeLedgerEntryUpdated && c.Updated.Data.Type == xdr.LedgerEntryTypeAccount {
			a := c.Updated.Data.Account
			f := uint32(a.Flags)
			before = &f
			a.Flags = 0b1010
			a.HomeDomain = "example.org"
			a.InflationDest = &dest
		}
	}
	if before == nil {
		t.Fatal("the set-options operation updates no account")
	}
	l := factsOf(t, lcm, pass)
	flags := changesOf(l, tx, "account_flags_changed")
	want := fmt.Sprint(map[string]any{"flags": uint32(10), "flags_before": *before, "auth_required": false,
		"auth_revocable": true, "auth_immutable": false, "auth_clawback_enabled": true})
	if len(flags) != 1 || fmt.Sprint(flags[0].Detail) != want {
		t.Errorf("account_flags_changed %+v, want %s", flags, want)
	}
	home := changesOf(l, tx, "home_domain_changed")
	if len(home) != 1 || home[0].Detail["home_domain"] != "example.org" || home[0].Detail["home_domain_before"] != "" ||
		home[0].Detail["home_domain_hex"] != hex.EncodeToString([]byte("example.org")) {
		t.Errorf("home_domain_changed %+v", home)
	}
	infl := changesOf(l, tx, "inflation_destination_changed")
	if len(infl) != 1 || infl[0].Detail["inflation_destination"] != dest.Address() {
		t.Errorf("inflation_destination_changed %+v", infl)
	}
}

func TestChangedPoolHasThePoolRole(t *testing.T) {
	lcm, pass, tx := ledgerOf(t, "cap-0038/pool-issuers-order-by-bytes-not-strkey")
	l := factsOf(t, lcm, pass)
	n := 0
	for _, p := range l.Participants {
		if p.TxIndex != nil && *p.TxIndex == tx && strings.HasPrefix(p.Account.Address, "L") {
			n++
			if !contains(p.Account.Roles, "liquidity_pool") || contains(p.Account.Roles, "counterparty") {
				t.Errorf("pool roles %v", p.Account.Roles)
			}
		}
	}
	if n == 0 {
		t.Fatal("no pool participant")
	}
}

// A manage_data that writes the entry's current value back is no data_entry_changed; a different value is one.
func TestDataEntryWrittenBackUnchangedIsNoStateChange(t *testing.T) {
	lcm, pass, tx := ledgerOf(t, "classic/manage-data-unchanged-value")
	l := factsOf(t, lcm, pass)
	if d := changesOf(l, tx, "data_entry_changed"); len(d) != 0 {
		t.Fatalf("data_entry_changed for an unchanged value: %+v", d)
	}
	owner := sourceOf(l, tx)
	ch := opChanges(t, &lcm, tx, 0)
	edited := false
	for i := range *ch {
		c := &(*ch)[i]
		if c.Type == xdr.LedgerEntryChangeTypeLedgerEntryUpdated && c.Updated.Data.Type == xdr.LedgerEntryTypeData {
			c.Updated.Data.Data.DataValue = xdr.DataValue{1, 2, 3}
			edited = true
		}
	}
	if !edited {
		t.Fatal("the manage_data updates no data entry")
	}
	l = factsOf(t, lcm, pass)
	d := changesOf(l, tx, "data_entry_changed")
	want := fmt.Sprint(map[string]any{"name": "wde", "value_hex": "010203", "change": "updated"})
	if len(d) != 1 || fmt.Sprint(d[0].Detail) != want || d[0].Account.Address != owner {
		t.Errorf("data_entry_changed %+v, want %s for %s", d, want, owner)
	}
}

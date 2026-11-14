package stellaretl

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/network"

	"github.com/tolgayayci/xdrcheck/go/internal/rig"
)

func decodeRow(t *testing.T, s string) map[string]any {
	t.Helper()
	d := json.NewDecoder(strings.NewReader(s))
	d.UseNumber()
	var r map[string]any
	if err := d.Decode(&r); err != nil {
		t.Fatal(err)
	}
	return r
}

func pick(rows []rig.Row, kind string) []rig.Row {
	var out []rig.Row
	for _, r := range rows {
		if r["kind"] == kind {
			out = append(out, r)
		}
	}
	return out
}

func TestEffectsMapToJudgeRows(t *testing.T) {
	w := &etlRun{commit: "c", o: RigOptions{Passphrase: network.PublicNetworkPassphrase}}
	ops := opContext{}
	// op id 85766927783358465: ledger 19969169, tx 0, op 0.
	ops.add(decodeRow(t, `{"id": 85766927783358465, "type_string": "path_payment_strict_send", "source_account": "GA3NZPBC5A5CZDAGDL4CALJAX3B5YVAGZHCHVNCJGHYKN4L355CQ2LCG"}`), 19969169)
	eff := func(typ, addr, details string) []rig.Row {
		return w.effectRows(decodeRow(t, `{"operation_id": 85766927783358465, "type_string": "`+typ+`", "address": "`+addr+`", "details": `+details+`}`), 19969169, ops, map[opKey]string{})
	}
	g := "GA3NZPBC5A5CZDAGDL4CALJAX3B5YVAGZHCHVNCJGHYKN4L355CQ2LCG"
	maker := "GDKXDZXUTUF5KOX5E4UTREZJBIX2WODP572Z72WMR4PE3O346YU4EOK5"
	trade := `{"bought_amount": "1.5", "bought_asset_type": "native", "sold_amount": "2.0000000", "sold_asset_code": "HKDT", "sold_asset_issuer": "GABSZVZBYEO5F4V5LZKV7GR4SAJ5IKJGGOF43BIN42FNDUG7QPH6IMRQ", "sold_asset_type": "credit_alphanum4"}`
	if r := pick(eff("trade", g, trade), "effect_balance_change"); len(r) != 0 {
		t.Errorf("the path payment source's trade effects are its debit and credit already: %v", r)
	}
	r := pick(eff("trade", maker, trade), "effect_balance_change")
	if len(r) != 2 || r[0]["amount"] != "15000000" || r[0]["asset"] != "native" || r[1]["amount"] != "-20000000" || r[1]["op_index"] != 0 {
		t.Errorf("maker's trade: %v", r)
	}
	// Trustline authorization changed by the issuer: the trustor's trustline, XDR bits.
	r = pick(eff("trustline_flags_updated", maker, `{"asset_code": "MSCIW", "asset_issuer": "GBRDHSZL4ZKOI2PTUMM53N3NICZXC5OX3KPCD4WD4NG4XGCBC2ZA3KAG", "asset_type": "credit_alphanum12", "authorized_flag": false, "authorized_to_maintain_liabilites_flag": true, "trustor": "`+g+`"}`), "entry_change")
	if len(r) != 2 || r[0]["field"] != "flags:set" || r[0]["new"] != "2" || r[1]["field"] != "flags:clear" || r[1]["new"] != "1" ||
		r[0]["account"] != g || r[0]["asset"] != "MSCIW:GBRDHSZL4ZKOI2PTUMM53N3NICZXC5OX3KPCD4WD4NG4XGCBC2ZA3KAG" {
		t.Errorf("trustline flags: %v", r)
	}
	// A flags effect that states no flag is a row with no bits (the judge calls it a no-op).
	r = pick(eff("trustline_flags_updated", maker, `{"asset_code": "MSCIW", "asset_issuer": "GBRDHSZL4ZKOI2PTUMM53N3NICZXC5OX3KPCD4WD4NG4XGCBC2ZA3KAG", "asset_type": "credit_alphanum12", "trustor": "`+g+`"}`), "entry_change")
	if len(r) != 1 || r[0]["new"] != "0" {
		t.Errorf("empty flags: %v", r)
	}
	r = pick(eff("signer_created", g, `{"public_key": "`+g+`", "weight": 1}`), "entry_change")
	if len(r) != 1 || !strings.HasPrefix(r[0]["field"].(string), "signer:30") || len(r[0]["field"].(string)) != 7+66 || r[0]["new"] != "1" {
		t.Errorf("signer: %v", r)
	}
	r = pick(eff("trustline_created", g, `{"asset_type": "liquidity_pool_shares", "liquidity_pool_id": "`+strings.Repeat("ab", 32)+`", "limit": "922337203685.4775807"}`), "entry_change")
	if len(r) != 2 || r[0]["change"] != "created" || r[0]["pool"] != strings.Repeat("ab", 32) || r[1]["new"] != "9223372036854775807" {
		t.Errorf("pool-share trustline: %v", r)
	}
	r = pick(eff("liquidity_pool_deposited", g, `{"liquidity_pool": {"id": "`+strings.Repeat("ab", 32)+`"}, "reserves_deposited": [{"asset": "native", "amount": "1.0000000"}]}`), "effect_balance_change")
	if len(r) != 2 || r[0]["holder"] != g || r[0]["amount"] != "-10000000" || !strings.HasPrefix(r[1]["holder"].(string), "L") || r[1]["amount"] != "10000000" {
		t.Errorf("pool deposit: %v", r)
	}
	r = pick(eff("data_created", g, `{"name": "k", "value": "djE="}`), "entry_change")
	if len(r) != 2 || r[1]["new"] != "7631" || r[1]["data_name"] != "k" {
		t.Errorf("data: %v", r)
	}
	// asset_balance_changes of an operation.
	op := w.opTokenEvents(decodeRow(t, `{"id": 85766927783358465, "details": {"asset_balance_changes": [{"amount": "400.1194057", "asset_type": "native", "from": "`+g+`", "to": "CBQDHNBFBZYE4MKPWBSJOPIYLW4SFSXAXUTSXJN76GNKYVYPCKWC6QUK", "type": "transfer"}]}}`), 19969169)
	if len(op) != 1 || op[0]["kind"] != "op_token_event" || op[0]["amount"] != "4001194057" || op[0]["contract"] != "CAS3J7GYLGXMF6TDJBBYYSE3HQ6BBSMLNUQ34T6TZMYMW2EVH34XOWMA" {
		t.Errorf("asset balance changes: %v", op)
	}
}

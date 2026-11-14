package walletbackend

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/tolgayayci/xdrcheck/go/internal/rig"
)

func scRowOf(t *testing.T, s string) map[string]any {
	t.Helper()
	// Test rows write bytea values as the dump holds them after JSON decoding (`\x…`).
	d := json.NewDecoder(strings.NewReader(strings.ReplaceAll(s, `\x`, `\\x`)))
	d.UseNumber()
	var r map[string]any
	if err := d.Decode(&r); err != nil {
		t.Fatal(err)
	}
	return r
}

func entryOf(rows []rig.Row) []rig.Row {
	var out []rig.Row
	for _, r := range rows {
		if r["kind"] == "entry_change" {
			out = append(out, r)
		}
	}
	return out
}

func TestStateChangesMapToEntryRows(t *testing.T) {
	m := &mapper{commit: "c", tokens: map[string]token{}, assets: map[string]string{}, bycontract: map[string]token{}}
	acct := `\x3044ad47185a30e91c245e8b0582b191e27d99fb40f9ff48ca0d7e1264ec879b20`
	g := "GBCK2RYYLIYOSHBEL2FQLAVRSHRH3GP3ID476SGKBV7BEZHMQ6NSBB7B"
	tok := `\x10` + strings.Repeat("cd", 32)
	base := `"to_id": 19058303195680768, "operation_id": 19058303195680769, "ledger_number": 4437357, "account_id": "` + acct + `"`
	cases := []struct {
		name string
		row  string
		want []map[string]any
	}{
		{"signed-payload signer, full bytes", `{` + base + `, "state_change_category": "SIGNER", "state_change_reason": "ADD",
			"signer_account_id": "\x7844ad47185a30e91c245e8b0582b191e27d99fb40f9ff48ca0d7e1264ec879b2000000003deadbe00", "signer_weight_new": 1}`,
			[]map[string]any{{"entry_type": "account", "account": g, "field": "signer:7844ad47185a30e91c245e8b0582b191e27d99fb40f9ff48ca0d7e1264ec879b2000000003deadbe00", "new": "1"}}},
		{"signer stored truncated passes through", `{` + base + `, "state_change_category": "SIGNER", "state_change_reason": "REMOVE",
			"signer_account_id": "\x7844ad47185a30e91c245e8b0582b191e27d99fb40f9ff48ca0d7e1264ec879b20", "signer_weight_old": 1}`,
			[]map[string]any{{"field": "signer:7844ad47185a30e91c245e8b0582b191e27d99fb40f9ff48ca0d7e1264ec879b20", "old": "1"}}},
		{"trustline added: lifecycle and limit in raw units", `{` + base + `, "state_change_category": "TRUSTLINE", "state_change_reason": "ADD",
			"token_id": "` + tok + `", "trustline_limit_new": "922337203685.4775807"}`,
			[]map[string]any{{"entry_type": "trustline", "change": "created"}, {"field": "limit", "new": "9223372036854775807"}}},
		{"trustline limit update: old stored raw", `{` + base + `, "state_change_category": "TRUSTLINE", "state_change_reason": "UPDATE",
			"token_id": "` + tok + `", "trustline_limit_old": "1000000000000000", "trustline_limit_new": "100000000.0000000"}`,
			[]map[string]any{{"field": "limit", "old": "1000000000000000", "new": "1000000000000000"}}},
		{"pool-share trustline removed", `{` + base + `, "state_change_category": "TRUSTLINE", "state_change_reason": "REMOVE",
			"liquidity_pool_id": "` + strings.Repeat("ab", 32) + `"}`,
			[]map[string]any{{"entry_type": "trustline", "change": "removed", "pool": strings.Repeat("ab", 32)}}},
		{"authorization bits translated to XDR", `{` + base + `, "state_change_category": "BALANCE_AUTHORIZATION", "state_change_reason": "SET",
			"token_id": "` + tok + `", "flags": 64}`,
			[]map[string]any{{"field": "flags:set", "new": "2"}}},
		{"account flags translated to XDR", `{` + base + `, "state_change_category": "FLAGS", "state_change_reason": "CLEAR", "flags": 6}`,
			[]map[string]any{{"entry_type": "account", "field": "flags:clear", "new": "3"}}},
		{"threshold", `{` + base + `, "state_change_category": "SIGNATURE_THRESHOLD", "state_change_reason": "UPDATE",
			"threshold": "MEDIUM", "threshold_old": 1, "threshold_new": 1}`,
			[]map[string]any{{"field": "threshold:med", "old": "1", "new": "1"}}},
		{"data value base64 to hex", `{` + base + `, "state_change_category": "DATA_ENTRY", "state_change_reason": "UPDATE",
			"data_entry_name": "k", "key_value": {"old": "djE=", "new": "djI="}}`,
			[]map[string]any{{"entry_type": "data", "data_name": "k", "field": "value", "old": "7631", "new": "7632"}}},
		{"home domain", `{` + base + `, "state_change_category": "HOME_DOMAIN", "state_change_reason": "SET", "key_value": {"new": "x.org"}}`,
			[]map[string]any{{"field": "home_domain", "new": "782e6f7267"}}},
		{"contract deployed as ACCOUNT/CREATE of the contract", `{` + base[:len(base)-len(`, "account_id": "`+acct+`"`)] + `, "account_id": "` + tok + `",
			"state_change_category": "ACCOUNT", "state_change_reason": "CREATE"}`,
			[]map[string]any{{"entry_type": "contract_data", "change": "created"}}},
	}
	for _, c := range cases {
		got := entryOf(m.mapRow("state_changes", scRowOf(t, c.row)))
		if len(got) != len(c.want) {
			t.Errorf("%s: %d rows, want %d: %v", c.name, len(got), len(c.want), got)
			continue
		}
		for i, w := range c.want {
			for k, v := range w {
				if got[i][k] != v {
					t.Errorf("%s: row %d %s = %v, want %v", c.name, i, k, got[i][k], v)
				}
			}
			if got[i]["op_index"] != 0 || got[i]["tx_index"] != 0 {
				t.Errorf("%s: tx/op %v/%v", c.name, got[i]["tx_index"], got[i]["op_index"])
			}
		}
	}
	// A balance row of a token the service has not classified is still a balance change, named by contract.
	got := m.mapRow("state_changes", scRowOf(t, `{`+base+`, "state_change_category": "BALANCE", "state_change_reason": "CREDIT",
		"token_id": "`+tok+`", "amount": "5"}`))
	if len(got) != 1 || got[0]["kind"] != "balance_change" || !strings.HasPrefix(got[0]["asset"].(string), "C") {
		t.Errorf("balance: %v", got)
	}
}

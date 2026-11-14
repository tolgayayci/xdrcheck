package stellaretl

// Exporters: every stellar-etl export mapped to the common rows. Amounts come from exact text where the export
// has it (`amount_raw`, the 7-decimal strings of effects); float-only columns are marked exact:false.

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/tolgayayci/xdrcheck/go/internal/rig"
)

func (w *etlRun) base(source string, ledger uint32) rig.Row {
	return rig.Row{"pipeline": "stellar-etl", "commit": w.commit, "source": source, "ledger": ledger, "exact": true}
}

func assetOf(typ, code, issuer string) string {
	switch typ {
	case "native", "":
		if code == "" {
			return "native"
		}
	}
	return code + ":" + issuer
}

var entryChangeNames = map[int64]string{0: "created", 1: "updated", 2: "removed", 3: "state", 4: "restored"}

func (w *etlRun) mapRow(cmd, etype string, r map[string]any, l uint32) []rig.Row {
	row := w.base(cmd, l)
	switch cmd {
	case "export_ledgers":
		row["kind"], row["hash"], row["protocol"], row["closed_at"] = "ledger", str(r["ledger_hash"]), num(r["protocol_version"]), str(r["closed_at"])
		// The judge reads close_time as unix seconds.
		if t, err := time.Parse(time.RFC3339Nano, str(r["closed_at"])); err == nil {
			row["close_time"] = t.Unix()
		}
		row["tx_count"], row["failed_count"], row["op_count"] = num(r["transaction_count"])+num(r["failed_transaction_count"]), num(r["failed_transaction_count"]), num(r["operation_count"])
		row["successful_tx_count"] = num(r["successful_transaction_count"])
		return []rig.Row{row}
	case "export_transactions":
		_, tx, _ := toid(num(r["id"]))
		row["kind"], row["tx_index"], row["tx_hash"] = "tx", tx, str(r["transaction_hash"])
		row["success"], row["fee_charged"], row["result_code"], row["op_count"] = r["successful"], str(r["fee_charged"]), str(r["transaction_result_code"]), num(r["operation_count"])
		if h := str(r["inner_transaction_hash"]); h != "" {
			row["inner_hash"] = h
		}
		out := []rig.Row{row}
		for _, k := range []string{"account", "fee_account"} {
			if a := str(r[k]); a != "" {
				p := w.base(cmd, l)
				p["kind"], p["tx_index"], p["tx_hash"], p["holder"], p["role"] = "participant", tx, str(r["transaction_hash"]), a, k
				out = append(out, p)
			}
		}
		return out
	case "export_ledger_transaction":
		_, tx, _ := toid(num(r["id"]))
		row["kind"], row["tx_index"], row["tx_hash"] = "ledger_transaction", tx, str(r["transaction_hash"])
		return []rig.Row{row}
	case "export_operations":
		_, tx, op := toid(num(r["id"]))
		row["kind"], row["tx_index"], row["op_index"] = "operation", tx, op
		row["op_type"], row["source_account"], row["result_code"] = str(r["type_string"]), str(r["source_account"]), str(r["operation_result_code"])
		return []rig.Row{row}
	case "export_effects":
		_, tx, op := toid(num(r["operation_id"]))
		typ := str(r["type_string"])
		d, _ := r["details"].(map[string]any)
		row["tx_index"], row["op_index"] = tx, op
		// The effect verbatim; its judge rows (effect_balance_change, entry_change) are made by effectRows.
		row["kind"], row["effect"], row["address"], row["data"] = "effect", typ, str(r["address"]), d
		return []rig.Row{row}
	case "export_token_transfer":
		row["kind"], row["tx_hash"], row["event"], row["contract"] = "token_event", str(r["transaction_hash"]), str(r["event_topic"]), str(r["contract_id"])
		_, tx, _ := toid(num(r["transaction_id"]))
		row["tx_index"] = tx
		if v := num(r["operation_id"]); v > 0 {
			_, _, op := toid(v)
			row["op_index"] = op
		}
		row["from"], row["to"], row["asset"], row["amount"] = str(r["from"]), str(r["to"]), tokenAsset(r), str(r["amount_raw"])
		if mx := str(r["to_muxed_id"]); mx != "" {
			row["to_muxed_id"] = mx
		}
		return append([]rig.Row{row}, w.transferBalances(row, str(r["event_topic"]))...)
	case "export_contract_events":
		_, tx, _ := toid(num(r["transaction_id"]))
		row["kind"], row["tx_index"], row["tx_hash"], row["contract"] = "contract_event", tx, str(r["transaction_hash"]), str(r["contract_id"])
		row["event_type"], row["successful_call"], row["topics"], row["data"] = str(r["type_string"]), r["in_successful_contract_call"], r["topics_decoded"], r["data_decoded"]
		return []rig.Row{row}
	case "export_trades":
		_, tx, op := toid(num(r["history_operation_id"]))
		row["kind"], row["tx_index"], row["op_index"], row["exact"] = "trade", tx, op, false
		row["seller"], row["buyer"] = str(r["selling_account_address"]), str(r["buying_account_address"])
		row["selling_asset"] = assetOf(str(r["selling_asset_type"]), str(r["selling_asset_code"]), str(r["selling_asset_issuer"]))
		row["buying_asset"] = assetOf(str(r["buying_asset_type"]), str(r["buying_asset_code"]), str(r["buying_asset_issuer"]))
		row["selling_amount"], row["buying_amount"] = str(r["selling_amount"]), str(r["buying_amount"])
		return []rig.Row{row}
	case "export_assets":
		row["kind"], row["asset"] = "asset", assetOf(str(r["asset_type"]), str(r["asset_code"]), str(r["asset_issuer"]))
		return []rig.Row{row}
	case "export_ledger_entry_changes":
		// Not the judge's entry_change kind: stellar-etl compacts changes per ledger and carries no transaction, so
		// the rows cannot be matched to the judge's per-transaction facts. The drop checks cover them instead.
		row["kind"], row["entry_type"] = "ledger_entry_change", etype
		row["change"] = entryChangeNames[num(r["ledger_entry_change"])]
		if r["deleted"] == true {
			row["deleted"] = true
		}
		switch etype {
		case "account":
			if k, ok := accountKey(str(r["account_id"])); ok {
				row["entry_key"] = k
			}
			row["holder"], row["amount"] = str(r["account_id"]), rawOrFloat(r["balance"], row)
		case "trustline":
			row["holder"] = str(r["account_id"])
			row["asset"] = assetOf(str(r["asset_type"]), str(r["asset_code"]), str(r["asset_issuer"]))
			if p := str(r["liquidity_pool_id"]); p != "" {
				row["asset"] = "pool:" + p
			}
			row["amount"] = rawOrFloat(r["balance"], row)
		case "contract_data", "contract_code":
			row["key_hash"], row["contract"] = str(r["ledger_key_hash"]), str(r["contract_id"])
			if b := str(r["balance"]); b != "" {
				row["holder"], row["amount"] = str(r["balance_holder"]), b
			}
		case "ttl":
			row["key_hash"] = str(r["key_hash"])
		case "restored_key":
			row["key_hash"] = str(r["ledger_key_hash"])
		}
		data := map[string]any{}
		for k, v := range r {
			if k == "closed_at" || k == "closed_at_ms" {
				continue
			}
			data[k] = v
		}
		row["data"] = data
		return []rig.Row{row}
	}
	row["kind"], row["table"], row["data"] = "other", cmd, r
	return []rig.Row{row}
}

// transferBalances turns one token-transfer row of a classic asset (native or CODE:ISSUER, i.e. a verified SAC)
// into the signed balance changes it implies: transfer debits from and credits to, mint credits to, burn and
// clawback debit from, fee debits from (a refund carries a negative amount). Custom-token rows (no asset) give
// none: the judge keeps balances of verified SACs only.
func (w *etlRun) transferBalances(ev rig.Row, topic string) []rig.Row {
	asset, _ := ev["asset"].(string)
	amt, _ := ev["amount"].(string)
	if asset == "" || asset == ":" || amt == "" {
		return nil
	}
	neg := func(a string) string {
		if strings.HasPrefix(a, "-") {
			return a[1:]
		}
		if a == "0" {
			return a
		}
		return "-" + a
	}
	mk := func(holder, amount string) rig.Row {
		b := w.base("export_token_transfer", ev["ledger"].(uint32))
		b["kind"], b["holder"], b["asset"], b["amount"], b["reason"], b["fee"] = "balance_change", holder, asset, amount, topic, topic == "fee"
		for _, k := range []string{"tx_hash", "tx_index", "op_index", "contract"} {
			if v, ok := ev[k]; ok {
				b[k] = v
			}
		}
		return b
	}
	from, _ := ev["from"].(string)
	to, _ := ev["to"].(string)
	var out []rig.Row
	switch topic {
	case "transfer":
		if from != "" {
			out = append(out, mk(from, neg(amt)))
		}
		if to != "" {
			out = append(out, mk(to, amt))
		}
	case "mint":
		if to != "" {
			out = append(out, mk(to, amt))
		}
	case "burn", "clawback", "fee":
		if from != "" {
			out = append(out, mk(from, neg(amt)))
		}
	}
	return out
}

func tokenAsset(r map[string]any) string {
	if a := str(r["asset"]); a != "" {
		// token_transfer writes "credit_alphanum4:CODE:ISSUER"; the judge wants "CODE:ISSUER".
		for _, p := range []string{"credit_alphanum4:", "credit_alphanum12:"} {
			a = strings.TrimPrefix(a, p)
		}
		if a == "native" || strings.Contains(a, ":") {
			return a
		}
	}
	if str(r["asset_type"]) == "" {
		return "" // a custom (non-SAC) token: no classic asset
	}
	return assetOf(str(r["asset_type"]), str(r["asset_code"]), str(r["asset_issuer"]))
}

// rawOrFloat gives a balance column as raw units: stellar-etl writes classic balances as float64 lumps of
// 7-decimal units, so the value is marked inexact.
func rawOrFloat(v any, row rig.Row) string {
	if n, ok := v.(json.Number); ok {
		if raw, ok := rig.Raw(n.String(), 7); ok {
			row["exact"] = false
			return raw
		}
	}
	return str(v)
}

func accountKey(a string) (string, bool) {
	var id xdr.AccountId
	if err := id.SetAddress(a); err != nil {
		return "", false
	}
	k := xdr.LedgerKey{Type: xdr.LedgerEntryTypeAccount, Account: &xdr.LedgerKeyAccount{AccountId: id}}
	s, err := k.MarshalBinaryBase64()
	return s, err == nil
}

// accountOfKey is the account strkey of an account LedgerKey's XDR.
func accountOfKey(raw []byte) string {
	var k xdr.LedgerKey
	if err := k.UnmarshalBinary(raw); err != nil || k.Account == nil {
		return ""
	}
	pk := k.Account.AccountId.Ed25519
	if pk == nil {
		return ""
	}
	s, _ := strkey.Encode(strkey.VersionByteAccountID, pk[:])
	return s
}

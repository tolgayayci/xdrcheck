package stellaretl

// Effects and operations' asset_balance_changes mapped to judge rows of their own kinds:
//
//   - effect_balance_change: every amount-bearing effect, signed from the holder's side (the same effect set and
//     reading as the Horizon rig: credits and debits, account creation's starting balance, trades, pool deposits,
//     withdrawals and trades, claimable balances created / claimed / clawed back, revoked pool reserves). Effects
//     carry no fees.
//   - entry_change: the entries the effects say were created, removed or changed, and the attribute values they
//     state (signers, thresholds, flags, home domain, trustline limit and authorization, data values, sponsors).
//   - op_token_event: each entry of an invoke_host_function operation's asset_balance_changes.
//
// An effect's context comes from its operation (type and source), so effects are mapped after the segment's
// export_operations rows are read.

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/tolgayayci/xdrcheck/go/internal/rig"
)

type opKey struct {
	ledger uint32
	tx, op int
}

type opCtx struct {
	typ, source string
}

// opContext is the operations of a segment by (ledger, tx, op).
type opContext map[opKey]opCtx

func (c opContext) add(r map[string]any, l uint32) {
	_, tx, op := toid(num(r["id"]))
	c[opKey{l, tx, op}] = opCtx{typ: str(r["type_string"]), source: str(r["source_account"])}
}

// opTokenEvents maps an operation's asset_balance_changes to op_token_event rows.
func (w *etlRun) opTokenEvents(r map[string]any, l uint32) []rig.Row {
	d, _ := r["details"].(map[string]any)
	list, _ := d["asset_balance_changes"].([]any)
	_, tx, op := toid(num(r["id"]))
	var out []rig.Row
	for i, it := range list {
		m, _ := it.(map[string]any)
		asset := assetOf(str(m["asset_type"]), str(m["asset_code"]), str(m["asset_issuer"]))
		row := w.base("export_operations", l)
		row["kind"], row["tx_index"], row["op_index"], row["event_index"] = "op_token_event", tx, op, i
		row["contract"], row["asset"], row["event"] = w.sacOf(asset), asset, str(m["type"])
		row["from"], row["to"] = str(m["from"]), str(m["to"])
		if amt, ok := rig.Raw(str(m["amount"]), 7); ok {
			row["amount"] = amt
		} else {
			row["amount"], row["exact"] = str(m["amount"]), false
		}
		if mx := str(m["destination_muxed_id"]); mx != "" {
			row["to_muxed_id"] = mx
		}
		out = append(out, row)
	}
	return out
}

// sacOf is the SAC id of a classic asset string under the run's passphrase.
func (w *etlRun) sacOf(asset string) string {
	var a xdr.Asset
	switch {
	case asset == "native":
		a = xdr.MustNewNativeAsset()
	default:
		code, issuer, ok := strings.Cut(asset, ":")
		if !ok {
			return ""
		}
		var err error
		if a, err = xdr.NewCreditAsset(code, issuer); err != nil {
			return ""
		}
	}
	id, err := a.ContractID(w.o.Passphrase)
	if err != nil {
		return ""
	}
	return strkey.MustEncode(strkey.VersionByteContract, id[:])
}

// effectRows maps one export_effects row.
func (w *etlRun) effectRows(r map[string]any, l uint32, ops opContext, clawedCB map[opKey]string) []rig.Row {
	_, tx, op := toid(num(r["operation_id"]))
	key := opKey{l, tx, op}
	ctx := ops[key]
	typ := str(r["type_string"])
	d, _ := r["details"].(map[string]any)
	acct := str(r["address"])
	var out []rig.Row
	bal := func(holder, asset, amount string, sign int) {
		row := w.base("export_effects", l)
		row["kind"], row["tx_index"], row["op_index"] = "effect_balance_change", tx, op
		amt, ok := rig.Raw(amount, 7)
		if !ok {
			amt, row["exact"] = amount, false
		}
		if sign < 0 && amt != "0" {
			amt = "-" + strings.TrimPrefix(amt, "-")
		}
		row["holder"], row["asset"], row["amount"], row["reason"], row["fee"] = holder, asset, amt, typ, false
		if holder == acct {
			if mx := str(r["address_muxed"]); mx != "" {
				row["muxed"] = mx
			}
		}
		out = append(out, row)
	}
	det := func(prefix string) string {
		return assetOf(str(d[prefix+"asset_type"]), str(d[prefix+"asset_code"]), str(d[prefix+"asset_issuer"]))
	}
	reserves := func(k string) []map[string]any {
		list, _ := d[k].([]any)
		var o []map[string]any
		for _, it := range list {
			if m, ok := it.(map[string]any); ok {
				o = append(o, m)
			}
		}
		return o
	}
	poolID := func() string {
		if lp, ok := d["liquidity_pool"].(map[string]any); ok {
			return str(lp["id"])
		}
		return str(d["liquidity_pool_id"])
	}
	switch typ {
	case "account_created":
		// In invoke_host_function an account created by a SAC transfer also gets account_credited.
		if ctx.typ != "invoke_host_function" {
			bal(acct, "native", str(d["starting_balance"]), 1)
		}
	case "account_credited", "account_debited":
		sign := map[bool]int{true: -1, false: 1}[typ == "account_debited"]
		bal(acct, det(""), str(d["amount"]), sign)
		if b, ok := clawedCB[key]; ok && typ == "account_credited" {
			bal(b, det(""), str(d["amount"]), -1)
		}
	case "contract_credited", "contract_debited":
		bal(str(d["contract"]), det(""), str(d["amount"]), map[bool]int{true: -1, false: 1}[typ == "contract_debited"])
	case "trade":
		// A path payment's source has account_debited / account_credited for the payment; its trade effects
		// would count it twice.
		if strings.HasPrefix(ctx.typ, "path_payment") && ctx.source == acct {
			break
		}
		bal(acct, det("bought_"), str(d["bought_amount"]), 1)
		bal(acct, det("sold_"), str(d["sold_amount"]), -1)
	case "liquidity_pool_deposited", "liquidity_pool_withdrew":
		k, sign := "reserves_deposited", -1
		if typ == "liquidity_pool_withdrew" {
			k, sign = "reserves_received", 1
		}
		pool := poolStrkey(poolID())
		for _, m := range reserves(k) {
			bal(acct, str(m["asset"]), str(m["amount"]), sign)
			if pool != "" {
				bal(pool, str(m["asset"]), str(m["amount"]), -sign)
			}
		}
	case "liquidity_pool_trade":
		if pool := poolStrkey(poolID()); pool != "" {
			b, _ := d["bought"].(map[string]any)
			s, _ := d["sold"].(map[string]any)
			bal(pool, str(b["asset"]), str(b["amount"]), 1)
			bal(pool, str(s["asset"]), str(s["amount"]), -1)
		}
	case "liquidity_pool_revoked":
		if pool := poolStrkey(poolID()); pool != "" {
			for _, m := range reserves("reserves_revoked") {
				bal(pool, str(m["asset"]), str(m["amount"]), -1)
			}
		}
	case "claimable_balance_created", "claimable_balance_claimed", "claimable_balance_clawed_back":
		if amt := str(d["amount"]); amt != "" {
			bal(cbStrkey(str(d["balance_id"])), str(d["asset"]), amt, map[bool]int{true: 1, false: -1}[typ == "claimable_balance_created"])
		}
	}
	return append(out, w.effectEntryRows(r, l, tx, op, typ, acct, d)...)
}

// effectEntryRows maps an effect to entry rows (see the package comment above).
func (w *etlRun) effectEntryRows(r map[string]any, l uint32, tx, op int, typ, acct string, d map[string]any) []rig.Row {
	mk := func(etype string, kv ...string) rig.Row {
		row := w.base("export_effects", l)
		row["kind"], row["tx_index"], row["op_index"], row["entry_type"], row["account"], row["reason"] = "entry_change", tx, op, etype, acct, typ
		for i := 0; i+1 < len(kv); i += 2 {
			if kv[i+1] != "" || kv[i] == "new" && etype == "account" && kv[0] == "field" && kv[1] == "home_domain" {
				row[kv[i]] = kv[i+1]
			}
		}
		return row
	}
	trust := func(owner string, kv ...string) rig.Row {
		row := mk("trustline", kv...)
		row["account"] = owner
		if str(d["asset_type"]) == "liquidity_pool_shares" || str(d["liquidity_pool_id"]) != "" && str(d["asset_code"]) == "" && str(d["asset"]) == "" {
			row["pool"] = str(d["liquidity_pool_id"])
		} else if a := str(d["asset"]); a != "" && str(d["asset_code"]) == "" {
			row["asset"] = a
		} else {
			row["asset"] = assetOf(str(d["asset_type"]), str(d["asset_code"]), str(d["asset_issuer"]))
		}
		return row
	}
	data := func(name string, kv ...string) rig.Row {
		row := mk("data", kv...)
		row["data_name"] = name
		return row
	}
	hexOfB64 := func(v string) string {
		b, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return "undecodable:" + v
		}
		return hex.EncodeToString(b)
	}
	bits := func(table []struct {
		key string
		bit int64
	}) []rig.Row {
		var set, clear int64
		for _, t := range table {
			v, ok := d[t.key]
			if !ok {
				continue
			}
			if v == true {
				set |= t.bit
			} else {
				clear |= t.bit
			}
		}
		return []rig.Row{rig.Row{"set": set, "clear": clear}}
	}
	flagRows := func(base func(kv ...string) rig.Row, b rig.Row) []rig.Row {
		set, clear := b["set"].(int64), b["clear"].(int64)
		var out []rig.Row
		if set != 0 || clear == 0 {
			out = append(out, base("field", "flags:set", "new", strconv.FormatInt(set, 10)))
		}
		if clear != 0 {
			out = append(out, base("field", "flags:clear", "new", strconv.FormatInt(clear, 10)))
		}
		return out
	}
	raw := func(v string) string {
		if x, ok := rig.Raw(v, 7); ok {
			return x
		}
		return v
	}
	switch typ {
	case "account_created":
		return []rig.Row{mk("account", "change", "created")}
	case "account_removed":
		return []rig.Row{mk("account", "change", "removed")}
	case "trustline_created":
		return []rig.Row{trust(acct, "change", "created"), trust(acct, "field", "limit", "new", raw(str(d["limit"])))}
	case "trustline_removed":
		return []rig.Row{trust(acct, "change", "removed")}
	case "trustline_updated":
		return []rig.Row{trust(acct, "field", "limit", "new", raw(str(d["limit"])))}
	case "trustline_flags_updated":
		owner := str(d["trustor"])
		b := bits([]struct {
			key string
			bit int64
		}{{"authorized_flag", 1}, {"authorized_to_maintain_liabilites", 2}, {"authorized_to_maintain_liabilites_flag", 2}, {"authorized_to_maintain_liabilities_flag", 2}, {"clawback_enabled_flag", 4}})
		return flagRows(func(kv ...string) rig.Row { return trust(owner, kv...) }, b[0])
	case "account_flags_updated":
		b := bits([]struct {
			key string
			bit int64
		}{{"auth_required_flag", 1}, {"auth_revocable_flag", 2}, {"auth_immutable_flag", 4}, {"auth_clawback_enabled_flag", 8}})
		return flagRows(func(kv ...string) rig.Row { return mk("account", kv...) }, b[0])
	case "signer_created", "signer_updated", "signer_removed":
		k := signerKeyHex(str(d["public_key"]))
		if typ == "signer_removed" {
			return []rig.Row{mk("account", "field", "signer:"+k)}
		}
		return []rig.Row{mk("account", "field", "signer:"+k, "new", str(d["weight"]))}
	case "account_thresholds_updated":
		var out []rig.Row
		for _, t := range []struct{ k, f string }{{"low_threshold", "low"}, {"med_threshold", "med"}, {"high_threshold", "high"}} {
			if v := str(d[t.k]); v != "" {
				out = append(out, mk("account", "field", "threshold:"+t.f, "new", v))
			}
		}
		return out
	case "account_home_domain_updated":
		return []rig.Row{mk("account", "field", "home_domain", "new", hex.EncodeToString([]byte(str(d["home_domain"]))))}
	case "data_created":
		return []rig.Row{data(str(d["name"]), "change", "created"), data(str(d["name"]), "field", "value", "new", hexOfB64(str(d["value"])))}
	case "data_removed":
		return []rig.Row{data(str(d["name"]), "change", "removed")}
	case "data_updated":
		return []rig.Row{data(str(d["name"]), "field", "value", "new", hexOfB64(str(d["value"])))}
	}
	// Sponsorship of accounts, trustlines and data entries.
	sp := func(base func(kv ...string) rig.Row) []rig.Row {
		switch {
		case strings.HasSuffix(typ, "_sponsorship_created"):
			return []rig.Row{base("field", "sponsor", "new", str(d["sponsor"]))}
		case strings.HasSuffix(typ, "_sponsorship_removed"):
			return []rig.Row{base("field", "sponsor", "old", str(d["former_sponsor"]))}
		case strings.HasSuffix(typ, "_sponsorship_updated"):
			return []rig.Row{base("field", "sponsor", "old", str(d["former_sponsor"]), "new", str(d["new_sponsor"]))}
		}
		return nil
	}
	switch {
	case strings.HasPrefix(typ, "account_sponsorship_"):
		return sp(func(kv ...string) rig.Row { return mk("account", kv...) })
	case strings.HasPrefix(typ, "trustline_sponsorship_"):
		return sp(func(kv ...string) rig.Row { return trust(acct, kv...) })
	case strings.HasPrefix(typ, "data_sponsorship_"):
		return sp(func(kv ...string) rig.Row { return data(str(d["data_name"]), kv...) })
	}
	return nil
}

// signerKeyHex is a signer strkey (G, T, X, P) as its version byte and payload in hex, the judge's spelling.
func signerKeyHex(k string) string {
	vb, payload, err := strkey.DecodeAny(k)
	if err != nil {
		return "unparsed:" + k
	}
	return hex.EncodeToString(append([]byte{byte(vb)}, payload...))
}

// poolStrkey is a liquidity pool id (hex) as an L… strkey.
func poolStrkey(id string) string {
	b, err := hex.DecodeString(id)
	if err != nil || len(b) != 32 {
		return ""
	}
	s, err := strkey.Encode(strkey.VersionByteLiquidityPool, b)
	if err != nil {
		return ""
	}
	return s
}

// cbStrkey is a claimable balance id (hex of the XDR ClaimableBalanceID: 4-byte type, 32-byte hash) as a B…
// strkey (1-byte type, hash).
func cbStrkey(id string) string {
	b, err := hex.DecodeString(id)
	if err != nil || len(b) != 36 {
		return fmt.Sprintf("unparsed:%s", id)
	}
	s, err := strkey.Encode(strkey.VersionByteClaimableBalance, append([]byte{b[3]}, b[4:]...))
	if err != nil {
		return fmt.Sprintf("unparsed:%s", id)
	}
	return s
}

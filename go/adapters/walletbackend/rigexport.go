package walletbackend

// Exporters: every table wallet-backend writes, dumped verbatim (tables/<table>.jsonl) and mapped to the common
// rows (ROW_SCHEMA in the rig package docs). Tables with no mapping are carried as `other` rows, so nothing the
// service wrote is left out; the report lists them.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/tolgayayci/xdrcheck/go/internal/rig"
)

// Tables that are the service's own bookkeeping, dumped but not mapped to rows.
var bookkeeping = map[string]bool{"ingest_store": true, "gorp_migrations": true, "migrations": true, "protocols": true,
	"schema_migrations": true}

// Tables mapped to `other` rows on purpose (no common kind fits; the judge does not read them).
var asOther = map[string]bool{"contract_tokens": true, "trustline_assets": true, "protocol_wasms": true, "protocol_contracts": true,
	"liquidity_pools": true, "sep41_allowances": true, "transaction_hashes": true}

func (w *rigRun) export(ctx context.Context) (int, error) {
	out, err := w.db.Query(ctx, w.dbName, "SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE' ORDER BY 1")
	if err != nil {
		return 0, err
	}
	tables := strings.Fields(out)
	dir := filepath.Join(w.o.Out, "tables")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, err
	}
	for _, t := range tables {
		n, err := w.dumpTable(ctx, t, filepath.Join(dir, t+".jsonl"))
		if err != nil {
			return 0, err
		}
		w.rep.Tables[t] = n
	}
	rows, err := rig.CreateJSONL(filepath.Join(w.o.Out, rowsFile))
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	m := &mapper{commit: w.commit, passphrase: w.o.Passphrase, tokens: map[string]token{}, assets: map[string]string{}}
	m.load(filepath.Join(dir, "contract_tokens.jsonl"), func(r map[string]any) {
		m.tokens[str(r["id"])] = token{contract: str(r["contract_id"]), typ: str(r["type"]), code: str(r["code"]), issuer: str(r["issuer"])}
	})
	m.load(filepath.Join(dir, "trustline_assets.jsonl"), func(r map[string]any) {
		m.assets[str(r["id"])] = str(r["code"]) + ":" + str(r["issuer"])
	})
	m.bycontract = map[string]token{}
	for _, t := range m.tokens {
		m.bycontract[t.contract] = t
	}
	if id, err := xdr.MustNewNativeAsset().ContractID(w.o.Passphrase); err == nil {
		m.native = strkey.MustEncode(strkey.VersionByteContract, id[:])
	}
	for _, t := range tables {
		if bookkeeping[t] || w.rep.Tables[t] == 0 {
			continue
		}
		mapped := true
		err := m.load(filepath.Join(dir, t+".jsonl"), func(r map[string]any) {
			for _, row := range m.mapRow(t, r) {
				rows.Write(row)
			}
		})
		if err != nil {
			return 0, err
		}
		if !m.known(t) {
			mapped = false
		}
		if !mapped {
			w.rep.Unmapped[t] = w.rep.Tables[t]
		}
	}
	return rows.Count(), nil
}

type token struct{ contract, typ, code, issuer string }

type mapper struct {
	commit, passphrase, native string
	tokens                     map[string]token  // contract_tokens.id → token
	bycontract                 map[string]token  // contract strkey → token
	assets                     map[string]string // trustline_assets.id → CODE:ISSUER
}

func (m *mapper) load(path string, f func(map[string]any)) error {
	fh, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer fh.Close()
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 1<<20), 256<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.UseNumber()
		var r map[string]any
		if err := dec.Decode(&r); err != nil {
			return fmt.Errorf("%s: %v", path, err)
		}
		f(r)
	}
	return sc.Err()
}

func (m *mapper) known(t string) bool {
	switch t {
	case "transactions", "operations", "transactions_accounts", "operations_accounts", "state_changes", "native_balances",
		"trustline_balances", "sac_balances", "sep41_balances", "liquidity_pool_balances":
		return true
	}
	return asOther[t] || strings.HasPrefix(t, "blend_")
}

func str(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case json.Number:
		return x.String()
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func num(v any) int64 {
	if n, ok := v.(json.Number); ok {
		i, _ := n.Int64()
		return i
	}
	return 0
}

// addr turns a stored address (bytea `\x<version byte><32 bytes>`, or strkey text) into a strkey.
func addr(v any) string {
	s := str(v)
	h, ok := strings.CutPrefix(s, `\x`)
	if !ok {
		return s
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return s
	}
	if len(b) == 33 {
		switch b[0] {
		case byte(strkey.VersionByteAccountID), byte(strkey.VersionByteContract), byte(strkey.VersionByteLiquidityPool), byte(strkey.VersionByteClaimableBalance):
			if k, err := strkey.Encode(strkey.VersionByte(b[0]), b[1:]); err == nil {
				return k
			}
		}
	}
	if len(b) == 32 {
		if k, err := strkey.Encode(strkey.VersionByteContract, b); err == nil {
			return k
		}
	}
	return h
}

func hexOf(v any) string { return strings.TrimPrefix(str(v), `\x`) }

// toid splits a TOID into ledger, 0-based tx index and 0-based op index (-1: the transaction itself).
func toid(id int64) (ledger uint32, tx int, op int) {
	return uint32(id >> 32), int((id>>12)&0xFFFFF) - 1, int(id&0xFFF) - 1
}

func (m *mapper) base(source string, ledger uint32) rig.Row {
	return rig.Row{"pipeline": "wallet-backend", "commit": m.commit, "source": source, "ledger": ledger, "exact": true}
}

func (m *mapper) assetOf(contract string) string {
	if contract == m.native && contract != "" {
		return "native"
	}
	if t, ok := m.bycontract[contract]; ok && t.typ == "SAC" {
		if t.code == "" && t.issuer == "" {
			return "native"
		}
		return t.code + ":" + t.issuer
	}
	return contract
}

func (m *mapper) mapRow(t string, r map[string]any) []rig.Row {
	switch t {
	case "transactions":
		l, tx, _ := toid(num(r["to_id"]))
		if ln := num(r["ledger_number"]); ln > 0 {
			l = uint32(ln)
		}
		row := m.base(t, l)
		rc := str(r["result_code"])
		row["kind"], row["tx_index"], row["tx_hash"] = "tx", tx, hexOf(r["hash"])
		row["result_code"], row["fee_charged"] = rc, str(r["fee_charged"])
		row["success"] = strings.Contains(strings.ToLower(rc), "success")
		if v, ok := r["is_fee_bump"]; ok {
			row["fee_bump"] = v
		}
		return []rig.Row{row}
	case "operations":
		l, tx, op := toid(num(r["id"]))
		row := m.base(t, l)
		row["kind"], row["tx_index"], row["op_index"] = "operation", tx, op
		row["op_type"], row["result_code"], row["success"] = str(r["operation_type"]), str(r["result_code"]), r["successful"]
		return []rig.Row{row}
	case "transactions_accounts":
		l, tx, _ := toid(num(r["tx_to_id"]))
		row := m.base(t, l)
		row["kind"], row["tx_index"], row["holder"], row["role"] = "participant", tx, addr(r["account_id"]), "transaction"
		return []rig.Row{row}
	case "operations_accounts":
		l, tx, op := toid(num(r["operation_id"]))
		row := m.base(t, l)
		// Operation-level participants repeat the transaction-level ones (transactions_accounts); the judge
		// compares participants per transaction, so these go out under their own kind.
		row["kind"], row["tx_index"], row["op_index"], row["holder"], row["role"] = "op_participant", tx, op, addr(r["account_id"]), "operation"
		return []rig.Row{row}
	case "state_changes":
		l, tx, _ := toid(num(r["to_id"]))
		if ln := num(r["ledger_number"]); ln > 0 {
			l = uint32(ln)
		}
		row := m.base(t, l)
		row["tx_index"] = tx
		opid := num(r["operation_id"])
		if opid != 0 {
			_, _, op := toid(opid)
			row["op_index"] = op
		}
		cat, reason := str(r["state_change_category"]), str(r["state_change_reason"])
		if cat == "BALANCE" && (reason == "CREDIT" || reason == "DEBIT" || reason == "MINT" || reason == "BURN") {
			amt := str(r["amount"])
			if reason == "DEBIT" || reason == "BURN" {
				if strings.HasPrefix(amt, "-") {
					amt = strings.TrimPrefix(amt, "-")
				} else if amt != "" && amt != "0" {
					amt = "-" + amt
				}
			}
			// Every balance row goes out as a balance change, named by its token's contract: the judge maps a
			// verified SAC id to its asset and calls anything else a non-SAC contract. Nothing here depends on
			// which tokens the service itself has classified.
			contract := addr(r["token_id"])
			asset := contract
			if contract == m.native && contract != "" {
				asset = "native"
			}
			row["kind"], row["holder"], row["contract"], row["asset"], row["amount"] = "balance_change", addr(r["account_id"]), contract, asset, amt
			row["reason"], row["fee"] = reason, opid == 0
			if mx := str(r["to_muxed_id"]); mx != "" {
				row["to_muxed_id"] = mx
			}
			return []rig.Row{row}
		}
		entries := m.entryRows(row, cat, reason, r)
		row["kind"], row["category"], row["reason"], row["address"] = "state_change", cat, reason, addr(r["account_id"])
		data := map[string]any{}
		for k, v := range r {
			if v == nil || k == "ingested_at" || k == "ledger_created_at" {
				continue
			}
			if strings.HasSuffix(k, "_account_id") || k == "account_id" || k == "token_id" {
				v = addr(v)
			}
			data[k] = v
		}
		row["data"] = data
		return append(entries, row)
	case "native_balances":
		return []rig.Row{m.balance(t, r, addr(r["account_id"]), "native", "", str(r["balance"]))}
	case "trustline_balances":
		return []rig.Row{m.balance(t, r, addr(r["account_id"]), m.assets[str(r["asset_id"])], "", str(r["balance"]))}
	case "sac_balances", "sep41_balances":
		tk := m.tokens[str(r["contract_id"])]
		asset := tk.contract
		if tk.typ == "SAC" {
			asset = m.assetOf(tk.contract)
		}
		return []rig.Row{m.balance(t, r, addr(r["account_id"]), asset, tk.contract, str(r["balance"]))}
	case "liquidity_pool_balances":
		return []rig.Row{m.balance(t, r, addr(r["account_id"]), "pool:"+str(r["pool_id"]), "", str(r["shares"]))}
	}
	// other: verbatim
	row := m.base(t, uint32(num(r["last_modified_ledger"])))
	if l := num(r["ledger_number"]); l > 0 {
		row["ledger"] = uint32(l)
	}
	row["kind"], row["table"] = "other", t
	data := map[string]any{}
	keys := make([]string, 0, len(r))
	for k := range r {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := r[k]
		if s, ok := v.(string); ok && strings.HasPrefix(s, `\x`) && (strings.HasSuffix(k, "_id") || strings.Contains(k, "address") || k == "account_id") {
			v = addr(v)
		}
		data[k] = v
	}
	row["data"] = data
	return []rig.Row{row}
}

func (m *mapper) balance(t string, r map[string]any, holder, asset, contract, amount string) rig.Row {
	row := m.base(t, uint32(num(r["last_modified_ledger"])))
	row["kind"], row["holder"], row["asset"], row["amount"] = "balance", holder, asset, amount
	if contract != "" {
		row["contract"] = contract
	}
	return row
}

// entryRows maps one state change to the judge's entry rows: a lifecycle row (`change`) for an entry created or
// removed, and an attribute row (`field`, `old`, `new`) for each value the row states. Entries are named by
// parts (entry_type, account, token / pool, data_name); the judge resolves a trustline's token (a SAC id) to its
// asset from the ledger. Signer keys are the stored bytes (version byte and payload) as they are, whatever their
// length. Flag bits are translated from wallet-backend's own bit layout to the XDR flags.
func (m *mapper) entryRows(base rig.Row, cat, reason string, r map[string]any) []rig.Row {
	acct := addr(r["account_id"])
	mk := func(etype string, kv ...any) rig.Row {
		x := rig.Row{}
		for k, v := range base {
			x[k] = v
		}
		x["kind"], x["entry_type"], x["account"], x["category"], x["reason"] = "entry_change", etype, acct, cat, reason
		for i := 0; i+1 < len(kv); i += 2 {
			if v, ok := kv[i+1].(string); ok && v == "" {
				continue
			}
			x[kv[i].(string)] = kv[i+1]
		}
		return x
	}
	trust := func(kv ...any) rig.Row {
		x := mk("trustline", kv...)
		if p := str(r["liquidity_pool_id"]); p != "" {
			x["pool"] = strings.TrimPrefix(p, `\x`)
		} else {
			x["token"] = addr(r["token_id"])
		}
		return x
	}
	opt := func(k string) string { return str(r[k]) }
	switch cat {
	case "ACCOUNT":
		change := map[string]string{"CREATE": "created", "MERGE": "removed"}[reason]
		if change == "" {
			return nil
		}
		if strings.HasPrefix(acct, "C") {
			// A contract deployed is written as ACCOUNT/CREATE of the contract: its instance entry.
			k, err := InstanceKey(acct)
			if err != nil {
				return nil
			}
			x := mk("contract_data", "change", change, "entry_key", k)
			delete(x, "account")
			return []rig.Row{x}
		}
		return []rig.Row{mk("account", "change", change)}
	case "TRUSTLINE":
		switch reason {
		case "ADD":
			return []rig.Row{trust("change", "created"), trust("field", "limit", "new", rawLimit(opt("trustline_limit_new")))}
		case "REMOVE":
			return []rig.Row{trust("change", "removed")}
		case "UPDATE":
			return []rig.Row{trust("field", "limit", "old", rawLimit(opt("trustline_limit_old")), "new", rawLimit(opt("trustline_limit_new")))}
		}
	case "BALANCE_AUTHORIZATION":
		f := map[string]string{"SET": "flags:set", "CLEAR": "flags:clear"}[reason]
		if f == "" {
			return nil
		}
		return []rig.Row{trust("field", f, "new", strconv.FormatInt(xdrBits(num(r["flags"]), trustlineBits), 10))}
	case "FLAGS":
		f := map[string]string{"SET": "flags:set", "CLEAR": "flags:clear"}[reason]
		if f == "" {
			return nil
		}
		return []rig.Row{mk("account", "field", f, "new", strconv.FormatInt(xdrBits(num(r["flags"]), accountBits), 10))}
	case "SIGNER":
		key := signerHex(r["signer_account_id"])
		if key == "" {
			return nil
		}
		return []rig.Row{mk("account", "field", "signer:"+key, "old", opt("signer_weight_old"), "new", opt("signer_weight_new"))}
	case "SIGNATURE_THRESHOLD":
		lvl := map[string]string{"LOW": "low", "MEDIUM": "med", "HIGH": "high"}[opt("threshold")]
		if lvl == "" {
			return nil
		}
		return []rig.Row{mk("account", "field", "threshold:"+lvl, "old", opt("threshold_old"), "new", opt("threshold_new"))}
	case "HOME_DOMAIN":
		old, nw := kvText(r, "old"), kvText(r, "new")
		x := mk("account", "field", "home_domain")
		if old != nil {
			x["old"] = hex.EncodeToString([]byte(*old))
		}
		if nw != nil {
			x["new"] = hex.EncodeToString([]byte(*nw))
		}
		return []rig.Row{x}
	case "DATA_ENTRY":
		data := func(kv ...any) rig.Row {
			x := mk("data", kv...)
			x["data_name"] = opt("data_entry_name")
			return x
		}
		val := func(side string) string {
			v := kvText(r, side)
			if v == nil {
				return ""
			}
			b, err := base64.StdEncoding.DecodeString(*v)
			if err != nil {
				return "undecodable:" + *v
			}
			return hex.EncodeToString(b)
		}
		switch reason {
		case "ADD":
			return []rig.Row{data("change", "created"), data("field", "value", "new", val("new"))}
		case "REMOVE":
			return []rig.Row{data("change", "removed")}
		case "UPDATE":
			return []rig.Row{data("field", "value", "old", val("old"), "new", val("new"))}
		}
	}
	return nil
}

// rawLimit gives a trustline limit in raw units: the service stores a new limit as a 7-decimal amount and an old
// one as raw units.
func rawLimit(v string) string {
	if strings.Contains(v, ".") {
		if raw, ok := rig.Raw(v, 7); ok {
			return raw
		}
	}
	return v
}

// wallet-backend's flag bits (types.FlagBit*) → XDR account and trustline flags.
var (
	accountBits   = map[int64]int64{1 << 1: 1, 1 << 2: 2, 1 << 3: 4, 1 << 4: 8}
	trustlineBits = map[int64]int64{1 << 0: 1, 1 << 6: 2, 1 << 5: 4}
)

func xdrBits(stored int64, table map[int64]int64) int64 {
	var out int64
	for from, to := range table {
		if stored&from != 0 {
			out |= to
		}
	}
	return out
}

// signerHex is a stored signer key (bytea: version byte, payload) as hex, verbatim; a strkey text value is
// decoded to the same bytes.
func signerHex(v any) string {
	s := str(v)
	if h, ok := strings.CutPrefix(s, `\x`); ok {
		return strings.ToLower(h)
	}
	if s == "" {
		return ""
	}
	if vb, payload, err := strkey.DecodeAny(s); err == nil {
		return hex.EncodeToString(append([]byte{byte(vb)}, payload...))
	}
	return "unparsed:" + s
}

// kvText is one side ("old" / "new") of a state change's key_value payload.
func kvText(r map[string]any, side string) *string {
	kv, ok := r["key_value"].(map[string]any)
	if !ok {
		if s, ok := r["key_value"].(string); ok {
			_ = json.Unmarshal([]byte(s), &kv)
		}
	}
	v, ok := kv[side]
	if !ok || v == nil {
		return nil
	}
	t := str(v)
	return &t
}

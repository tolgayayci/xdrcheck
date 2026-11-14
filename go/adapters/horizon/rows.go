package horizon

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// Common rows (the rig row schema shared with the wallet-backend and stellar-etl rigs; kinds and field names follow
// the judge's facts). Every row has kind, pipeline ("horizon"), commit, source (the Horizon table), ledger,
// tx_index / tx_hash / op_index where the table has them, and exact (always true: Horizon stores integers and
// 7-decimal strings, both converted without floats). tx_index and op_index are 0-based in apply order; Horizon's
// application orders are 1-based. Amounts are integer strings in the smallest unit.
//
// Mapped: history_ledgers → ledger; history_transactions → tx; history_operations → operation, and each entry
// of an invoke_host_function's asset_balance_changes → token_event; history_effects → balance_change for every
// amount-bearing effect (signed from the holder's side; Horizon has no fee effects, so fee is always false) and
// entry_change where the effect states an entry's lifecycle (deduplicated per operation, key and change);
// history_transaction_participants → participant (holder). Trades, operation participants and the
// claimable-balance / liquidity-pool link tables → other (verbatim). Rows are written sorted by ledger, as the
// judge (crates/xdrcheck-judge) reads them; its row fields (holder, entry_key, amount, ...) are all present.

// Row is one common row.
type Row map[string]any

const pipeline = "horizon"

type rawLine map[string]any

func (r rawLine) str(k string) string {
	switch v := r[k].(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	case bool:
		return fmt.Sprint(v)
	}
	return ""
}

func (r rawLine) strp(k string) *string {
	if v, ok := r[k].(string); ok {
		return &v
	}
	return nil
}

func (r rawLine) u32(k string) uint32 {
	n, _ := r[k].(json.Number)
	v, _ := n.Int64()
	return uint32(v)
}

func (r rawLine) obj(k string) rawLine {
	if m, ok := r[k].(map[string]any); ok {
		return rawLine(m)
	}
	return rawLine{}
}

// Stroops converts Horizon's decimal amount ("12.3400000", "-0.0000001", i128 values included) to an integer
// string in the smallest unit, by string arithmetic only.
func Stroops(s string) (string, error) {
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	ip, fp, _ := strings.Cut(s, ".")
	if ip == "" || len(fp) > 7 || strings.Trim(ip+fp, "0123456789") != "" {
		return "", fmt.Errorf("bad amount %q", s)
	}
	d := strings.TrimLeft(ip+fp+strings.Repeat("0", 7-len(fp)), "0")
	if d == "" {
		return "0", nil
	}
	if neg {
		return "-" + d, nil
	}
	return d, nil
}

func negate(s string) string {
	if s == "0" {
		return s
	}
	if strings.HasPrefix(s, "-") {
		return s[1:]
	}
	return "-" + s
}

// assetOf reads Horizon's asset_type / asset_code / asset_issuer (with a prefix) as "native" or "CODE:ISSUER".
func assetOf(r rawLine, prefix string) string {
	t := r.str(prefix + "asset_type")
	if t == "native" {
		return "native"
	}
	if t == "" {
		return ""
	}
	return r.str(prefix+"asset_code") + ":" + r.str(prefix+"asset_issuer")
}

type exporter struct {
	passphrase string
	commit     string
	txHash     map[[2]uint32]string
	pathSource map[[3]uint32]string // path-payment operations → their source account
	invokeOps  map[[3]uint32]bool   // invoke_host_function operations
	clawedCB   map[[3]uint32]string // clawback_claimable_balance operation → the balance's holder (B…)
	sac        map[string]string
	w          *bufio.Writer
	counts     map[string]int
	seen       map[string]bool // entry_change dedup: several effects of one op can state the same change
	err        error
}

func (e *exporter) base(kind, source string, ledger, txo, opo uint32) Row {
	r := Row{"kind": kind, "pipeline": pipeline, "commit": e.commit, "source": source, "ledger": ledger, "exact": true}
	if txo > 0 {
		r["tx_index"] = txo - 1
		r["tx_hash"] = e.txHash[[2]uint32{ledger, txo}]
	}
	if opo > 0 {
		r["op_index"] = opo - 1
	}
	return r
}

func (e *exporter) emit(r Row) {
	if e.err != nil {
		return
	}
	b, err := json.Marshal(r)
	if err != nil {
		e.err = err
		return
	}
	e.counts[r["kind"].(string)]++
	// Prefixed with the ledger for the external sort (the judge reads rows sorted by ledger).
	fmt.Fprintf(e.w, "%010d\t", r["ledger"])
	e.w.Write(b)
	e.err = e.w.WriteByte('\n')
}

func (e *exporter) sacOf(asset string) string {
	if c, ok := e.sac[asset]; ok {
		return c
	}
	var a xdr.Asset
	var err error
	if asset == "native" {
		a = xdr.MustNewNativeAsset()
	} else if code, issuer, ok := strings.Cut(asset, ":"); ok {
		a, err = xdr.NewCreditAsset(code, issuer)
	} else {
		err = fmt.Errorf("bad asset")
	}
	c := ""
	if err == nil {
		if id, err2 := a.ContractID(e.passphrase); err2 == nil {
			c, _ = strkey.Encode(strkey.VersionByteContract, id[:])
		}
	}
	e.sac[asset] = c
	return c
}

// ExportRows maps raw table dumps (tables/<table>.jsonl[.zst]) to common rows, sorted by ledger (stable).
func ExportRows(tablesDir, out, passphrase, commit string, counts map[string]int) error {
	files, err := filepath.Glob(filepath.Join(tablesDir, "*.jsonl*"))
	if err != nil {
		return err
	}
	sort.Strings(files)
	unsorted := out + ".unsorted"
	defer os.Remove(unsorted)
	if err := exportUnsorted(files, unsorted, passphrase, commit, counts); err != nil {
		return err
	}
	return sortByLedger(unsorted, out)
}

// sortByLedger sorts "<ledger>\t<json>" lines with GNU sort (stable, bounded memory) and strips the prefix.
func sortByLedger(in, out string) error {
	cmd := exec.Command("sort", "-s", "-t", "\t", "-k1,1", "-S", "1G", "--parallel=4", "-T", filepath.Dir(out), in)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	f, err := os.Create(out)
	if err != nil {
		return err
	}
	w := bufio.NewWriterSize(f, 1<<20)
	if err := cmd.Start(); err != nil {
		f.Close()
		return err
	}
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 1<<20), 1<<30)
	for sc.Scan() {
		_, row, ok := bytes.Cut(sc.Bytes(), []byte{'\t'})
		if !ok {
			continue
		}
		w.Write(row)
		w.WriteByte('\n')
	}
	if err := sc.Err(); err != nil {
		f.Close()
		return err
	}
	if err := cmd.Wait(); err != nil {
		f.Close()
		return fmt.Errorf("sort: %v: %s", err, stderr.String())
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func exportUnsorted(files []string, out, passphrase, commit string, counts map[string]int) error {
	f, err := os.Create(out)
	if err != nil {
		return err
	}
	w := bufio.NewWriterSize(f, 1<<20)
	e := &exporter{passphrase: passphrase, commit: commit, txHash: map[[2]uint32]string{}, sac: map[string]string{},
		pathSource: map[[3]uint32]string{}, invokeOps: map[[3]uint32]bool{}, clawedCB: map[[3]uint32]string{}, w: w, counts: counts, seen: map[string]bool{}}
	fail := func(err error) error { f.Close(); return err }
	for _, p := range files {
		b := filepath.Base(p)
		if strings.HasPrefix(b, "history_transactions.") || strings.HasPrefix(b, "history_operations.") ||
			strings.HasPrefix(b, "history_effects.") {
			if err := eachRaw(p, func(r rawLine) error {
				switch r.str("table") {
				case "history_transactions":
					e.txHash[[2]uint32{r.u32("ledger"), r.u32("tx_order")}] = r.str("transaction_hash")
				case "history_operations":
					// path_payment_strict_receive (2) and path_payment_strict_send (13)
					k := [3]uint32{r.u32("ledger"), r.u32("tx_order"), r.u32("op_order")}
					switch r.u32("type") {
					case 2, 13:
						e.pathSource[k] = r.str("source_account")
					case 24:
						e.invokeOps[k] = true
					}
				case "history_effects":
					// claimable_balance_clawed_back (80) has no amount; remember its balance per operation (effect
					// order within an operation is not guaranteed in the dump)
					if r.u32("type") == 80 {
						if h, err := cbStrkey(r.obj("details").str("balance_id")); err == nil {
							e.clawedCB[[3]uint32{r.u32("ledger"), r.u32("tx_order"), r.u32("op_order")}] = h
						}
					}
				}
				return nil
			}); err != nil {
				return fail(err)
			}
		}
	}
	for _, p := range files {
		if err := eachRaw(p, e.row); err != nil {
			return fail(err)
		}
		if e.err != nil {
			return fail(e.err)
		}
	}
	if err := w.Flush(); err != nil {
		return fail(err)
	}
	return f.Close()
}

// xdrName strips the Go XDR enum prefix: "TransactionResultCodeTxSuccess" → "TxSuccess" (the judge's names).
func xdrName(s, prefix string) string { return strings.TrimPrefix(s, prefix) }

func (e *exporter) row(r rawLine) error {
	ledger, txo, opo := r.u32("ledger"), r.u32("tx_order"), r.u32("op_order")
	table := r.str("table")
	switch table {
	case "history_ledgers":
		ct, _ := time.Parse("2006-01-02T15:04:05", r.str("closed_at"))
		x := e.base("ledger", table, ledger, 0, 0)
		x["hash"], x["protocol"], x["close_time"] = r.str("ledger_hash"), r.u32("protocol_version"), ct.Unix()
		x["tx_count"] = r.u32("successful_transaction_count") + r.u32("failed_transaction_count")
		x["failed_count"], x["op_count"] = r.u32("failed_transaction_count"), r.u32("operation_count")
		e.emit(x)
	case "history_transactions":
		x := e.base("tx", table, ledger, txo, 0)
		x["success"], _ = r["successful"].(bool)
		x["fee_charged"], x["op_count"] = r.str("fee_charged"), r.u32("operation_count")
		if h := r.strp("inner_transaction_hash"); h != nil {
			x["inner_hash"] = *h
		}
		var res xdr.TransactionResult
		if err := xdr.SafeUnmarshalBase64(r.str("tx_result"), &res); err == nil {
			x["result_code"] = xdrName(res.Result.Code.String(), "TransactionResultCode")
		} else {
			x["result_code"] = ""
			x["result_decode_error"] = err.Error()
		}
		x["source_account"] = r.str("account")
		for _, k := range []string{"account_muxed", "fee_account", "fee_account_muxed", "memo_type", "memo"} {
			if v := r.strp(k); v != nil {
				x[k] = *v
			}
		}
		e.emit(x)
	case "history_operations":
		x := e.base("operation", table, ledger, txo, opo)
		x["op_type"] = xdrName(xdr.OperationType(r.u32("type")).String(), "OperationType")
		x["source_account"] = r.str("source_account")
		if v := r.strp("source_account_muxed"); v != nil {
			x["source_account_muxed"] = *v
		}
		e.emit(x)
		return e.operation(r, ledger, txo, opo)
	case "history_transaction_participants":
		// One row per (transaction, account): the judge compares participants as a multiset per transaction.
		x := e.base("participant", table, ledger, txo, 0)
		x["holder"], x["address"] = r.str("account"), r.str("account")
		e.emit(x)
	case "history_effects":
		return e.effect(r, ledger, txo, opo)
	default:
		// Trades and the claimable-balance / liquidity-pool link tables: verbatim.
		x := e.base("other", table, ledger, txo, opo)
		data := map[string]any{}
		for k, v := range r {
			if k != "table" {
				data[k] = v
			}
		}
		x["table"], x["data"] = table, data
		e.emit(x)
	}
	return nil
}

// Horizon effect types (internal/db2/history/main.go).
var effectNames = map[uint32]string{
	0: "account_created", 1: "account_removed", 2: "account_credited", 3: "account_debited",
	4: "account_thresholds_updated", 5: "account_home_domain_updated", 6: "account_flags_updated",
	7: "account_inflation_destination_updated", 10: "signer_created", 11: "signer_removed", 12: "signer_updated",
	20: "trustline_created", 21: "trustline_removed", 22: "trustline_updated", 23: "trustline_authorized",
	24: "trustline_deauthorized", 25: "trustline_authorized_to_maintain_liabilities", 26: "trustline_flags_updated",
	33: "trade", 40: "data_created", 41: "data_removed", 42: "data_updated", 43: "sequence_bumped",
	50: "claimable_balance_created", 51: "claimable_balance_claimant_created", 52: "claimable_balance_claimed",
	60: "account_sponsorship_created", 61: "account_sponsorship_updated", 62: "account_sponsorship_removed",
	63: "trustline_sponsorship_created", 64: "trustline_sponsorship_updated", 65: "trustline_sponsorship_removed",
	66: "data_sponsorship_created", 67: "data_sponsorship_updated", 68: "data_sponsorship_removed",
	69: "claimable_balance_sponsorship_created", 70: "claimable_balance_sponsorship_updated",
	71: "claimable_balance_sponsorship_removed", 72: "signer_sponsorship_created",
	73: "signer_sponsorship_updated", 74: "signer_sponsorship_removed",
	80: "claimable_balance_clawed_back", 90: "liquidity_pool_deposited", 91: "liquidity_pool_withdrew",
	92: "liquidity_pool_trade", 93: "liquidity_pool_created", 94: "liquidity_pool_removed",
	95: "liquidity_pool_revoked", 96: "contract_credited", 97: "contract_debited",
}

func (e *exporter) effect(r rawLine, ledger, txo, opo uint32) error {
	typ := r.u32("type")
	name := effectNames[typ]
	if name == "" {
		name = fmt.Sprintf("effect_%d", typ)
	}
	d := r.obj("details")
	acct := r.str("account")
	var mxID string
	if m := r.strp("address_muxed"); m != nil {
		mxID, _ = muxedID(*m)
	}
	where := func(err error) error {
		return fmt.Errorf("ledger %d tx %d op %d effect %s: %v", ledger, txo, opo, name, err)
	}
	bal := func(holder, mx, asset, decimal string, sign int) error {
		amt, err := Stroops(decimal)
		if err != nil {
			return where(err)
		}
		if sign < 0 {
			amt = negate(amt)
		}
		x := e.base("balance_change", "history_effects", ledger, txo, opo)
		x["holder"], x["asset"], x["amount"], x["reason"], x["fee"] = holder, asset, amt, name, false
		if c := e.sacOf(asset); c != "" {
			x["contract"] = c
		}
		if mx != "" {
			x["muxed_id"] = mx
		}
		e.emit(x)
		return nil
	}
	var err error
	switch typ {
	case 0:
		// In invoke_host_function an account created by a SAC transfer also gets account_credited for the same
		// amount; count it once.
		if e.invokeOps[[3]uint32{ledger, txo, opo}] {
			break
		}
		err = bal(acct, mxID, "native", d.str("starting_balance"), 1)
	case 2, 3:
		err = bal(acct, mxID, assetOf(d, ""), d.str("amount"), map[bool]int{true: -1, false: 1}[typ == 3])
		// clawback_claimable_balance: its claimable_balance_clawed_back effect has no amount; the issuer's
		// account_credited in the same operation carries it, and the balance entry loses it.
		if b, ok := e.clawedCB[[3]uint32{ledger, txo, opo}]; ok && typ == 2 && err == nil {
			err = bal(b, "", assetOf(d, ""), d.str("amount"), -1)
		}
	case 96, 97: // SAC balance of a contract; the effect row itself is filed under the operation's source
		err = bal(d.str("contract"), "", assetOf(d, ""), d.str("amount"), map[bool]int{true: -1, false: 1}[typ == 97])
	case 33:
		// In a path payment the source's account_debited and the destination's account_credited already carry
		// the payment; the taker-side trade effects (filed under the source) would count it twice.
		if src, ok := e.pathSource[[3]uint32{ledger, txo, opo}]; ok && src == acct {
			break
		}
		if err = bal(acct, mxID, assetOf(d, "bought_"), d.str("bought_amount"), 1); err == nil {
			err = bal(acct, mxID, assetOf(d, "sold_"), d.str("sold_amount"), -1)
		}
	case 90, 91:
		k, sign := "reserves_deposited", -1
		if typ == 91 {
			k, sign = "reserves_received", 1
		}
		pid := d.obj("liquidity_pool").str("id")
		pool := poolStrkey(&pid)
		list, _ := d[k].([]any)
		for _, it := range list {
			m := rawLine(it.(map[string]any))
			if err = bal(acct, mxID, m.str("asset"), m.str("amount"), sign); err != nil {
				break
			}
			if pool != nil { // the pool's reserves move the other way
				if err = bal(*pool, "", m.str("asset"), m.str("amount"), -sign); err != nil {
					break
				}
			}
		}
	case 50, 52, 80: // the claimable balance entry as holder (B…), as the judge counts it
		holder, herr := cbStrkey(d.str("balance_id"))
		if herr != nil {
			return where(herr)
		}
		amount := d.str("amount")
		if typ == 80 && amount == "" {
			break // amount comes with the issuer's account_credited (case 2)
		}
		err = bal(holder, "", d.str("asset"), amount, map[bool]int{true: 1, false: -1}[typ == 50])
	case 95: // revoked pool-share trust line: the pool's reserves go to claimable balances (their own 50 effects)
		pid := d.obj("liquidity_pool").str("id")
		if pool := poolStrkey(&pid); pool != nil {
			list, _ := d["reserves_revoked"].([]any)
			for _, it := range list {
				m := rawLine(it.(map[string]any))
				if err = bal(*pool, "", m.str("asset"), m.str("amount"), -1); err != nil {
					break
				}
			}
		}
	case 92: // the pool's side of a path-payment hop through it
		pool := d.obj("liquidity_pool").str("id")
		if ps := poolStrkey(&pool); ps != nil {
			if err = bal(*ps, "", d.obj("bought").str("asset"), d.obj("bought").str("amount"), 1); err == nil {
				err = bal(*ps, "", d.obj("sold").str("asset"), d.obj("sold").str("amount"), -1)
			}
		}
	}
	if err != nil {
		return err
	}
	ent := func(typName, change, key string, kerr error) error {
		if kerr != nil {
			return where(kerr)
		}
		id := fmt.Sprintf("%d/%d/%d/%s/%s", ledger, txo, opo, change, key)
		if e.seen[id] {
			return nil
		}
		e.seen[id] = true
		x := e.base("entry_change", "history_effects", ledger, txo, opo)
		x["phase"], x["change"], x["entry_type"], x["reason"] = "op", change, typName, name
		x["entry_key"], x["key"] = key, key
		e.emit(x)
		return nil
	}
	lifecycle := func(created, removed uint32) string {
		switch typ {
		case created:
			return "created"
		case removed:
			return "removed"
		}
		return "updated"
	}
	switch typ {
	case 0, 1, 4, 5, 6, 7, 10, 11, 12, 43:
		k, kerr := accountKey(acct)
		return ent("account", lifecycle(0, 1), k, kerr)
	case 20, 21, 22, 23, 24, 25, 26:
		var asset string
		if d.str("asset_type") == "liquidity_pool_shares" {
			asset = "pool:" + d.str("liquidity_pool_id")
		} else {
			asset = d.str("asset_code") + ":" + d.str("asset_issuer")
		}
		owner := acct
		if t := d.str("trustor"); t != "" { // allow_trust / set_trust_line_flags: the effect is the issuer's
			owner = t
		}
		k, kerr := trustlineKey(owner, asset)
		return ent("trustline", lifecycle(20, 21), k, kerr)
	case 40, 41, 42:
		k, kerr := dataKey(acct, d.str("name"))
		return ent("data", lifecycle(40, 41), k, kerr)
	case 50, 52, 80:
		k, kerr := cbKey(d.str("balance_id"))
		change := lifecycle(50, 52)
		if typ == 80 {
			change = "removed"
		}
		return ent("claimable_balance", change, k, kerr)
	case 90, 91, 92, 93, 94, 95:
		id := d.obj("liquidity_pool").str("id")
		if id == "" {
			id = d.str("liquidity_pool_id")
		}
		k, kerr := lpKey(id)
		return ent("liquidity_pool", lifecycle(93, 94), k, kerr)
	}
	return nil
}

func (e *exporter) operation(r rawLine, ledger, txo, opo uint32) error {
	list, _ := r.obj("details")["asset_balance_changes"].([]any)
	for i, it := range list {
		m := rawLine(it.(map[string]any))
		amt, err := Stroops(m.str("amount"))
		if err != nil {
			return fmt.Errorf("ledger %d tx %d op %d asset_balance_changes: %v", ledger, txo, opo, err)
		}
		asset := assetOf(m, "")
		x := e.base("token_event", "history_operations", ledger, txo, opo)
		x["contract"], x["event"], x["asset"], x["amount"], x["event_index"] = e.sacOf(asset), m.str("type"), asset, amt, i
		for k, f := range map[string]string{"from": "from", "to": "to", "to_muxed_id": "destination_muxed_id"} {
			if v := m.strp(f); v != nil {
				x[k] = *v
			}
		}
		e.emit(x)
	}
	return nil
}

func openRaw(path string) (io.ReadCloser, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	if !strings.HasSuffix(path, ".zst") {
		return f, nil
	}
	zr, err := zstd.NewReader(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	return struct {
		io.Reader
		io.Closer
	}{zr, closerFunc(func() error { zr.Close(); return f.Close() })}, nil
}

type closerFunc func() error

func (c closerFunc) Close() error { return c() }

func eachRaw(path string, fn func(rawLine) error) error {
	rc, err := openRaw(path)
	if err != nil {
		return err
	}
	defer rc.Close()
	sc := bufio.NewScanner(rc)
	sc.Buffer(make([]byte, 1<<20), 1<<30)
	for sc.Scan() {
		if len(bytes.TrimSpace(sc.Bytes())) == 0 {
			continue
		}
		d := json.NewDecoder(bytes.NewReader(sc.Bytes()))
		d.UseNumber()
		var r rawLine
		if err := d.Decode(&r); err != nil {
			return fmt.Errorf("%s: %v", path, err)
		}
		if err := fn(r); err != nil {
			return err
		}
	}
	return sc.Err()
}

// ExportRows maps raw dumps (one per shard database) to common rows.

func muxedID(m string) (string, error) {
	var a xdr.MuxedAccount
	if err := a.SetAddress(m); err != nil {
		return "", err
	}
	id, err := a.GetId()
	if err != nil {
		return "", err
	}
	return fmt.Sprint(id), nil
}

func cbStrkey(hexID string) (string, error) {
	var id xdr.ClaimableBalanceId
	if err := xdr.SafeUnmarshalHex(hexID, &id); err != nil {
		return "", fmt.Errorf("claimable balance id %q: %v", hexID, err)
	}
	if id.V0 == nil {
		return "", fmt.Errorf("claimable balance id %q: unknown type", hexID)
	}
	return strkey.Encode(strkey.VersionByteClaimableBalance, append([]byte{0}, id.V0[:]...))
}

func poolStrkey(hexID *string) *string {
	if hexID == nil {
		return nil
	}
	b, err := hex.DecodeString(*hexID)
	if err != nil || len(b) != 32 {
		return nil
	}
	s, err := strkey.Encode(strkey.VersionByteLiquidityPool, b)
	if err != nil {
		return nil
	}
	return &s
}

func keyB64(k xdr.LedgerKey) (string, error) { return xdr.MarshalBase64(k) }

func accountKey(g string) (string, error) {
	var id xdr.AccountId
	if err := id.SetAddress(g); err != nil {
		return "", err
	}
	var k xdr.LedgerKey
	if err := k.SetAccount(id); err != nil {
		return "", err
	}
	return keyB64(k)
}

func trustlineKey(g, asset string) (string, error) {
	var id xdr.AccountId
	if err := id.SetAddress(g); err != nil {
		return "", err
	}
	var tla xdr.TrustLineAsset
	if p, ok := strings.CutPrefix(asset, "pool:"); ok {
		b, err := hex.DecodeString(p)
		if err != nil || len(b) != 32 {
			return "", fmt.Errorf("bad pool id %q", p)
		}
		var pid xdr.PoolId
		copy(pid[:], b)
		tla = xdr.TrustLineAsset{Type: xdr.AssetTypeAssetTypePoolShare, LiquidityPoolId: &pid}
	} else {
		code, issuer, _ := strings.Cut(asset, ":")
		a, err := xdr.NewCreditAsset(code, issuer)
		if err != nil {
			return "", fmt.Errorf("asset %q: %v", asset, err)
		}
		tla = a.ToTrustLineAsset()
	}
	var k xdr.LedgerKey
	if err := k.SetTrustline(id, tla); err != nil {
		return "", err
	}
	return keyB64(k)
}

func dataKey(g, name string) (string, error) {
	var id xdr.AccountId
	if err := id.SetAddress(g); err != nil {
		return "", err
	}
	var k xdr.LedgerKey
	if err := k.SetData(id, name); err != nil {
		return "", err
	}
	return keyB64(k)
}

func cbKey(hexID string) (string, error) {
	var id xdr.ClaimableBalanceId
	if err := xdr.SafeUnmarshalHex(hexID, &id); err != nil {
		return "", fmt.Errorf("claimable balance id %q: %v", hexID, err)
	}
	var k xdr.LedgerKey
	if err := k.SetClaimableBalance(id); err != nil {
		return "", err
	}
	return keyB64(k)
}

func lpKey(hexID string) (string, error) {
	b, err := hex.DecodeString(hexID)
	if err != nil || len(b) != 32 {
		return "", fmt.Errorf("liquidity pool id %q", hexID)
	}
	var pid xdr.PoolId
	copy(pid[:], b)
	var k xdr.LedgerKey
	if err := k.SetLiquidityPool(pid); err != nil {
		return "", err
	}
	return keyB64(k)
}

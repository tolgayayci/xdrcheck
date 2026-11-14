package walletbackend

// observe: read wallet-backend's rows for a ledger range back with SQL and map them onto the neutral
// observation vocabulary (corpus/schema/observation.schema.json).
//
//   - receipts: the number of transaction and operation rows per ledger.
//   - transactions: hash, result code (wallet-backend's Go enum name mapped to the XDR-JSON name through a
//     fixed table; an unknown label passes through unchanged), fee charged where the column exists; the index
//     is the order of to_id within the ledger.
//   - participants: one fact per row of transactions_accounts and operations_accounts (muxed: base_only).
//   - state_changes: one fact per row, by category and reason (table below); unmapped rows are left out and
//     counted in the adapter's log, so they can neither satisfy nor violate an expectation by accident.
//   - addresses: every address column of those rows, exactly as stored.
//
// Addresses are read as the raw bytes of their column and passed through as `version_byte_payload_hex`
// (version byte followed by the payload). `account.address` is filled only when the stored value is a 33-byte
// account (G…) or contract (C…) key, which wallet-backend holds in that form; signer values are never
// interpreted: the harness decodes them in full, so a truncated value (wallet-backend#716) is caught rather
// than rendered as a plausible strkey the way wallet-backend's own Scan renders it.
//
//	SIGNER/ADD, /REMOVE, /UPDATE         signer_added, signer_removed, signer_changed  weight_before
//	  … of the account's own master key  thresholds_changed                            master_weight
//	SIGNATURE_THRESHOLD/UPDATE           thresholds_changed                            low, medium or high
//	TRUSTLINE/ADD, /REMOVE               trustline_created, trustline_removed          limit_as_stored
//	BALANCE_AUTHORIZATION/SET, /CLEAR    trustline_flags_changed                       the flag booleans, flags_as_stored
//	BALANCE/DEBIT, /CREDIT, /MINT, /BURN balance_changed                               delta, reason
//	ACCOUNT/CREATE, /MERGE               account_created, account_removed
//	  ACCOUNT/CREATE of a contract       contract_deployed                             contract
//
// The rows that need wallet-backend's own model to read (source: internal/indexer/processors/effects.go,
// effects_horizon.go and contract_deploy.go, and internal/indexer/types/types.go, at every commit the replay check
// pins):
//
//   - Like Horizon, wallet-backend treats an account's master key as a signer whose weight is the master weight
//     (go-stellar-sdk's AccountEntry.SignerSummary): a SetOptions that changes the master weight writes a SIGNER row
//     whose signer is the account itself. In the ledger that is the account's thresholds entry (byte 0), so the row
//     is the neutral `thresholds_changed` with `master_weight`; SIGNER/REMOVE of the master key is master weight 0.
//     CreateAccount writes SIGNER/ADD of the new account's master key (weight 1) beside ACCOUNT/CREATE: that row
//     records the created account's default, which the neutral vocabulary carries in `account_created`, so it is
//     left out (it is recognised by its operation's type, CREATE_ACCOUNT, from the operations table).
//   - The `flags` column is wallet-backend's own bit mask (types.FlagBit*: authorized = bit 0, clawback_enabled =
//     bit 5, authorized_to_maintain_liabilities = bit 6), not the XDR TrustLineFlags mask, and a row lists only the
//     flags its change set (SET) or cleared (CLEAR), not the trustline's flags afterwards. So the adapter never fills
//     `flags`: it passes the stored integer as `flags_as_stored` and spells out the listed flags as the booleans
//     they are after the change (true on SET, false on CLEAR). Flags a row does not list are not stated.
//   - Contract deployments are written as ACCOUNT/CREATE whose account is the new contract (C…).
//
// A ledger is reported as seen when the ingest cursor is at or past it, or when rows exist for it; a ledger
// missing from the observation was not seen.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/stellar/go-stellar-sdk/strkey"

	"github.com/tolgayayci/xdrcheck/go/adapterkit"
)

// schemaCols holds the columns (and their types) of the tables observe reads, per session's commit.
type schemaCols struct {
	tables map[string]map[string]string // table -> column -> data_type
}

func (c *schemaCols) has(table, col string) bool   { _, ok := c.tables[table][col]; return ok }
func (c *schemaCols) typ(table, col string) string { return c.tables[table][col] }

func (s *server) columns(ctx context.Context, ss *session) (*schemaCols, error) {
	if ss.cols != nil {
		return ss.cols, nil
	}
	var rows []struct {
		Table  string `json:"table_name"`
		Column string `json:"column_name"`
		Type   string `json:"data_type"`
	}
	q := "SELECT table_name::text, column_name::text, data_type::text FROM information_schema.columns WHERE table_schema = 'public' AND table_name IN ('transactions', 'operations', 'state_changes', 'transactions_accounts', 'operations_accounts')"
	if err := s.db.QueryJSON(ctx, ss.db, q, &rows); err != nil {
		return nil, err
	}
	c := &schemaCols{tables: map[string]map[string]string{}}
	for _, r := range rows {
		if c.tables[r.Table] == nil {
			c.tables[r.Table] = map[string]string{}
		}
		c.tables[r.Table][r.Column] = r.Type
	}
	for _, t := range []string{"transactions", "operations", "state_changes"} {
		if !c.has(t, "ledger_number") {
			return nil, fmt.Errorf("table %s has no ledger_number column at this commit", t)
		}
	}
	ss.cols = c
	return c, nil
}

// textExpr renders a column so that its JSON value is a string: bytea as hex, everything else as text.
func textExpr(c *schemaCols, table, alias, col string) string {
	if !c.has(table, col) {
		return "NULL::text"
	}
	ref := alias + "." + quoteIdent(col)
	if c.typ(table, col) == "bytea" {
		return "encode(" + ref + ", 'hex')"
	}
	return ref + "::text"
}

// encodingOf is the as_stored encoding of an address column.
func encodingOf(c *schemaCols, table, col string) string {
	if c.typ(table, col) == "bytea" {
		return "version_byte_payload_hex"
	}
	return "strkey_text"
}

// addressColumns are the address-bearing columns of state_changes present at this commit.
func addressColumns(c *schemaCols) []string {
	var out []string
	for col, t := range c.tables["state_changes"] {
		if (strings.HasSuffix(col, "account_id") || col == "token_id" || strings.HasSuffix(col, "contract_id")) && (t == "bytea" || t == "text" || t == "character varying") {
			out = append(out, col)
		}
	}
	sort.Strings(out)
	return out
}

type txRow struct {
	Hash       string  `json:"hash"`
	ToID       string  `json:"to_id"`
	Ledger     int64   `json:"ledger_number"`
	ResultCode *string `json:"result_code"`
	FeeCharged *string `json:"fee_charged"`
}

type countRow struct {
	Ledger int64 `json:"ledger_number"`
	N      int64 `json:"n"`
}

type partRow struct {
	Ledger  int64   `json:"ledger_number"`
	Hash    string  `json:"hash"`
	OpID    *string `json:"op_id"`
	Account *string `json:"account"`
}

type scRow struct {
	Ledger   int64              `json:"ledger_number"`
	Hash     string             `json:"hash"`
	OpID     *string            `json:"operation_id"`
	Category *string            `json:"category"`
	Reason   *string            `json:"reason"`
	Account  *string            `json:"account_id"`
	Signer   *string            `json:"signer_account_id"`
	WOld     *string            `json:"signer_weight_old"`
	WNew     *string            `json:"signer_weight_new"`
	Token    *string            `json:"token_id"`
	Flags    *string            `json:"flags"`
	Limit    *string            `json:"trustline_limit_new"`
	Amount   *string            `json:"amount"`
	Level    *string            `json:"threshold"`
	TNew     *string            `json:"threshold_new"`
	OpType   *string            `json:"operation_type"`
	Addrs    map[string]*string `json:"addrs"`
}

func (s *server) observe(ctx context.Context, p adapterkit.ObserveParams) (any, error) {
	ss, err := s.session(p.Session)
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, fail("environment", "%v", errNoDatabase)
	}
	if p.Range.End < p.Range.Start {
		return nil, fail("invalid_params", "range %d..%d", p.Range.Start, p.Range.End)
	}
	c, err := s.columns(ctx, ss)
	if err != nil {
		return nil, fail("internal", "reading the schema: %v", err)
	}
	obs := adapterkit.Observation{Schema: adapterkit.ObservationSchema, Range: p.Range, Ledgers: []adapterkit.Ledger{}}
	for _, k := range adapterkit.AllKinds {
		st := obs.Kinds.Kind(k)
		switch {
		case k == adapterkit.KindMovements:
			*st = adapterkit.KindStatus{Status: "not_applicable", Reason: "the adapter maps state changes only; balance movements are not read from wallet-backend's tables"}
		case !slices.Contains(p.Kinds, k):
			*st = adapterkit.KindStatus{Status: "not_applicable", Reason: "not requested"}
		case k == adapterkit.KindReceipts:
			*st = adapterkit.KindStatus{Status: "provided", Subkinds: []string{"transactions", "operations"}}
		default:
			*st = adapterkit.KindStatus{Status: "provided"}
		}
	}
	lo, hi := p.Range.Start, p.Range.End
	where := fmt.Sprintf("ledger_number BETWEEN %d AND %d", lo, hi)

	var txs []txRow
	q := fmt.Sprintf("SELECT %s AS hash, t.to_id::text AS to_id, t.ledger_number, %s AS result_code, %s AS fee_charged FROM transactions t WHERE t.%s ORDER BY t.to_id",
		textExpr(c, "transactions", "t", "hash"), textExpr(c, "transactions", "t", "result_code"), textExpr(c, "transactions", "t", "fee_charged"), where)
	if err := s.db.QueryJSON(ctx, ss.db, q, &txs); err != nil {
		return nil, fail("internal", "transactions: %v", err)
	}
	var ops []countRow
	if err := s.db.QueryJSON(ctx, ss.db, "SELECT ledger_number, count(*) AS n FROM operations WHERE "+where+" GROUP BY ledger_number", &ops); err != nil {
		return nil, fail("internal", "operations: %v", err)
	}
	var parts []partRow
	if obs.Kinds.Participants.Status == "provided" || obs.Kinds.Addresses.Status == "provided" {
		if parts, err = s.participantRows(ctx, ss, c, where); err != nil {
			return nil, fail("internal", "participants: %v", err)
		}
	}
	var scs []scRow
	if obs.Kinds.StateChanges.Status == "provided" || obs.Kinds.Addresses.Status == "provided" {
		if scs, err = s.stateChangeRows(ctx, ss, c, where); err != nil {
			return nil, fail("internal", "state changes: %v", err)
		}
	}
	cursor, _ := s.cursor(ctx, ss.db)

	keep := func(h string) bool { return len(p.TxHashes) == 0 || slices.Contains(p.TxHashes, h) }
	seen := map[int64]bool{}
	byLedger := map[int64]*adapterkit.Ledger{}
	ledger := func(seq int64) *adapterkit.Ledger {
		if l, ok := byLedger[seq]; ok {
			return l
		}
		zero := int64(0)
		z2 := int64(0)
		l := &adapterkit.Ledger{LedgerSeq: seq}
		if obs.Kinds.Receipts.Status == "provided" {
			l.Receipt = &adapterkit.Receipt{Transactions: &zero, Operations: &z2}
		}
		byLedger[seq] = l
		return l
	}
	for seq := lo; seq <= hi; seq++ {
		if cursor != nil && seq <= *cursor {
			seen[seq] = true
		}
	}
	for _, t := range txs {
		seen[t.Ledger] = true
	}
	for _, o := range ops {
		seen[o.Ledger] = true
	}
	for seq := range seen {
		ledger(seq)
	}

	index := map[int64]int{}
	for _, t := range txs {
		l := ledger(t.Ledger)
		if l.Receipt != nil {
			*l.Receipt.Transactions++
		}
		i := index[t.Ledger]
		index[t.Ledger]++
		if obs.Kinds.Transactions.Status != "provided" || !keep(t.Hash) {
			continue
		}
		l.Transactions = append(l.Transactions, mapTransaction(t, i))
	}
	for _, o := range ops {
		if l := ledger(o.Ledger); l.Receipt != nil {
			n := o.N
			l.Receipt.Operations = &n
		}
	}
	for _, r := range parts {
		if !keep(r.Hash) || r.Account == nil {
			continue
		}
		l := ledger(r.Ledger)
		table := "transactions_accounts"
		loc := adapterkit.Locator{TxHash: r.Hash}
		if r.OpID != nil {
			table = "operations_accounts"
			loc.OpIndex = opIndex(*r.OpID)
		}
		st := stored(encodingOf(c, table, "account_id"), *r.Account)
		if obs.Kinds.Participants.Status == "provided" {
			l.Participants = append(l.Participants, adapterkit.ObsParticipant{Locator: loc, Account: *account(st)})
		}
		if obs.Kinds.Addresses.Status == "provided" {
			l.Addresses = append(l.Addresses, adapterkit.ObsAddress{Locator: loc, Field: table + ".account_id", AsStored: st})
		}
	}
	unmapped := map[string]int{}
	cols := addressColumns(c)
	for _, r := range scs {
		if !keep(r.Hash) {
			continue
		}
		l := ledger(r.Ledger)
		loc := adapterkit.Locator{TxHash: r.Hash}
		if r.OpID != nil {
			loc.OpIndex = opIndex(*r.OpID)
		}
		if obs.Kinds.StateChanges.Status == "provided" {
			if fact, ok := mapStateChange(r, func(col string) string { return encodingOf(c, "state_changes", col) }); ok {
				fact.Locator = loc
				l.StateChanges = append(l.StateChanges, fact)
			} else {
				unmapped[deref(r.Category)+"/"+deref(r.Reason)]++
			}
		}
		if obs.Kinds.Addresses.Status == "provided" {
			for _, col := range cols {
				if v := r.Addrs[col]; v != nil {
					l.Addresses = append(l.Addresses, adapterkit.ObsAddress{Locator: loc, Field: "state_changes." + col, AsStored: stored(encodingOf(c, "state_changes", col), *v)})
				}
			}
		}
	}
	if len(unmapped) > 0 {
		var parts []string
		for k, n := range unmapped {
			parts = append(parts, fmt.Sprintf("%s ×%d", k, n))
		}
		sort.Strings(parts)
		s.logf("observe %s: state-change rows with no neutral kind left out: %s", p.Session, strings.Join(parts, ", "))
	}

	seqs := make([]int64, 0, len(byLedger))
	for seq := range byLedger {
		seqs = append(seqs, seq)
	}
	slices.Sort(seqs)
	for _, seq := range seqs {
		l := byLedger[seq]
		sortFacts(l)
		obs.Ledgers = append(obs.Ledgers, *l)
	}
	return obs, nil
}

func (s *server) participantRows(ctx context.Context, ss *session, c *schemaCols, where string) ([]partRow, error) {
	var out []partRow
	hash := textExpr(c, "transactions", "t", "hash")
	if c.tables["transactions_accounts"] != nil {
		join, err := txJoin(c, "transactions_accounts", "a")
		if err != nil {
			return nil, err
		}
		var rows []partRow
		q := fmt.Sprintf("SELECT t.ledger_number, %s AS hash, NULL::text AS op_id, %s AS account FROM transactions_accounts a JOIN transactions t ON %s WHERE t.%s ORDER BY 2, 4",
			hash, textExpr(c, "transactions_accounts", "a", "account_id"), join, where)
		if err := s.db.QueryJSON(ctx, ss.db, q, &rows); err != nil {
			return nil, err
		}
		out = append(out, rows...)
	}
	if c.tables["operations_accounts"] != nil {
		opCol := ""
		for _, cand := range []string{"operation_id", "op_id"} {
			if c.has("operations_accounts", cand) {
				opCol = cand
				break
			}
		}
		if opCol != "" {
			var rows []partRow
			q := fmt.Sprintf("SELECT t.ledger_number, %s AS hash, a.%s::text AS op_id, %s AS account FROM operations_accounts a JOIN transactions t ON t.to_id = (a.%s >> 12) << 12 WHERE t.%s ORDER BY 2, 3, 4",
				hash, quoteIdent(opCol), textExpr(c, "operations_accounts", "a", "account_id"), quoteIdent(opCol), where)
			if err := s.db.QueryJSON(ctx, ss.db, q, &rows); err != nil {
				return nil, err
			}
			out = append(out, rows...)
		}
	}
	return out, nil
}

// txJoin is the join condition of a per-transaction table onto transactions at this commit.
func txJoin(c *schemaCols, table, alias string) (string, error) {
	switch {
	case c.has(table, "tx_to_id"):
		return alias + ".tx_to_id = t.to_id", nil
	case c.has(table, "to_id"):
		return alias + ".to_id = t.to_id", nil
	case c.has(table, "tx_hash"):
		return alias + ".tx_hash = t.hash", nil
	}
	return "", fmt.Errorf("%s has no column linking it to transactions", table)
}

func (s *server) stateChangeRows(ctx context.Context, ss *session, c *schemaCols, where string) ([]scRow, error) {
	join, err := txJoin(c, "state_changes", "sc")
	if err != nil {
		return nil, err
	}
	sel := func(col string) string { return textExpr(c, "state_changes", "sc", col) + " AS " + quoteIdent(col) }
	var addrs []string
	for _, col := range addressColumns(c) {
		addrs = append(addrs, quoteLiteral(col)+", "+textExpr(c, "state_changes", "sc", col))
	}
	addrObj := "NULL::json"
	if len(addrs) > 0 {
		addrObj = "json_build_object(" + strings.Join(addrs, ", ") + ")"
	}
	order := "sc.ledger_number"
	if c.has("state_changes", "state_change_id") {
		order = "t.to_id, " + textExpr(c, "state_changes", "sc", "operation_id") + ", sc.state_change_id"
	}
	// The type of the row's operation, read from the operations table (a scalar subquery: one value per row).
	opType := "NULL::text"
	if c.has("state_changes", "operation_id") && c.has("operations", "id") && c.has("operations", "operation_type") {
		opType = "(SELECT o.operation_type::text FROM operations o WHERE o.id = sc.operation_id LIMIT 1)"
	}
	q := fmt.Sprintf("SELECT sc.ledger_number, %s AS hash, %s, %s AS category, %s AS reason, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s AS operation_type, %s AS addrs FROM state_changes sc JOIN transactions t ON %s WHERE sc.%s ORDER BY %s",
		textExpr(c, "transactions", "t", "hash"), sel("operation_id"),
		textExpr(c, "state_changes", "sc", "state_change_category"), textExpr(c, "state_changes", "sc", "state_change_reason"),
		sel("account_id"), sel("signer_account_id"), sel("signer_weight_old"), sel("signer_weight_new"),
		sel("token_id"), sel("flags"), sel("trustline_limit_new"), sel("amount"), sel("threshold"), sel("threshold_new"), opType, addrObj, join, where, order)
	var rows []scRow
	if err := s.db.QueryJSON(ctx, ss.db, q, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// opIndex is the operation's index in its transaction from wallet-backend's operation ID (a TOID: the low 12
// bits are the operation's 1-based order). 0 is a transaction-level row and has no operation.
func opIndex(id string) *int {
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil || n <= 0 || n&0xfff == 0 {
		return nil
	}
	i := int(n&0xfff) - 1
	return &i
}

func stored(encoding, value string) adapterkit.Stored {
	return adapterkit.Stored{Encoding: encoding, Value: value}
}

// account maps a stored address: as_stored always; address only for a 33-byte account or contract key (or a
// G…/C… text the indexer holds as is).
func account(st adapterkit.Stored) *adapterkit.ObsAccount {
	a := &adapterkit.ObsAccount{AsStored: &st}
	a.Address = addressOf(st)
	return a
}

func addressOf(st adapterkit.Stored) string {
	switch st.Encoding {
	case "version_byte_payload_hex":
		b, err := hex.DecodeString(st.Value)
		if err != nil || len(b) != 33 {
			return ""
		}
		var vb strkey.VersionByte
		switch b[0] {
		case byte(strkey.VersionByteAccountID):
			vb = strkey.VersionByteAccountID
		case byte(strkey.VersionByteContract):
			vb = strkey.VersionByteContract
		default:
			return ""
		}
		s, err := strkey.Encode(vb, b[1:])
		if err != nil {
			return ""
		}
		return s
	case "strkey_text":
		if strings.HasPrefix(st.Value, "G") || strings.HasPrefix(st.Value, "C") {
			return st.Value
		}
	}
	return ""
}

func mapTransaction(t txRow, index int) adapterkit.ObsTransaction {
	i := index
	o := adapterkit.ObsTransaction{Hash: t.Hash, Index: &i}
	if t.ResultCode != nil {
		o.NativeLabel = *t.ResultCode
		o.ResultCode = resultCode(*t.ResultCode)
	}
	if t.FeeCharged != nil && integerRe.MatchString(*t.FeeCharged) {
		o.FeeCharged = *t.FeeCharged
	}
	return o
}

var integerRe = regexp.MustCompile(`^-?[0-9]+$`)

// mapStateChange maps one state_changes row to one fact, or reports that its category has no neutral kind.
func mapStateChange(r scRow, encoding func(col string) string) (adapterkit.ObsStateChange, bool) {
	label := deref(r.Category) + "/" + deref(r.Reason)
	f := adapterkit.ObsStateChange{NativeLabel: label}
	if r.Account != nil {
		f.Account = account(stored(encoding("account_id"), *r.Account))
	}
	asset := func() {
		if r.Token != nil {
			st := stored(encoding("token_id"), *r.Token)
			if a := addressOf(st); a != "" {
				f.Asset = a
			} else {
				f.Asset = st.Value
			}
		}
	}
	detail := map[string]any{}
	switch label {
	case "SIGNER/ADD", "SIGNER/REMOVE", "SIGNER/UPDATE":
		if masterKey(r, encoding) {
			if label == "SIGNER/ADD" && deref(r.OpType) == "CREATE_ACCOUNT" {
				return f, false // the created account's default master key: part of account_created
			}
			f.Kind = "thresholds_changed"
			if label == "SIGNER/REMOVE" {
				detail["master_weight"] = json.Number("0")
			} else if w, ok := weight(r.WNew); ok {
				detail["master_weight"] = json.Number(strconv.Itoa(w))
			}
			break
		}
		f.Kind = map[string]string{"SIGNER/ADD": "signer_added", "SIGNER/REMOVE": "signer_removed", "SIGNER/UPDATE": "signer_changed"}[label]
		if r.Signer != nil {
			st := stored(encoding("signer_account_id"), *r.Signer)
			f.Signer = &adapterkit.ObsSigner{AsStored: &st}
			if label != "SIGNER/REMOVE" {
				if w, ok := weight(r.WNew); ok {
					f.Signer.Weight = &w
				}
			}
		}
		if w, ok := weight(r.WOld); ok {
			detail["weight_before"] = json.Number(strconv.Itoa(w))
		}
	case "TRUSTLINE/ADD", "TRUSTLINE/REMOVE":
		f.Kind = map[string]string{"TRUSTLINE/ADD": "trustline_created", "TRUSTLINE/REMOVE": "trustline_removed"}[label]
		asset()
		if label == "TRUSTLINE/ADD" && r.Limit != nil {
			detail["limit_as_stored"] = *r.Limit // a decimal with seven places, not stroops: never converted
		}
	case "BALANCE_AUTHORIZATION/SET", "BALANCE_AUTHORIZATION/CLEAR":
		f.Kind = "trustline_flags_changed"
		asset()
		if r.Flags != nil {
			detail["flags_as_stored"] = *r.Flags
			if n, err := strconv.ParseUint(*r.Flags, 10, 16); err == nil {
				for _, b := range trustlineFlagBits {
					if n&b.bit != 0 {
						detail[b.key] = label == "BALANCE_AUTHORIZATION/SET"
					}
				}
			}
		}
	case "SIGNATURE_THRESHOLD/UPDATE":
		f.Kind = "thresholds_changed"
		if key, ok := thresholdLevels[deref(r.Level)]; ok {
			if w, ok := weight(r.TNew); ok {
				detail[key] = json.Number(strconv.Itoa(w))
			}
		}
	case "BALANCE/DEBIT", "BALANCE/CREDIT", "BALANCE/MINT", "BALANCE/BURN":
		f.Kind = "balance_changed"
		asset()
		if r.Amount != nil {
			sign := ""
			if label == "BALANCE/DEBIT" || label == "BALANCE/BURN" {
				sign = "-"
			}
			if integerRe.MatchString(*r.Amount) && !strings.HasPrefix(*r.Amount, "-") {
				detail["delta"] = sign + *r.Amount
			} else {
				detail["delta_as_stored"] = *r.Amount
			}
		}
		if r.OpID == nil || *r.OpID == "0" {
			detail["reason"] = "fee"
		} else {
			detail["reason"] = "other"
		}
	case "ACCOUNT/CREATE":
		f.Kind = "account_created"
		if f.Account != nil && strings.HasPrefix(f.Account.Address, "C") {
			f.Kind = "contract_deployed"
			detail["contract"] = f.Account.Address
		}
	case "ACCOUNT/MERGE":
		f.Kind = "account_removed"
	default:
		return f, false
	}
	if len(detail) > 0 {
		f.Detail = detail
	}
	return f, true
}

// trustlineFlagBits are wallet-backend's bits for the trustline flags in its `flags` column (its types.FlagBit*
// constants, the same at every pinned commit) and the neutral detail key each one is.
var trustlineFlagBits = []struct {
	bit uint64
	key string
}{
	{1 << 0, "authorized"},
	{1 << 5, "clawback_enabled"},
	{1 << 6, "authorized_to_maintain_liabilities"},
}

// thresholdLevels maps wallet-backend's `threshold` column (its ThresholdLevel values) to the neutral detail key.
var thresholdLevels = map[string]string{"LOW": "low", "MEDIUM": "medium", "HIGH": "high"}

// masterKey reports whether a SIGNER row is about the account's own master key: the signer column holds the
// account itself.
func masterKey(r scRow, encoding func(col string) string) bool {
	return r.Signer != nil && r.Account != nil && encoding("signer_account_id") == encoding("account_id") &&
		strings.EqualFold(*r.Signer, *r.Account)
}

func weight(s *string) (int, bool) {
	if s == nil {
		return 0, false
	}
	n, err := strconv.Atoi(*s)
	if err != nil || n < 0 || n > 255 {
		return 0, false
	}
	return n, true
}

// sortFacts orders facts as the protocol asks: by transaction, operation index, then the fact's JSON text.
func sortFacts(l *adapterkit.Ledger) {
	idx := map[string]int{}
	for _, t := range l.Transactions {
		if t.Index != nil {
			idx[t.Hash] = *t.Index
		}
	}
	key := func(loc adapterkit.Locator, v any) string {
		op := -1
		if loc.OpIndex != nil {
			op = *loc.OpIndex
		}
		b, _ := json.Marshal(v)
		return fmt.Sprintf("%s|%010d|%s", loc.TxHash, op+1, b)
	}
	sort.SliceStable(l.Transactions, func(i, j int) bool { return deint(l.Transactions[i].Index) < deint(l.Transactions[j].Index) })
	sortBy(l.Participants, func(x adapterkit.ObsParticipant) string { return key(x.Locator, x) })
	sortBy(l.StateChanges, func(x adapterkit.ObsStateChange) string { return key(x.Locator, x) })
	sortBy(l.Addresses, func(x adapterkit.ObsAddress) string { return key(x.Locator, x) })
}

func deint(p *int) int {
	if p == nil {
		return -1
	}
	return *p
}

func sortBy[T any](xs []T, key func(T) string) {
	keys := make([]string, len(xs))
	for i := range xs {
		keys[i] = key(xs[i])
	}
	idx := make([]int, len(xs))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool { return keys[idx[a]] < keys[idx[b]] })
	sorted := make([]T, len(xs))
	for i, j := range idx {
		sorted[i] = xs[j]
	}
	copy(xs, sorted)
}

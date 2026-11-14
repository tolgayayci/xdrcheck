package stellaretl

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode"

	"github.com/tolgayayci/xdrcheck/go/adapterkit"
)

// The exports the adapter runs, in order: every export stellar-etl has. Each writes JSON Lines to its own folder
// under the session's out/. The first five and export_contract_events and export_trades are mapped onto facts
// (below); the others (ledger entry changes, assets, ledger transactions) are judged only on how the command
// ended: exit status, signal, runtime panic, timeout and peak memory. Every export runs, whatever an earlier
// one did, so each one's ending is known on every ledger.
var exportCommands = []string{"export_ledgers", "export_transactions", "export_operations", "export_effects", "export_token_transfer",
	"export_contract_events", "export_trades", "export_ledger_entry_changes", "export_assets", "export_ledger_transaction"}

// Rows as stellar-etl writes them (internal/transform/schema.go at v2.8.34). Only the columns the mapping reads
// are declared; amounts and fees are kept as their literal JSON tokens.

type ledgerRow struct {
	Sequence   int64  `json:"sequence"`
	LedgerHash string `json:"ledger_hash"`
}

type txRow struct {
	Hash            string      `json:"transaction_hash"`
	Ledger          int64       `json:"ledger_sequence"`
	ID              int64       `json:"id"`
	Successful      bool        `json:"successful"`
	ResultCode      string      `json:"transaction_result_code"`
	FeeCharged      json.Number `json:"fee_charged"`
	InnerHash       string      `json:"inner_transaction_hash"`
	Account         string      `json:"account"`
	AccountMuxed    string      `json:"account_muxed"`
	FeeAccount      string      `json:"fee_account"`
	FeeAccountMuxed string      `json:"fee_account_muxed"`
}

type opRow struct {
	Ledger             int64  `json:"ledger_sequence"`
	ID                 int64  `json:"id"`
	TxID               int64  `json:"transaction_id"`
	SourceAccount      string `json:"source_account"`
	SourceAccountMuxed string `json:"source_account_muxed"`
	TypeString         string `json:"type_string"`
	ResultCode         string `json:"operation_result_code"`
	TraceCode          string `json:"operation_trace_code"`
}

type effectRow struct {
	Ledger       int64                      `json:"ledger_sequence"`
	OperationID  int64                      `json:"operation_id"`
	Address      string                     `json:"address"`
	AddressMuxed *string                    `json:"address_muxed"`
	TypeString   string                     `json:"type_string"`
	Index        int64                      `json:"index"`
	Details      map[string]json.RawMessage `json:"details"`
}

type transferRow struct {
	Ledger      int64           `json:"ledger_sequence"`
	TxHash      string          `json:"transaction_hash"`
	TxID        int64           `json:"transaction_id"`
	OperationID *int64          `json:"operation_id"`
	EventTopic  string          `json:"event_topic"`
	From        *string         `json:"from"`
	To          *string         `json:"to"`
	AssetType   string          `json:"asset_type"`
	AssetCode   *string         `json:"asset_code"`
	AssetIssuer *string         `json:"asset_issuer"`
	Amount      json.RawMessage `json:"amount"`
	AmountRaw   string          `json:"amount_raw"`
	ContractID  string          `json:"contract_id"`
	ToMuxed     *string         `json:"to_muxed"`
	ToMuxedID   *string         `json:"to_muxed_id"`
}

type contractEventRow struct {
	Ledger                   int64             `json:"ledger_sequence"`
	TxHash                   string            `json:"transaction_hash"`
	TypeString               string            `json:"type_string"`
	InSuccessfulContractCall bool              `json:"in_successful_contract_call"`
	OperationID              *int64            `json:"operation_id"`
	TopicsDecoded            []json.RawMessage `json:"topics_decoded"`
}

type tradeRow struct {
	HistoryOperationID int64  `json:"history_operation_id"`
	Seller             string `json:"selling_account_address"`
	Buyer              string `json:"buying_account_address"`
}

// anyRow is the ledger of a row of any export: its ledger_sequence (or sequence) column, or the ledger of its
// history_operation_id TOID.
type anyRow struct {
	LedgerSequence *int64 `json:"ledger_sequence"`
	Sequence       *int64 `json:"sequence"`
	OperationID    *int64 `json:"history_operation_id"`
}

func (r anyRow) ledger() (int64, bool) {
	switch {
	case r.LedgerSequence != nil:
		return *r.LedgerSequence, true
	case r.Sequence != nil:
		return *r.Sequence, true
	case r.OperationID != nil:
		return *r.OperationID >> 32, true
	}
	return 0, false
}

// exports is everything one session's commands wrote.
type exports struct {
	ledgers   []ledgerRow
	txs       []txRow
	ops       []opRow
	effects   []effectRow
	transfers []transferRow
	events    []contractEventRow
	trades    []tradeRow
	rowLedger map[string][]int64 // every export: the ledger of each row that names one
}

// readExports reads every JSON Lines file under out/<command>/ (and its subfolders). A missing folder is an
// export that wrote nothing.
func readExports(out string) (*exports, error) {
	e := &exports{rowLedger: map[string][]int64{}}
	targets := map[string]func([]byte) error{
		"export_ledgers":         func(b []byte) error { return appendRow(b, &e.ledgers) },
		"export_transactions":    func(b []byte) error { return appendRow(b, &e.txs) },
		"export_operations":      func(b []byte) error { return appendRow(b, &e.ops) },
		"export_effects":         func(b []byte) error { return appendRow(b, &e.effects) },
		"export_token_transfer":  func(b []byte) error { return appendRow(b, &e.transfers) },
		"export_contract_events": func(b []byte) error { return appendRow(b, &e.events) },
		"export_trades":          func(b []byte) error { return appendRow(b, &e.trades) },
	}
	for _, cmd := range exportCommands {
		var files []string
		filepath.WalkDir(filepath.Join(out, cmd), func(p string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() && strings.HasSuffix(p, ".txt") {
				files = append(files, p)
			}
			return nil
		})
		sort.Strings(files)
		each := targets[cmd]
		for _, f := range files {
			err := readLines(f, func(b []byte) error {
				var r anyRow
				if json.Unmarshal(b, &r) == nil {
					if l, ok := r.ledger(); ok {
						e.rowLedger[cmd] = append(e.rowLedger[cmd], l)
					}
				}
				if each == nil {
					return nil
				}
				return each(b)
			})
			if err != nil {
				return nil, fmt.Errorf("%s: %w", filepath.Join(cmd, filepath.Base(f)), err)
			}
		}
	}
	return e, nil
}

func appendRow[T any](b []byte, to *[]T) error {
	var r T
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&r); err != nil {
		return err
	}
	*to = append(*to, r)
	return nil
}

func readLines(path string, each func([]byte) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 256<<20)
	n := 0
	for sc.Scan() {
		n++
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		if err := each(line); err != nil {
			return fmt.Errorf("line %d: %w", n, err)
		}
	}
	return sc.Err()
}

// rowsForLedger counts the rows of every export for one ledger (partial-write evidence after a stop).
func (e *exports) rowsForLedger(seq int64) int64 {
	var n int64
	for _, ls := range e.rowLedger {
		for _, l := range ls {
			if l == seq {
				n++
			}
		}
	}
	return n
}

// lastLedger is the highest ledger in the ledgers export, or nil.
func (e *exports) lastLedger() *int64 {
	var last *int64
	for _, r := range e.ledgers {
		if last == nil || r.Sequence > *last {
			v := r.Sequence
			last = &v
		}
	}
	return last
}

// TOIDs (stellar-etl's `id`, `transaction_id`, `operation_id`) pack the ledger, the transaction's application
// order (from 1) and the operation's index (from 1): ledger<<32 | order<<12 | op.
func toidTx(id int64) int64  { return id &^ 0xFFF }
func toidOrder(id int64) int { return int((id >> 12) & 0xFFFFF) }
func toidOp(id int64) int    { return int(id & 0xFFF) }

// mapping holds the lookups the observation needs.
type mapping struct {
	txHash map[int64]string // transaction TOID → hash
}

func (m *mapping) locator(txTOID int64, opTOID *int64) adapterkit.Locator {
	var loc adapterkit.Locator
	loc.TxHash = m.txHash[txTOID]
	if o := toidOrder(txTOID); o > 0 {
		i := o - 1
		loc.TxIndex = &i
	}
	if opTOID != nil && toidOp(*opTOID) > 0 {
		i := toidOp(*opTOID) - 1
		loc.OpIndex = &i
	}
	return loc
}

// observation builds the observation set for p from the exports, keeping only the requested, declared kinds.
func observation(e *exports, p adapterkit.ObserveParams, d adapterkit.DescribeResult) adapterkit.Observation {
	obs := adapterkit.Observation{Schema: adapterkit.ObservationSchema, Range: p.Range, Ledgers: []adapterkit.Ledger{}}
	for _, k := range adapterkit.AllKinds {
		st := obs.Kinds.Kind(k)
		c := d.Observations.Kind(k)
		switch {
		case !c.Supported:
			*st = adapterkit.KindStatus{Status: "not_applicable", Reason: c.Reason}
		case !slices.Contains(p.Kinds, k):
			*st = adapterkit.KindStatus{Status: "not_applicable", Reason: "not requested"}
		default:
			*st = adapterkit.KindStatus{Status: "provided", Subkinds: c.Subkinds}
		}
	}
	provided := func(k string) bool { return obs.Kinds.Kind(k).Status == "provided" }
	m := &mapping{txHash: map[int64]string{}}
	for _, t := range e.txs {
		m.txHash[t.ID] = t.Hash
	}
	keep := func(loc adapterkit.Locator) bool {
		return len(p.TxHashes) == 0 || slices.Contains(p.TxHashes, loc.TxHash)
	}

	byLedger := map[int64]*adapterkit.Ledger{}
	var seqs []int64
	for _, r := range e.ledgers {
		if r.Sequence < p.Range.Start || r.Sequence > p.Range.End || byLedger[r.Sequence] != nil {
			continue
		}
		byLedger[r.Sequence] = &adapterkit.Ledger{LedgerSeq: r.Sequence, LedgerHash: r.LedgerHash}
		seqs = append(seqs, r.Sequence)
	}
	slices.Sort(seqs)
	ledger := func(seq int64) *adapterkit.Ledger { return byLedger[seq] } // nil: the ledger was not seen

	txCount, opCount := map[int64]int64{}, map[int64]int64{} // rows held per ledger
	opCodes := map[int64][]opCode{}                          // transaction TOID → operation result codes
	for _, o := range e.ops {
		opCodes[o.TxID] = append(opCodes[o.TxID], opCode{toidOp(o.ID), operationResultCode(o)})
	}
	for _, t := range e.txs {
		txCount[t.Ledger]++
		l := ledger(t.Ledger)
		if l == nil {
			continue
		}
		loc := m.locator(t.ID, nil)
		if !keep(loc) {
			continue
		}
		if provided(adapterkit.KindTransactions) {
			ok := t.Successful
			l.Transactions = append(l.Transactions, adapterkit.ObsTransaction{Hash: t.Hash, Index: loc.TxIndex, Successful: &ok,
				ResultCode: enumName(t.ResultCode, "TransactionResultCode"), FeeCharged: t.FeeCharged.String(), InnerHash: t.InnerHash,
				NativeLabel: t.ResultCode, OperationResultCodes: operationResultCodes(opCodes[t.ID])})
		}
		// The transaction's source and, for a fee bump, its fee account.
		if provided(adapterkit.KindParticipants) {
			if t.Account != "" {
				l.Participants = append(l.Participants, adapterkit.ObsParticipant{Locator: loc, Account: account(t.Account, t.AccountMuxed)})
			}
			if t.FeeAccount != "" {
				l.Participants = append(l.Participants, adapterkit.ObsParticipant{Locator: loc, Account: account(t.FeeAccount, t.FeeAccountMuxed)})
			}
		}
	}
	for _, o := range e.ops {
		opCount[o.Ledger]++
		l := ledger(o.Ledger)
		if l == nil || !provided(adapterkit.KindParticipants) {
			continue
		}
		id := o.ID
		loc := m.locator(o.TxID, &id)
		if keep(loc) && o.SourceAccount != "" {
			l.Participants = append(l.Participants, adapterkit.ObsParticipant{Locator: loc, Account: account(o.SourceAccount, o.SourceAccountMuxed)})
		}
	}
	for _, ef := range e.effects {
		l := ledger(ef.Ledger)
		if l == nil {
			continue
		}
		id := ef.OperationID
		loc := m.locator(toidTx(id), &id)
		if !keep(loc) {
			continue
		}
		muxed := ""
		if ef.AddressMuxed != nil {
			muxed = *ef.AddressMuxed
		}
		if provided(adapterkit.KindParticipants) && ef.Address != "" {
			l.Participants = append(l.Participants, adapterkit.ObsParticipant{Locator: loc, Account: account(ef.Address, muxed)})
		}
		if provided(adapterkit.KindStateChanges) {
			if sc, ok := stateChange(ef, loc, muxed); ok {
				l.StateChanges = append(l.StateChanges, sc)
			}
		}
	}
	for _, tr := range e.transfers {
		l := ledger(tr.Ledger)
		if l == nil || !provided(adapterkit.KindMovements) || !slices.Contains(MovementKinds, tr.EventTopic) {
			continue
		}
		loc := m.locator(tr.TxID, tr.OperationID)
		if loc.TxHash == "" {
			loc.TxHash = tr.TxHash
		}
		if !keep(loc) {
			continue
		}
		l.Movements = append(l.Movements, movement(tr, loc))
	}
	// Trades: the seller and the buyer of each fill are participants of the operation that made it (a pool's
	// side has no account).
	for _, tr := range e.trades {
		id := tr.HistoryOperationID
		l := ledger(id >> 32)
		if l == nil || !provided(adapterkit.KindParticipants) {
			continue
		}
		loc := m.locator(toidTx(id), &id)
		if !keep(loc) {
			continue
		}
		for _, a := range []string{tr.Seller, tr.Buyer} {
			if a != "" {
				l.Participants = append(l.Participants, adapterkit.ObsParticipant{Locator: loc, Account: account(a, "")})
			}
		}
	}
	evCount := consensusEvents(e.events)
	for _, seq := range seqs {
		l := byLedger[seq]
		if provided(adapterkit.KindReceipts) {
			txs, ops, evs := txCount[seq], opCount[seq], evCount[seq]
			l.Receipt = &adapterkit.Receipt{Transactions: &txs, Operations: &ops, Events: &evs}
		}
		sortFacts(l)
		obs.Ledgers = append(obs.Ledgers, *l)
	}
	return obs
}

// consensusEvents counts, per ledger, the consensus events the contract-events export stored. stellar-etl writes
// a transaction's transaction-level events, its operation events and its diagnostic events into one table; only
// the operation events carry an operation_id. The transaction-level events of CAP-67 are the fee events (first
// topic the symbol "fee"), and the diagnostic list repeats contract events with nothing to tell them apart
// (in a failed transaction too, marked in_successful_contract_call when the call itself succeeded). A row counts
// when it is an operation event, or a transaction-level fee event; diagnostic rows (of any type) do not.
func consensusEvents(rows []contractEventRow) map[int64]int64 {
	out := map[int64]int64{}
	for _, ev := range rows {
		if ev.TypeString == "ContractEventTypeDiagnostic" || !ev.InSuccessfulContractCall {
			continue
		}
		if ev.OperationID == nil && !(len(ev.TopicsDecoded) > 0 && string(ev.TopicsDecoded[0]) == `{"symbol":"fee"}`) {
			continue
		}
		out[ev.Ledger]++
	}
	return out
}

type opCode struct {
	op   int
	code string
}

// operationResultCodes lists a transaction's operation result codes in operation order, or nil when any
// operation row carries no code the mapping knows.
func operationResultCodes(codes []opCode) []string {
	codes = slices.Clone(codes)
	slices.SortFunc(codes, func(a, b opCode) int { return a.op - b.op })
	var out []string
	for _, c := range codes {
		if c.code == "" {
			return nil
		}
		out = append(out, c.code)
	}
	return out
}

// account is an account object as stored: the base column as `address` and the muxed column, when the row has
// one, as `on_chain_form` exactly as emitted. Nothing is derived from either.
func account(base, muxed string) adapterkit.ObsAccount {
	a := adapterkit.ObsAccount{Address: base}
	if muxed != "" {
		a.OnChainForm = muxed
	}
	return a
}

// effectKinds maps stellar-etl effect types to the neutral state-change kinds. Effects of other types are not
// mapped (and so can neither satisfy nor violate an expectation).
var effectKinds = map[string]string{
	"account_created":            "account_created",
	"account_removed":            "account_removed",
	"account_credited":           "balance_changed",
	"account_debited":            "balance_changed",
	"account_thresholds_updated": "thresholds_changed",
	"signer_created":             "signer_added",
	"signer_removed":             "signer_removed",
	"signer_updated":             "signer_changed",
	"trustline_created":          "trustline_created",
	"trustline_removed":          "trustline_removed",
	"trustline_updated":          "trustline_limit_changed",
	"trustline_flags_updated":    "trustline_flags_changed",
	"sequence_bumped":            "sequence_bumped",
}

// StateChangeKinds are the neutral kinds the adapter maps effects to.
var StateChangeKinds = func() []string {
	var out []string
	for _, k := range effectKinds {
		if !slices.Contains(out, k) {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out
}()

// MovementKinds are the token-transfer event topics mapped to movements. Fee rows are not mapped: stellar-etl
// writes a fee refund as a `fee` row with a negative amount, and turning that into a `fee_refund` would mean
// rewriting the row.
var MovementKinds = []string{"transfer", "mint", "burn", "clawback"}

func stateChange(ef effectRow, loc adapterkit.Locator, muxed string) (adapterkit.ObsStateChange, bool) {
	kind, ok := effectKinds[ef.TypeString]
	if !ok {
		return adapterkit.ObsStateChange{}, false
	}
	acct := account(ef.Address, muxed)
	sc := adapterkit.ObsStateChange{Locator: loc, Kind: kind, Account: &acct, NativeLabel: ef.TypeString}
	str := func(k string) (string, bool) {
		raw, ok := ef.Details[k]
		if !ok {
			return "", false
		}
		var s string
		if json.Unmarshal(raw, &s) == nil {
			return s, true
		}
		return string(raw), true
	}
	if at, ok := str("asset_type"); ok {
		if at == "native" {
			sc.Asset = "native"
		} else if code, ok := str("asset_code"); ok {
			if iss, ok := str("asset_issuer"); ok {
				sc.Asset = code + ":" + iss
			}
		}
	}
	detail := map[string]any{}
	switch kind {
	case "balance_changed":
		if v, ok := str("amount"); ok {
			detail["delta_as_stored"] = v
		}
	case "trustline_created", "trustline_limit_changed":
		if v, ok := str("limit"); ok {
			detail["limit_as_stored"] = v
		}
	case "signer_added", "signer_removed", "signer_changed":
		if k, ok := str("public_key"); ok && k != "" {
			sc.Signer = &adapterkit.ObsSigner{AsStored: &adapterkit.Stored{Encoding: "strkey_text", Value: k}}
			if w, ok := ef.Details["weight"]; ok {
				var n int
				if json.Unmarshal(w, &n) == nil {
					sc.Signer.Weight = &n
				}
			}
		}
	}
	if len(detail) > 0 {
		sc.Detail = detail
	}
	return sc, true
}

var plainInteger = regexp.MustCompile(`^-?[0-9]+$`)

// movement maps a token-transfer row. The asset is the row's own classic asset (`CODE:ISSUER`, or `native`),
// else the emitting contract. The amount is `amount_raw`, the exact integer the row carries; without it, the
// `amount` token goes to amount_as_stored untouched. `to_muxed` is passed as `to.on_chain_form` and
// `to_muxed_id` as a u64 routing ID — the ID of the M… address the row carries — exactly as emitted.
func movement(tr transferRow, loc adapterkit.Locator) adapterkit.ObsMovement {
	mv := adapterkit.ObsMovement{Locator: loc, Kind: tr.EventTopic, NativeLabel: tr.EventTopic}
	switch {
	case tr.AssetType == "native":
		mv.Asset = "native"
	case tr.AssetCode != nil && tr.AssetIssuer != nil && *tr.AssetCode != "" && *tr.AssetIssuer != "":
		mv.Asset = *tr.AssetCode + ":" + *tr.AssetIssuer
	default:
		mv.Asset = tr.ContractID
	}
	if plainInteger.MatchString(tr.AmountRaw) {
		mv.Amount = tr.AmountRaw
	} else if len(tr.Amount) > 0 {
		s := string(tr.Amount)
		mv.AmountAsStored = &s
	}
	if tr.From != nil && *tr.From != "" {
		a := account(*tr.From, "")
		mv.From = &a
	}
	if tr.To != nil && *tr.To != "" {
		muxed := ""
		if tr.ToMuxed != nil {
			muxed = *tr.ToMuxed
		}
		a := account(*tr.To, muxed)
		mv.To = &a
	}
	if tr.ToMuxedID != nil {
		v := *tr.ToMuxedID
		mv.Routing = &adapterkit.ObsRouting{Type: "u64", Value: &v}
	}
	return mv
}

// enumName turns a Go enum label stellar-etl stores (TransactionResultCodeTxFeeBumpInnerSuccess) into the
// XDR-JSON name (tx_fee_bump_inner_success): drop the type prefix, snake-case the rest. A label without the
// prefix is passed through unchanged, so it shows as a wrong value rather than a silent match.
func enumName(label, prefix string) string {
	if !strings.HasPrefix(label, prefix) || len(label) == len(prefix) {
		return label
	}
	return snake(strings.TrimPrefix(label, prefix))
}

// operationResultCode is `<operation>.<code>` for an applied operation (from the trace code,
// PaymentResultCodePaymentSuccess → payment.success), or the outer code (op_bad_auth, …).
func operationResultCode(o opRow) string {
	if o.ResultCode != "OperationResultCodeOpInner" {
		if !strings.HasPrefix(o.ResultCode, "OperationResultCode") {
			return ""
		}
		return enumName(o.ResultCode, "OperationResultCode")
	}
	typ, rest, ok := strings.Cut(o.TraceCode, "ResultCode")
	if !ok || rest == "" || o.TypeString == "" {
		return ""
	}
	return o.TypeString + "." + snake(strings.TrimPrefix(rest, typ))
}

func snake(s string) string {
	var b strings.Builder
	for i, r := range s {
		if unicode.IsUpper(r) {
			if i > 0 {
				b.WriteByte('_')
			}
			b.WriteRune(unicode.ToLower(r))
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// sortFacts orders facts as the protocol asks: by transaction index, operation index, then the fact's JSON text.
func sortFacts(l *adapterkit.Ledger) {
	key := func(loc adapterkit.Locator, v any) string {
		tx, op := -1, -1
		if loc.TxIndex != nil {
			tx = *loc.TxIndex
		}
		if loc.OpIndex != nil {
			op = *loc.OpIndex
		}
		b, _ := json.Marshal(v)
		return fmt.Sprintf("%010d|%010d|%s", tx+1, op+1, b)
	}
	sortBy(l.Transactions, func(x adapterkit.ObsTransaction) string {
		i := -1
		if x.Index != nil {
			i = *x.Index
		}
		return fmt.Sprintf("%010d|%s", i+1, x.Hash)
	})
	sortBy(l.Participants, func(x adapterkit.ObsParticipant) string { return key(x.Locator, x) })
	sortBy(l.StateChanges, func(x adapterkit.ObsStateChange) string { return key(x.Locator, x) })
	sortBy(l.Movements, func(x adapterkit.ObsMovement) string { return key(x.Locator, x) })
}

func sortBy[T any](xs []T, key func(T) string) {
	keys := make([]string, len(xs))
	idx := make([]int, len(xs))
	for i := range xs {
		idx[i], keys[i] = i, key(xs[i])
	}
	slices.SortStableFunc(idx, func(a, b int) int { return strings.Compare(keys[a], keys[b]) })
	sorted := make([]T, len(xs))
	for i, j := range idx {
		sorted[i] = xs[j]
	}
	copy(xs, sorted)
}

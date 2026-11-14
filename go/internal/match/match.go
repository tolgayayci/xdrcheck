// Package match compares what an indexer holds (an adapter's observation set) with what a manifest entry
// expects of one variant, fact by fact, exactly as docs/manifest.md §6.2–§6.10 states (the normative rules)
// and docs/replay-harness.md §6 computes them. It produces one result per expected fact — matched, missing, wrong or
// not_applicable — and one result per observed fact of the focus transaction that no expectation accounted for
// — ignored, extra-in-scope or forbidden. It does not classify the entry; the classifier reads Result.
//
// Rules implemented, with their manifest numbers:
//
//   - Scope (§6.3): a fact belongs to the focus transaction (variant focus.tx_hash) or to the transaction at the
//     item's own tx_index, resolved through expect.transactions[].hash. Observed facts are located by tx_hash
//     (or by tx_index through the same table); other transactions are never looked at except through the
//     whole-ledger receipts and the transaction list. Facts without a locator are in scope only when the ledger
//     has a single transaction; otherwise they are listed as unattributed and neither satisfy nor violate.
//   - Ambient facts (balance_changed, sequence_bumped; fee and fee_refund movements) satisfy an item that lists
//     them and are never extras.
//   - Presence: a listed item is required; an only_if item is required only when the adapter declares that
//     modelling choice; kinds and sub-kinds the adapter does not provide are not_applicable (§6.10).
//   - Receipts (§6.2): each counter the adapter provides is compared exactly; a lower count is missing with
//     Shortfall set, a higher one wrong.
//   - Transactions (§6.2): by hash; successful, result_code, operation_result_codes, fee_charged and the
//     fee-bump fields compared where the observation carries them.
//   - Participants P-1…P-6: by base address; a muxed_id is never compared for base_only readers; any reader
//     that reports one must report the expected one; a base_and_alias reader must report it (P-2: the expected
//     ID is read from the ledger by the reference extractor). Identity held only in muxed form is wrong; roles
//     are never compared (the protocol has no way to declare that roles are modelled, so P-4 never applies);
//     must_not_include is checked against everything held for the transaction; exact turns other participants
//     into extras.
//   - Negative facts (a must_not_include item, a count: 0 movement) hold vacuously for a reader that holds
//     nothing for the transaction: they are matched only when the transaction is positively observed (in the
//     transaction list, or some fact of a provided kind is located in it), and not_applicable otherwise. They
//     are marked Negative so that a result of negative facts alone is never a pass.
//   - State changes S-1…S-6: candidates by kind, transaction, base account and asset (either form; a fact that
//     carries no asset is not penalised for it, like a detail key it does not hold); an account held only in a
//     muxed form, or in bytes that carry the key but do not decode, is a wrong account (ledger entries are
//     owned by base accounts); signer
//     compared in full from the stored bytes (a prefix is wrong), and required: a candidate that carries no
//     signer, or a signer without a key, for an item that states one is wrong; a stated detail key compared only when the
//     reader's fact carries it; cause, identifiers, op_index and native labels never compared; exactness over
//     the non-ambient, unaccounted changes of a kind the adapter models. balance_changed at the granularity of the
//     transaction (S-7): when the expected items and the candidates of one (transaction, account, asset) differ in
//     number and none matches alone, their delta sums are compared (one net row against per-event rows, or the
//     reverse).
//   - Movements M-1…M-7: candidates by kind, asset (either form; a contract that is not the asset's own SAC is
//     another asset), base from and to (a muxed endpoint is its embedded base: the ID is routing); amount string-equal (an amount_as_stored token must be a plain equal
//     integer); routing absent ≡ void ≡ none reported; exactly count records; count 0: no record with that
//     kind, asset and endpoints at all, whatever its amount (M-4); fee kinds only when the adapter models them,
//     and never extras. Only the matching records are accounted by a matched item, so under movements_exact a
//     further record of the same transfer with another amount is an extra.
//   - Addresses (§6.8): the expected strkey must be the full decoding of a stored value of the transaction; a
//     stored value that carries the same key but does not decode to it (truncated, padded, wrong type) is wrong.
//
// Stored values are decoded by the harness's own strict strkey decoder (strkey.go) according to as_stored's
// encoding; an adapter's interpreted fields are used only where no as_stored is given — except that an
// `address` beside a muxed as_stored is taken as the base the indexer holds, since adapters fill `address` only
// when the indexer holds that form.
package match

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/tolgayayci/xdrcheck/go/internal/adapter"
	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
)

// Status is the result of one expected fact.
type Status string

const (
	Matched       Status = "matched"
	Missing       Status = "missing"
	Wrong         Status = "wrong"
	NotApplicable Status = "not_applicable"
)

// ExtraStatus is the result of one observed fact no expectation accounted for.
type ExtraStatus string

const (
	Ignored      ExtraStatus = "ignored"        // outside every exactness scope, ambient, or of a kind not modelled
	ExtraInScope ExtraStatus = "extra-in-scope" // inside an exactness scope: counts as a wrong value
	Forbidden    ExtraStatus = "forbidden"      // hits a must-not fact (must_not_include, a count: 0 movement)
)

// Fact kinds of expected facts (Fact.Kind).
const (
	FactReceipt     = "receipt"
	FactTransaction = "transaction"
	FactParticipant = "participant"
	FactMustNot     = "must_not_include"
	FactStateChange = "state_change"
	FactMovement    = "movement"
	FactAddress     = "address"
)

// Result is the match of one variant's expectations against one observation set.
type Result struct {
	LedgerSeq      int64   `json:"ledger_seq"`
	LedgerObserved bool    `json:"ledger_observed"`
	FocusTx        string  `json:"focus_tx"`
	FocusTxSeen    string  `json:"focus_tx_seen"` // present, absent, or unknown (transactions not provided)
	Facts          []Fact  `json:"facts"`
	Extras         []Extra `json:"extras,omitzero"`
	Unattributed   []Ref   `json:"unattributed,omitzero"`
}

// Fact is the result of one expected fact.
type Fact struct {
	Kind      string `json:"kind"`
	Index     int    `json:"index"`            // position in its expect list (receipts: 0)
	Field     string `json:"field,omitzero"`   // receipts: the counter
	Label     string `json:"label"`            // what was expected, in a few words
	TxHash    string `json:"tx_hash,omitzero"` // the transaction it belongs to
	Status    Status `json:"status"`
	Shortfall bool   `json:"shortfall,omitzero"` // receipts: the reader counted fewer than expected
	Negative  bool   `json:"negative,omitzero"`  // a must-not fact: must_not_include, or a count: 0 movement
	Reason    string `json:"reason,omitzero"`
	Diffs     []Diff `json:"diffs,omitzero"`
	Observed  []Ref  `json:"observed,omitzero"` // the observed facts it was compared with
}

// Diff is one differing field.
type Diff struct {
	Field    string `json:"field"`
	Expected string `json:"expected"`
	Observed string `json:"observed"`
}

// Ref points at an observed fact: kind (participants, state_changes, movements, addresses), ledger and index
// in that ledger's array.
type Ref struct {
	Kind   string `json:"kind"`
	Ledger int64  `json:"ledger"`
	Index  int    `json:"index"`
	TxHash string `json:"tx_hash,omitzero"`
}

// Extra is the result of one observed fact of the focus transaction that no expectation accounted for, or that
// hits a must-not fact.
type Extra struct {
	Ref
	Status ExtraStatus `json:"status"`
	Reason string      `json:"reason,omitzero"`
}

// Summary counts a result.
type Summary struct {
	Matched, Missing, Wrong, NotApplicable int
	ExtraInScope, Forbidden                int
	ReceiptShortfall, ReceiptExcess        bool
	// MatchedPositive counts the matched facts that are not negative: only these can make an entry pass, since
	// a must-not fact also holds for a reader that holds nothing.
	MatchedPositive int
}

// Summary counts facts and extras.
func (r *Result) Summary() Summary {
	var s Summary
	for _, f := range r.Facts {
		switch f.Status {
		case Matched:
			s.Matched++
			if !f.Negative {
				s.MatchedPositive++
			}
		case Missing:
			s.Missing++
			s.ReceiptShortfall = s.ReceiptShortfall || f.Shortfall
		case Wrong:
			s.Wrong++
			s.ReceiptExcess = s.ReceiptExcess || f.Kind == FactReceipt
		case NotApplicable:
			s.NotApplicable++
		}
	}
	for _, e := range r.Extras {
		switch e.Status {
		case ExtraInScope:
			s.ExtraInScope++
		case Forbidden:
			s.Forbidden++
		}
	}
	return s
}

// AnyWrong reports a wrong fact, an extra in an exactness scope, or a forbidden fact present.
func (s Summary) AnyWrong() bool { return s.Wrong > 0 || s.ExtraInScope > 0 || s.Forbidden > 0 }

// Input is one variant's expectations and one observation set.
type Input struct {
	Expect       *manifest.Expect // resolved for the variant (Variant.Resolved)
	LedgerSeq    int64
	FocusTxHash  string
	FocusTxIndex *int
	Passphrase   string                // the pass's network passphrase, for asset contract IDs
	Declared     *adapter.Observations // describe's declarations; nil uses the observation's kinds alone
	Observation  *adapter.Observation
}

// MatchVariant matches one variant of an entry.
func MatchVariant(v *manifest.Variant, declared *adapter.Observations, obs *adapter.Observation) (*Result, error) {
	if v.Resolved == nil {
		return nil, fmt.Errorf("variant %s@%d is not resolved", v.Network, v.Protocol)
	}
	in := Input{Expect: v.Resolved, LedgerSeq: v.LedgerSeq, Passphrase: v.Passphrase, Declared: declared, Observation: obs}
	if v.Focus != nil {
		in.FocusTxHash, in.FocusTxIndex = v.Focus.TxHash, v.Focus.TxIndex
	}
	return Match(in)
}

// Match runs every rule. An error means the expectations themselves cannot be evaluated (an unresolvable
// transaction scope, an expected address or asset that does not decode): a corpus fault, not a reader result.
func Match(in Input) (*Result, error) {
	if in.Expect == nil || in.Observation == nil {
		return nil, fmt.Errorf("match: expectations and observation are required")
	}
	m := &matcher{in: in, exp: in.Expect, accounted: map[Ref]bool{}, forbidden: map[Ref]string{}}
	m.res = &Result{LedgerSeq: in.LedgerSeq, FocusTx: in.FocusTxHash}
	m.ledger = in.Observation.Ledger(in.LedgerSeq)
	m.res.LedgerObserved = m.ledger != nil
	if m.ledger == nil {
		m.ledger = &adapter.Ledger{LedgerSeq: in.LedgerSeq}
	}
	m.indexToHash = map[int]string{}
	for _, t := range m.exp.Transactions {
		if t.Hash != "" {
			m.indexToHash[t.Index] = t.Hash
		}
	}
	if in.FocusTxIndex != nil && in.FocusTxHash != "" {
		m.indexToHash[*in.FocusTxIndex] = in.FocusTxHash
	}
	m.singleTx = ""
	if n := m.exp.Ledger; n != nil && n.Transactions != nil && *n.Transactions == 1 {
		m.singleTx = in.FocusTxHash
		if m.singleTx == "" && len(m.exp.Transactions) == 1 {
			m.singleTx = m.exp.Transactions[0].Hash
		}
	}
	m.supports = map[string]support{}
	for _, k := range adapter.AllKinds {
		m.supports[k] = m.kindSupport(k)
	}
	m.collectUnattributed()

	steps := []func() error{m.receipts, m.transactions, m.participants, m.stateChanges, m.movements, m.addresses}
	for _, step := range steps {
		if err := step(); err != nil {
			return nil, err
		}
	}
	m.extras()
	return m.res, nil
}

type matcher struct {
	in          Input
	exp         *manifest.Expect
	res         *Result
	ledger      *adapter.Ledger
	indexToHash map[int]string
	singleTx    string
	supports    map[string]support
	accounted   map[Ref]bool
	forbidden   map[Ref]string // must-not hits, with the reason
	// which observed kinds an exactness flag covers, set by the steps
	participantsExact, stateChangesExact, movementsExact bool
}

// ---- kinds and sub-kinds ----

type support struct {
	provided bool
	subkinds []string // nil: all
	reason   string
}

func (s support) has(sub string) bool {
	return s.provided && (s.subkinds == nil || slices.Contains(s.subkinds, sub))
}

// kindSupport combines describe's declaration and the observe response's status: a kind is provided only when
// both say so, and its sub-kinds are the intersection of both lists.
func (m *matcher) kindSupport(kind string) support {
	st := m.in.Observation.Kinds.Kind(kind)
	if st == nil || st.Status != "provided" {
		reason := "the adapter does not provide " + kind
		if st != nil && st.Reason != "" {
			reason += ": " + st.Reason
		}
		return support{reason: reason}
	}
	sub := st.Subkinds
	if m.in.Declared != nil {
		c := m.in.Declared.Kind(kind)
		if !c.Supported {
			reason := "the adapter declares " + kind + " unsupported"
			if c.Reason != "" {
				reason += ": " + c.Reason
			}
			return support{reason: reason}
		}
		switch {
		case c.Subkinds == nil:
		case sub == nil:
			sub = c.Subkinds
		default:
			var both []string
			for _, s := range sub {
				if slices.Contains(c.Subkinds, s) {
					both = append(both, s)
				}
			}
			sub = append([]string{}, both...)
		}
	}
	return support{provided: true, subkinds: sub}
}

func (m *matcher) na(kind, sub string) string {
	s := m.supports[kind]
	if !s.provided {
		return s.reason
	}
	return fmt.Sprintf("the adapter does not model %s %q", kind, sub)
}

func (m *matcher) modelling() []string {
	if m.in.Declared == nil {
		return nil
	}
	return m.in.Declared.StateChanges.Modelling
}

// ---- scope ----

// scope resolves an item's transaction.
func (m *matcher) scope(txIndex *int) (string, error) {
	if txIndex == nil {
		if m.in.FocusTxHash == "" {
			return "", fmt.Errorf("the variant has no focus.tx_hash and the item no tx_index")
		}
		return m.in.FocusTxHash, nil
	}
	if h, ok := m.indexToHash[*txIndex]; ok {
		return h, nil
	}
	return "", fmt.Errorf("tx_index %d resolves to no hash (expect.transactions has none at that index)", *txIndex)
}

// txOf locates an observed fact. ok is false for a fact with no locator in a ledger of several transactions.
func (m *matcher) txOf(loc adapter.Locator) (string, bool) {
	switch {
	case loc.TxHash != "":
		return loc.TxHash, true
	case loc.TxIndex != nil:
		if h, ok := m.indexToHash[*loc.TxIndex]; ok {
			return h, true
		}
		return fmt.Sprintf("#%d", *loc.TxIndex), true // a transaction the entry does not list
	case m.singleTx != "":
		return m.singleTx, true
	}
	return "", false
}

func (m *matcher) collectUnattributed() {
	l := m.ledger
	add := func(kind string, i int, loc adapter.Locator) {
		if _, ok := m.txOf(loc); !ok {
			m.res.Unattributed = append(m.res.Unattributed, Ref{Kind: kind, Ledger: l.LedgerSeq, Index: i})
		}
	}
	for i, p := range l.Participants {
		add(adapter.KindParticipants, i, p.Locator)
	}
	for i, s := range l.StateChanges {
		add(adapter.KindStateChanges, i, s.Locator)
	}
	for i, mv := range l.Movements {
		add(adapter.KindMovements, i, mv.Locator)
	}
	for i, a := range l.Addresses {
		add(adapter.KindAddresses, i, a.Locator)
	}
}

func (m *matcher) inTx(loc adapter.Locator, tx string) bool {
	h, ok := m.txOf(loc)
	return ok && h == tx
}

// txObserved reports whether the reader positively holds the transaction: it is in the transaction list, or a
// fact of a provided kind is located in it. A negative fact is evidence only then.
func (m *matcher) txObserved(tx string) bool {
	l := m.ledger
	if m.supports[adapter.KindTransactions].provided {
		for _, t := range l.Transactions {
			if t.Hash == tx {
				return true
			}
		}
	}
	located := func(kind string, n int, loc func(int) adapter.Locator) bool {
		if !m.supports[kind].provided {
			return false
		}
		for i := 0; i < n; i++ {
			if m.inTx(loc(i), tx) {
				return true
			}
		}
		return false
	}
	return located(adapter.KindParticipants, len(l.Participants), func(i int) adapter.Locator { return l.Participants[i].Locator }) ||
		located(adapter.KindStateChanges, len(l.StateChanges), func(i int) adapter.Locator { return l.StateChanges[i].Locator }) ||
		located(adapter.KindMovements, len(l.Movements), func(i int) adapter.Locator { return l.Movements[i].Locator }) ||
		located(adapter.KindAddresses, len(l.Addresses), func(i int) adapter.Locator { return l.Addresses[i].Locator })
}

const notObserved = "the reader holds nothing for the transaction, so a must-not fact proves nothing"

// unverified makes the result of an item marked `unverified` (a stated value the reference extractor cannot
// derive) not_applicable. Its candidates stay accounted, so they are not extras either.
func unverified(f *Fact, reason string) {
	if reason != "" {
		f.Status, f.Reason, f.Diffs = NotApplicable, "unverified: "+reason, nil
	}
}

func (m *matcher) add(f Fact) { m.res.Facts = append(m.res.Facts, f) }

// ---- receipts and transactions ----

func (m *matcher) receipts() error {
	lc := m.exp.Ledger
	if lc == nil {
		return nil
	}
	var r adapter.Receipt
	if m.ledger.Receipt != nil {
		r = *m.ledger.Receipt
	}
	for _, c := range []struct {
		name     string
		want     *int
		observed *int64
	}{{"transactions", lc.Transactions, r.Transactions}, {"operations", lc.Operations, r.Operations}, {"events", lc.Events, r.Events}, {"entry_changes", lc.EntryChanges, r.EntryChanges}} {
		if c.want == nil {
			continue
		}
		f := Fact{Kind: FactReceipt, Field: c.name, Label: fmt.Sprintf("ledger %d: %d %s", m.in.LedgerSeq, *c.want, c.name)}
		switch {
		case !m.supports[adapter.KindReceipts].has(c.name):
			f.Status, f.Reason = NotApplicable, m.na(adapter.KindReceipts, c.name)
		case !m.res.LedgerObserved:
			f.Status, f.Reason, f.Shortfall = Missing, "the ledger is absent from the observation", true
		case c.observed == nil:
			f.Status, f.Reason = Missing, "the receipt does not carry this counter"
		case *c.observed == int64(*c.want):
			f.Status = Matched
		case *c.observed < int64(*c.want):
			f.Status, f.Shortfall, f.Reason = Missing, true, "the reader counted fewer"
			f.Diffs = []Diff{{c.name, fmt.Sprint(*c.want), fmt.Sprint(*c.observed)}}
		default:
			f.Status, f.Reason = Wrong, "the reader counted more"
			f.Diffs = []Diff{{c.name, fmt.Sprint(*c.want), fmt.Sprint(*c.observed)}}
		}
		m.add(f)
	}
	return nil
}

func (m *matcher) transactions() error {
	sup := m.supports[adapter.KindTransactions]
	m.res.FocusTxSeen = "unknown"
	if sup.provided && m.in.FocusTxHash != "" {
		m.res.FocusTxSeen = "absent"
		for _, t := range m.ledger.Transactions {
			if t.Hash == m.in.FocusTxHash {
				m.res.FocusTxSeen = "present"
			}
		}
	}
	for i, et := range m.exp.Transactions {
		f := Fact{Kind: FactTransaction, Index: i, TxHash: et.Hash, Label: fmt.Sprintf("transaction %d %s successful=%v", et.Index, short(et.Hash), et.Successful)}
		if !sup.provided {
			f.Status, f.Reason = NotApplicable, sup.reason
			m.add(f)
			continue
		}
		var found []int
		for j, t := range m.ledger.Transactions {
			if (et.Hash != "" && t.Hash == et.Hash) || (et.Hash == "" && t.Index != nil && *t.Index == et.Index) {
				found = append(found, j)
			}
		}
		if len(found) == 0 {
			f.Status, f.Reason = Missing, "no transaction with this hash"
			m.add(f)
			continue
		}
		for _, j := range found {
			t := m.ledger.Transactions[j]
			f.Observed = append(f.Observed, Ref{Kind: adapter.KindTransactions, Ledger: m.ledger.LedgerSeq, Index: j, TxHash: t.Hash})
			if t.Successful != nil && *t.Successful != et.Successful {
				f.Diffs = append(f.Diffs, Diff{"successful", fmt.Sprint(et.Successful), fmt.Sprint(*t.Successful)})
			}
			cmp := func(field, want, got string) {
				if want != "" && got != "" && want != got {
					f.Diffs = append(f.Diffs, Diff{field, want, got})
				}
			}
			cmp("result_code", et.ResultCode, t.ResultCode)
			cmp("fee_charged", et.FeeCharged, t.FeeCharged)
			cmp("inner_hash", et.InnerHash, t.InnerHash)
			cmp("inner_result_code", et.InnerResultCode, t.InnerResultCode)
			if et.OperationResultCodes != nil && t.OperationResultCodes != nil && !slices.Equal(et.OperationResultCodes, t.OperationResultCodes) {
				f.Diffs = append(f.Diffs, Diff{"operation_result_codes", strings.Join(et.OperationResultCodes, ","), strings.Join(t.OperationResultCodes, ",")})
			}
			if et.InnerSuccessful != nil && t.InnerSuccessful != nil && *et.InnerSuccessful != *t.InnerSuccessful {
				f.Diffs = append(f.Diffs, Diff{"inner_successful", fmt.Sprint(*et.InnerSuccessful), fmt.Sprint(*t.InnerSuccessful)})
			}
		}
		f.Status = Matched
		if len(f.Diffs) > 0 {
			f.Status = Wrong
		}
		m.add(f)
	}
	return nil
}

// ---- identities ----

// ident is what the harness makes of an observed account object.
type ident struct {
	base      *Address // the base identity the reader holds
	muxed     *Address // the muxed form, when held
	muxedID   string
	rawKey    []byte // raw_key_hex: identity by key only
	muxedOnly bool   // only the M/W form is held
	err       string // the value does not decode
	sv        *storedValue
	shown     string
}

func identOf(a *adapter.ObsAccount) ident {
	var id ident
	if a == nil {
		id.err = "no account"
		return id
	}
	setFrom := func(x Address) {
		switch {
		case x.IsBase():
			id.base = &x
		case x.IsMuxed():
			id.muxed = &x
			id.muxedID, _ = x.MuxedID()
		default:
			id.err = "a " + x.Kind() + " address is not an account identity"
		}
	}
	if a.AsStored != nil {
		sv := decodeStored(a.AsStored.Encoding, a.AsStored.Value, ctxAccount)
		id.sv, id.shown = &sv, sv.shown
		switch {
		case sv.rawKey:
			id.rawKey = sv.raw
		case len(sv.readings) > 0:
			setFrom(sv.readings[0])
		default:
			id.err = sv.err
		}
		// An address beside a muxed stored value is the base the indexer holds (adapters fill it only then).
		if id.muxed != nil && a.Address != "" {
			if b, err := DecodeStrkey(a.Address); err == nil && b.IsBase() {
				id.base = &b
			}
		}
	} else {
		id.shown = a.Address
		if a.Address != "" {
			if x, err := DecodeStrkey(a.Address); err != nil {
				id.err = "address " + a.Address + ": " + err.Error()
			} else {
				setFrom(x)
			}
		}
		if a.OnChainForm != "" {
			if id.shown == "" {
				id.shown = a.OnChainForm
			}
			if x, err := DecodeStrkey(a.OnChainForm); err == nil && x.IsMuxed() {
				id.muxed = &x
				if id.muxedID == "" {
					id.muxedID, _ = x.MuxedID()
				}
			} else if id.base == nil && id.err == "" {
				id.err = "on_chain_form " + a.OnChainForm + " is not a muxed address"
			}
		}
	}
	if a.MuxedID != "" {
		id.muxedID = a.MuxedID
	}
	id.muxedOnly = id.base == nil && id.muxed != nil
	if id.base == nil && id.muxed == nil && id.rawKey == nil && id.err == "" {
		id.err = "no address form"
	}
	return id
}

// sameBase reports whether the identity's base is e (a raw key matches by key material on 32-byte types).
func (id ident) sameBase(e Address) bool {
	if id.base != nil {
		return id.base.Equal(e)
	}
	return id.rawKey != nil && e.Version != VersionClaimableBalance && bytes.Equal(id.rawKey, e.Key())
}

// endpointIs reports whether a movement endpoint is e by base address (M-1): the base held, or the base
// embedded in a muxed form — a muxed ID on a movement is routing information, not another account.
func (id ident) endpointIs(e Address) bool {
	if id.sameBase(e) {
		return true
	}
	if id.muxed != nil {
		b, _ := id.muxed.Base()
		return b.Equal(e)
	}
	return false
}

// relatedTo reports whether the identity is about e although it does not hold e's base: muxed only, or a
// stored value that carries e's key but does not decode.
func (id ident) relatedTo(e Address) (bool, string) {
	if id.muxedOnly {
		if b, _ := id.muxed.Base(); b.Equal(e) {
			return true, "identity stored only in muxed form (" + id.muxed.String() + ")"
		}
	}
	if id.err != "" && id.sv != nil && id.sv.carriesKey(e.Key()) {
		return true, "stored value carries the key but does not decode: " + id.err
	}
	return false, ""
}

// hitsForbidden reports whether the identity is the forbidden address: by base for a base address; for a muxed
// address, the same base and ID.
func (id ident) hitsForbidden(f Address) bool {
	if f.IsMuxed() {
		fid, _ := f.MuxedID()
		if id.muxed != nil && id.muxed.Equal(f) {
			return true
		}
		b, _ := f.Base()
		return id.sameBase(b) && id.muxedID == fid
	}
	if id.sameBase(f) {
		return true
	}
	if id.muxed != nil {
		b, _ := id.muxed.Base()
		return b.Equal(f)
	}
	return false
}

func decodeExpected(field, s string) (Address, error) {
	a, err := DecodeStrkey(s)
	if err != nil {
		return Address{}, fmt.Errorf("expected %s %q does not decode: %v", field, s, err)
	}
	return a, nil
}

// ---- participants ----

func (m *matcher) participants() error {
	p := m.exp.Participants
	if p == nil {
		return nil
	}
	sup := m.supports[adapter.KindParticipants]
	tx, err := m.scope(nil)
	if err != nil {
		return err
	}
	l := m.ledger
	var inScope []int
	for i, op := range l.Participants {
		if m.inTx(op.Locator, tx) {
			inScope = append(inScope, i)
		}
	}
	ref := func(i int) Ref {
		return Ref{Kind: adapter.KindParticipants, Ledger: l.LedgerSeq, Index: i, TxHash: tx}
	}
	baseOnly := m.in.Declared != nil && m.in.Declared.Participants.Muxed == "base_only"
	// A reader that declares it stores the muxed alias must report the expected muxed ID (P-2).
	alias := m.in.Declared != nil && m.in.Declared.Participants.Muxed == "base_and_alias"

	for i, item := range p.MustInclude {
		e, err := decodeExpected("participant", item.Address)
		if err != nil {
			return err
		}
		f := Fact{Kind: FactParticipant, Index: i, TxHash: tx, Label: "participant " + item.Address}
		if !sup.provided {
			f.Status, f.Reason = NotApplicable, sup.reason
			m.add(f)
			continue
		}
		if why, err := m.participantOutOfScope(item); err != nil {
			return err
		} else if why != "" {
			f.Status, f.Reason = NotApplicable, why
			m.add(f)
			continue
		}
		var cands, related []int
		var why string
		for _, j := range inScope {
			id := identOf(&l.Participants[j].Account)
			if id.sameBase(e) {
				cands = append(cands, j)
			} else if ok, w := id.relatedTo(e); ok {
				related, why = append(related, j), w
			}
		}
		switch {
		case len(cands) > 0:
			f.Status = Matched
			if item.MuxedID != "" && !baseOnly {
				compatible, reported := false, false
				for _, j := range cands {
					id := identOf(&l.Participants[j].Account)
					onChain := l.Participants[j].Account.OnChainForm
					reported = reported || id.muxedID != ""
					idOK := id.muxedID == item.MuxedID || (id.muxedID == "" && !alias)
					if idOK && (onChain == "" || item.OnChainForm == "" || onChain == item.OnChainForm) {
						compatible = true
					} else {
						f.Diffs = append(f.Diffs, Diff{"muxed_id", item.MuxedID, id.muxedID})
					}
				}
				switch {
				case compatible:
				case alias && !reported:
					f.Status, f.Reason = Wrong, "the adapter declares muxed: base_and_alias but reports no muxed ID for this account"
				default:
					f.Status, f.Reason = Wrong, "the reader reports another muxed ID for this account"
				}
				if compatible {
					f.Diffs = nil
				}
			}
			for _, j := range cands {
				f.Observed = append(f.Observed, ref(j))
				m.accounted[ref(j)] = true
			}
		case len(related) > 0:
			f.Status, f.Reason = Wrong, why
			for _, j := range related {
				f.Observed = append(f.Observed, ref(j))
				m.accounted[ref(j)] = true
			}
		default:
			f.Status, f.Reason = Missing, "no participant with this base address"
		}
		unverified(&f, item.Unverified)
		m.add(f)
	}

	for i, item := range p.MustNotInclude {
		fa, err := decodeExpected("must_not_include address", item.Address)
		if err != nil {
			return err
		}
		f := Fact{Kind: FactMustNot, Index: i, TxHash: tx, Label: "not " + item.Address, Negative: true}
		hits, searched := m.searchForbidden(fa, tx)
		switch {
		case !searched:
			f.Status, f.Reason = NotApplicable, "the adapter provides none of the kinds that hold addresses"
		case len(hits) > 0:
			f.Status, f.Reason, f.Observed = Wrong, "forbidden address present: "+item.Because, hits
			for _, h := range hits {
				m.forbidden[h] = "must_not_include " + item.Address + ": " + item.Because
			}
		case !m.txObserved(tx):
			f.Status, f.Reason = NotApplicable, notObserved
		default:
			f.Status = Matched
		}
		m.add(f)
	}
	m.participantsExact = p.Exact && sup.provided
	return nil
}

// searchForbidden looks for a forbidden address in everything held for the transaction, except a movement the
// entry lists itself with that address as an endpoint (listedMovement).
func (m *matcher) searchForbidden(fa Address, tx string) ([]Ref, bool) {
	l := m.ledger
	var hits []Ref
	searched := false
	check := func(kind string, i int, loc adapter.Locator, acct *adapter.ObsAccount) {
		if acct != nil && m.inTx(loc, tx) && identOf(acct).hitsForbidden(fa) {
			r := Ref{Kind: kind, Ledger: l.LedgerSeq, Index: i, TxHash: tx}
			if len(hits) == 0 || hits[len(hits)-1] != r {
				hits = append(hits, r)
			}
		}
	}
	if m.supports[adapter.KindParticipants].provided {
		searched = true
		for i := range l.Participants {
			check(adapter.KindParticipants, i, l.Participants[i].Locator, &l.Participants[i].Account)
		}
	}
	if m.supports[adapter.KindStateChanges].provided {
		searched = true
		for i := range l.StateChanges {
			check(adapter.KindStateChanges, i, l.StateChanges[i].Locator, l.StateChanges[i].Account)
		}
	}
	if m.supports[adapter.KindMovements].provided {
		searched = true
		for i := range l.Movements {
			if m.listedMovement(&l.Movements[i], tx, fa) {
				continue
			}
			check(adapter.KindMovements, i, l.Movements[i].Locator, l.Movements[i].From)
			check(adapter.KindMovements, i, l.Movements[i].Locator, l.Movements[i].To)
		}
	}
	if m.supports[adapter.KindAddresses].provided {
		searched = true
		for i, a := range l.Addresses {
			if !m.inTx(a.Locator, tx) {
				continue
			}
			sv := decodeStored(a.AsStored.Encoding, a.AsStored.Value, ctxForType(a.Type))
			for _, x := range sv.readings {
				hit := x.Equal(fa)
				if !fa.IsMuxed() {
					if b, ok := x.Base(); ok && b.Equal(fa) {
						hit = true
					}
				}
				if hit {
					hits = append(hits, Ref{Kind: adapter.KindAddresses, Ledger: l.LedgerSeq, Index: i, TxHash: tx})
					break
				}
			}
		}
	}
	return hits, searched
}

func ctxForType(t string) int {
	switch t {
	case "signed_payload", "pre_auth_tx", "hash_x":
		return ctxSigner
	case "":
		return ctxAny
	}
	return ctxAccount
}

// ---- state changes ----

func (m *matcher) stateChanges() error {
	sup := m.supports[adapter.KindStateChanges]
	l := m.ledger
	for i, item := range m.exp.StateChanges {
		tx, err := m.scope(item.TxIndex)
		if err != nil {
			return fmt.Errorf("expect.state_changes[%d]: %w", i, err)
		}
		e, err := decodeExpected("state-change account", item.Account.Address)
		if err != nil {
			return err
		}
		if item.Asset != "" {
			if _, err := parseAsset(item.Asset); err != nil {
				return fmt.Errorf("expect.state_changes[%d]: %w", i, err)
			}
		}
		label := item.Kind + " " + item.Account.Address
		if item.Asset != "" {
			label += " " + item.Asset
		}
		f := Fact{Kind: FactStateChange, Index: i, TxHash: tx, Label: label}
		if !sup.has(item.Kind) {
			f.Status, f.Reason = NotApplicable, m.na(adapter.KindStateChanges, item.Kind)
			m.add(f)
			continue
		}
		if why, err := m.stateChangeOutOfScope(item); err != nil {
			return err
		} else if why != "" {
			f.Status, f.Reason = NotApplicable, why
			m.add(f)
			continue
		}
		required := item.OnlyIf == "" || slices.Contains(m.modelling(), item.OnlyIf)

		type cand struct {
			j     int
			diffs []Diff
		}
		var cands []cand
		for j := range l.StateChanges {
			o := &l.StateChanges[j]
			if o.Kind != item.Kind || !m.inTx(o.Locator, tx) || o.Account == nil {
				continue
			}
			id := identOf(o.Account)
			var diffs []Diff
			if !id.sameBase(e) {
				ok, why := id.relatedTo(e)
				if !ok {
					continue
				}
				diffs = append(diffs, Diff{"account", item.Account.Address, why})
			}
			if item.Asset != "" && o.Asset != "" {
				if same, _ := sameAsset(item.Asset, o.Asset, m.in.Passphrase); !same {
					continue
				}
			}
			diffs = append(diffs, compareSigner(item.Signer, o.Signer)...)
			diffs = append(diffs, compareDetail(item.Detail, o.Detail)...)
			cands = append(cands, cand{j, diffs})
		}
		ref := func(j int) Ref { return Ref{Kind: adapter.KindStateChanges, Ledger: l.LedgerSeq, Index: j, TxHash: tx} }
		var matches []int
		for _, c := range cands {
			if len(c.diffs) == 0 {
				matches = append(matches, c.j)
			}
		}
		var net *netResult
		if len(matches) == 0 && len(cands) > 0 && item.Kind == "balance_changed" {
			var rows []map[string]any
			ok := true
			for _, c := range cands {
				ok = ok && onlyBalanceDiffs(c.diffs)
				rows = append(rows, l.StateChanges[c.j].Detail)
			}
			if ok {
				net = m.netBalance(i, tx, e, rows)
			}
		}
		switch {
		case len(matches) > 0:
			f.Status = Matched
			for _, j := range matches {
				f.Observed = append(f.Observed, ref(j))
				m.accounted[ref(j)] = true
			}
		case net != nil:
			f.Status, f.Reason, f.Diffs = Matched, net.reason, net.diffs
			if len(net.diffs) > 0 {
				f.Status = Wrong
			}
			for _, c := range cands {
				f.Observed = append(f.Observed, ref(c.j))
				m.accounted[ref(c.j)] = true
			}
		case len(cands) > 0:
			f.Status, f.Reason = Wrong, "a candidate differs"
			for _, c := range cands {
				f.Observed = append(f.Observed, ref(c.j))
				f.Diffs = append(f.Diffs, c.diffs...)
				m.accounted[ref(c.j)] = true
			}
		case required:
			f.Status, f.Reason = Missing, "no "+item.Kind+" for this account and asset in the transaction"
		default:
			f.Status, f.Reason = NotApplicable, "only_if "+item.OnlyIf+": the adapter does not declare this modelling choice"
		}
		if item.OnlyIf != "" && !required && f.Status != NotApplicable {
			f.Reason = strings.TrimSpace(f.Reason + " (only_if " + item.OnlyIf + " not declared; reported anyway)")
		}
		unverified(&f, item.Unverified)
		m.add(f)
	}
	m.stateChangesExact = m.exp.StateChangesExact && sup.provided
	return nil
}

// ---- balance granularity (S-7) ----

// netResult is the outcome of comparing balance changes at the granularity of the transaction.
type netResult struct {
	reason string
	diffs  []Diff // empty: the nets agree
}

// onlyBalanceDiffs reports whether a candidate differs from its item in the amount fields alone.
func onlyBalanceDiffs(d []Diff) bool {
	for _, x := range d {
		if x.Field != "detail.delta" && x.Field != "detail.balance_after" {
			return false
		}
	}
	return true
}

// netBalance applies S-7. Readers record a balance change either once per transaction (the net delta, as the
// reference extractor does) or once per event or operation (one row per transfer, mint or path hop). When the
// expected balance_changed items and the reader's candidates for one (transaction, base account, asset) differ in
// number and no single candidate matches, the two sides are compared by their sums: the expected items' deltas
// against the candidates' deltas. Equal sums match; different sums are wrong, with the sums as the diff. Where both
// sides state balance_after, some expected value must also be among the observed ones (the last event's balance is
// the net row's). It returns nil when the rule does not apply: the counts agree (the rows are compared one to one),
// or a delta is missing or not an integer on either side.
func (m *matcher) netBalance(index int, tx string, account Address, observed []map[string]any) *netResult {
	item := m.exp.StateChanges[index]
	var group []manifest.StateChange
	for _, x := range m.exp.StateChanges {
		if x.Kind != item.Kind || x.Asset != item.Asset || x.Unverified != "" {
			continue
		}
		if h, err := m.scope(x.TxIndex); err != nil || h != tx {
			continue
		}
		if a, err := DecodeStrkey(x.Account.Address); err != nil || !a.Equal(account) {
			continue
		}
		group = append(group, x)
	}
	if len(group) == len(observed) {
		return nil
	}
	want, ok := sumDeltas(len(group), func(i int) map[string]any { return group[i].Detail })
	if !ok {
		return nil
	}
	got, ok := sumDeltas(len(observed), func(i int) map[string]any { return observed[i] })
	if !ok {
		return nil
	}
	r := &netResult{reason: fmt.Sprintf("net of %d expected and %d observed balance changes compared (S-7)", len(group), len(observed))}
	if want.Cmp(got) != 0 {
		r.diffs = append(r.diffs, Diff{fmt.Sprintf("detail.delta (sum of %d expected, %d observed)", len(group), len(observed)), want.String(), got.String()})
	}
	var wantAfter, gotAfter []any
	for _, x := range group {
		if v, ok := x.Detail["balance_after"]; ok {
			wantAfter = append(wantAfter, v)
		}
	}
	for _, o := range observed {
		if v, ok := o["balance_after"]; ok {
			gotAfter = append(gotAfter, v)
		}
	}
	if len(wantAfter) > 0 && len(gotAfter) > 0 {
		common := false
		for _, w := range wantAfter {
			for _, g := range gotAfter {
				common = common || jsonEqual(w, g)
			}
		}
		if !common {
			r.diffs = append(r.diffs, Diff{"detail.balance_after (no common value)", show(wantAfter), show(gotAfter)})
		}
	}
	if len(r.diffs) > 0 {
		r.reason = fmt.Sprintf("the net of %d observed balance changes differs from the net of %d expected (S-7)", len(observed), len(group))
	}
	return r
}

// sumDeltas adds the integer `delta` of n detail objects; ok is false when one has none or it is not an integer.
func sumDeltas(n int, detail func(int) map[string]any) (*big.Int, bool) {
	sum := new(big.Int)
	for i := 0; i < n; i++ {
		v, ok := detail(i)["delta"]
		if !ok {
			return nil, false
		}
		var s string
		switch x := v.(type) {
		case string:
			s = x
		case json.Number:
			s = string(x)
		case int:
			s = fmt.Sprint(x)
		case int64:
			s = fmt.Sprint(x)
		default:
			return nil, false
		}
		if !plainInteger.MatchString(s) {
			return nil, false
		}
		d, _ := new(big.Int).SetString(s, 10)
		sum.Add(sum, d)
	}
	return sum, true
}

// compareSigner compares a stated signer with the candidate's (S-2). The signer itself is required: the item's
// kind is one the adapter declares, so a candidate that carries no signer, or a signer with no key, is wrong.
// The key is read from the stored bytes in full; type, payload and weight are compared where the observed
// signer carries them.
func compareSigner(e *manifest.Signer, o *adapter.ObsSigner) []Diff {
	if e == nil {
		return nil
	}
	if o == nil {
		return []Diff{{"signer", e.Key, "(none)"}}
	}
	var d []Diff
	switch {
	case e.Key != "" && o.AsStored == nil && o.Key == "":
		d = append(d, Diff{"signer.key", e.Key, "(none)"})
	case o.AsStored != nil && e.Key != "":
		sv := decodeStored(o.AsStored.Encoding, o.AsStored.Value, ctxSigner)
		switch {
		case len(sv.readings) == 0:
			d = append(d, Diff{"signer.key", e.Key, fmt.Sprintf("undecodable %s (%s)", sv.shown, sv.err)})
		case sv.readings[0].String() != e.Key:
			d = append(d, Diff{"signer.key", e.Key, sv.readings[0].String()})
		}
	case o.Key != "" && e.Key != "" && o.Key != e.Key:
		d = append(d, Diff{"signer.key", e.Key, o.Key})
	}
	if o.Type != "" && e.Type != "" && o.Type != e.Type {
		d = append(d, Diff{"signer.type", e.Type, o.Type})
	}
	if o.PayloadHex != "" && e.PayloadHex != "" && o.PayloadHex != e.PayloadHex {
		d = append(d, Diff{"signer.payload_hex", e.PayloadHex, o.PayloadHex})
	}
	if o.Weight != nil && e.Weight != nil && *o.Weight != *e.Weight {
		d = append(d, Diff{"signer.weight", fmt.Sprint(*e.Weight), fmt.Sprint(*o.Weight)})
	}
	return d
}

// compareDetail compares each stated key the observed fact carries, by exact JSON equality. A key the reader
// does not hold is skipped; <key>_as_stored values are never compared.
func compareDetail(e, o map[string]any) []Diff {
	var keys []string
	for k := range e {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var d []Diff
	for _, k := range keys {
		ov, ok := o[k]
		if !ok {
			continue
		}
		if !jsonEqual(e[k], ov) {
			d = append(d, Diff{"detail." + k, show(e[k]), show(ov)})
		}
	}
	return d
}

// ---- movements ----

var plainInteger = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

func (m *matcher) movements() error {
	sup := m.supports[adapter.KindMovements]
	l := m.ledger
	for i, item := range m.exp.Movements {
		tx, err := m.scope(item.TxIndex)
		if err != nil {
			return fmt.Errorf("expect.movements[%d]: %w", i, err)
		}
		if _, err := parseAsset(item.Asset); err != nil {
			return fmt.Errorf("expect.movements[%d]: %w", i, err)
		}
		from, to, err := movementEndpoints(&item)
		if err != nil {
			return err
		}
		want := item.Want()
		f := Fact{Kind: FactMovement, Index: i, TxHash: tx, Label: fmt.Sprintf("%s %s %s ×%d", item.Kind, item.Amount, item.Asset, want)}
		if !sup.has(item.Kind) {
			f.Status, f.Reason = NotApplicable, m.na(adapter.KindMovements, item.Kind)
			m.add(f)
			continue
		}
		ref := func(j int) Ref { return Ref{Kind: adapter.KindMovements, Ledger: l.LedgerSeq, Index: j, TxHash: tx} }
		var cands, matching []int
		var diffs []Diff
		for j := range l.Movements {
			o := &l.Movements[j]
			if !m.movementCandidate(&item, from, to, tx, o) {
				continue
			}
			cands = append(cands, j)
			var d []Diff
			if got, ok := amountOf(o); !ok || got != item.Amount {
				d = append(d, Diff{"amount", item.Amount, amountShown(o)})
			}
			d = append(d, compareRouting(item.Routing, o.Routing)...)
			if len(d) == 0 {
				matching = append(matching, j)
			}
			diffs = append(diffs, d...)
		}
		if item.Unverified != "" {
			for _, j := range cands {
				f.Observed = append(f.Observed, ref(j))
				m.accounted[ref(j)] = true
			}
			unverified(&f, item.Unverified)
			m.add(f)
			continue
		}
		switch {
		case want == 0:
			// M-4: no such record at all, whatever amount or routing it carries.
			f.Negative = true
			switch {
			case len(cands) > 0:
				f.Status, f.Reason = Wrong, "the reader holds a record the entry says must not exist (count 0)"
				for _, j := range cands {
					f.Observed = append(f.Observed, ref(j))
					m.forbidden[ref(j)] = "count 0 movement " + f.Label
				}
			case !m.txObserved(tx):
				f.Status, f.Reason = NotApplicable, notObserved
			default:
				f.Status = Matched
			}
			m.add(f)
			continue
		case len(matching) == want:
			// Only the matching records are this item's; another candidate (the same transfer with another
			// amount) stays unaccounted and is an extra under movements_exact.
			f.Status = Matched
			for _, j := range matching {
				f.Observed = append(f.Observed, ref(j))
				m.accounted[ref(j)] = true
			}
			m.add(f)
			continue
		case len(matching) > want:
			f.Status, f.Reason = Wrong, fmt.Sprintf("%d matching records, want %d", len(matching), want)
		case len(cands) > len(matching):
			f.Status, f.Reason, f.Diffs = Wrong, fmt.Sprintf("%d matching records, want %d; other candidates differ", len(matching), want), diffs
		default:
			f.Status, f.Reason = Missing, fmt.Sprintf("%d matching records, want %d", len(matching), want)
		}
		for _, j := range cands {
			f.Observed = append(f.Observed, ref(j))
			m.accounted[ref(j)] = true
		}
		m.add(f)
	}
	m.movementsExact = m.exp.MovementsExact && sup.provided
	return nil
}

// movementEndpoints decodes an expected movement's base from and to; nil where the item states none.
func movementEndpoints(item *manifest.Movement) (from, to *Address, err error) {
	if item.From != nil {
		a, err := decodeExpected("movement from", item.From.Address)
		if err != nil {
			return nil, nil, err
		}
		from = &a
	}
	if item.To != nil {
		a, err := decodeExpected("movement to", item.To.Address)
		if err != nil {
			return nil, nil, err
		}
		to = &a
	}
	return from, to, nil
}

// movementCandidate reports whether an observed movement is a candidate for an expected item (M-1): the same
// kind, in the item's transaction, the same asset (§6.3) and the same base from and to where the item states them.
func (m *matcher) movementCandidate(item *manifest.Movement, from, to *Address, tx string, o *adapter.ObsMovement) bool {
	if o.Kind != item.Kind || !m.inTx(o.Locator, tx) {
		return false
	}
	if same, _ := sameAsset(item.Asset, o.Asset, m.in.Passphrase); !same {
		return false
	}
	if from != nil && (o.From == nil || !identOf(o.From).endpointIs(*from)) {
		return false
	}
	return to == nil || (o.To != nil && identOf(o.To).endpointIs(*to))
}

// listedMovement reports whether an observed movement of the transaction is one the entry itself lists, with
// the forbidden address fa as a stated endpoint: an item with a count other than 0 (required, or unverified) in
// that transaction that names fa exactly as its from or to, and that the record matches in kind, asset, base
// endpoints and amount. Such a record is the entry's own statement, not a must_not_include hit for fa (§6.5 P-5,
// §6.7 M-7: a forged event's emitter may be recorded moving its own token). An item that leaves an endpoint
// unstated, or states only the base of a forbidden muxed address, never spares a record.
func (m *matcher) listedMovement(o *adapter.ObsMovement, tx string, fa Address) bool {
	for i := range m.exp.Movements {
		item := &m.exp.Movements[i]
		if item.Want() == 0 {
			continue
		}
		itx, err := m.scope(item.TxIndex)
		if err != nil || itx != tx {
			continue
		}
		from, to, err := movementEndpoints(item)
		if err != nil || !(from != nil && from.Equal(fa) || to != nil && to.Equal(fa)) {
			continue
		}
		if !m.movementCandidate(item, from, to, tx, o) {
			continue
		}
		if got, ok := amountOf(o); ok && got == item.Amount {
			return true
		}
	}
	return false
}

// amountOf returns the observed amount as an exact integer string: `amount`, or an amount_as_stored token that
// is a plain integer.
func amountOf(o *adapter.ObsMovement) (string, bool) {
	if o.Amount != "" {
		return o.Amount, true
	}
	if o.AmountAsStored != nil && plainInteger.MatchString(*o.AmountAsStored) {
		return *o.AmountAsStored, true
	}
	return "", false
}

func amountShown(o *adapter.ObsMovement) string {
	if o.Amount != "" {
		return o.Amount
	}
	if o.AmountAsStored != nil {
		return "as stored " + *o.AmountAsStored
	}
	return "(none)"
}

// compareRouting applies M-2: absent and void both mean no routing ID, and a reader reporting none passes; a
// reader that reports a value must report the expected type and value.
func compareRouting(e *manifest.Routing, o *adapter.ObsRouting) []Diff {
	if e == nil || o == nil || o.Type == "absent" || o.Type == "void" {
		return nil
	}
	got := o.Type
	if o.Value != nil {
		got += ":" + *o.Value
	}
	if e.Type == "absent" || e.Type == "void" {
		return []Diff{{"routing", "no routing ID", got}}
	}
	if o.Type != e.Type || o.Value == nil || *o.Value != e.Value {
		return []Diff{{"routing", e.Type + ":" + e.Value, got}}
	}
	return nil
}

// ---- addresses ----

type storedRef struct {
	ref      Ref
	sv       storedValue
	declared string // addresses[].type, when given
}

func (m *matcher) storedValues(tx string) []storedRef {
	l := m.ledger
	var out []storedRef
	acct := func(kind string, i int, loc adapter.Locator, a *adapter.ObsAccount) {
		if a != nil && a.AsStored != nil && m.inTx(loc, tx) {
			out = append(out, storedRef{Ref{kind, l.LedgerSeq, i, tx}, decodeStored(a.AsStored.Encoding, a.AsStored.Value, ctxAccount), ""})
		}
	}
	for i, a := range l.Addresses {
		if m.inTx(a.Locator, tx) {
			out = append(out, storedRef{Ref{adapter.KindAddresses, l.LedgerSeq, i, tx}, decodeStored(a.AsStored.Encoding, a.AsStored.Value, ctxForType(a.Type)), a.Type})
		}
	}
	for i := range l.Participants {
		acct(adapter.KindParticipants, i, l.Participants[i].Locator, &l.Participants[i].Account)
	}
	for i := range l.StateChanges {
		sc := &l.StateChanges[i]
		acct(adapter.KindStateChanges, i, sc.Locator, sc.Account)
		if sc.Signer != nil && sc.Signer.AsStored != nil && m.inTx(sc.Locator, tx) {
			out = append(out, storedRef{Ref{adapter.KindStateChanges, l.LedgerSeq, i, tx}, decodeStored(sc.Signer.AsStored.Encoding, sc.Signer.AsStored.Value, ctxSigner), ""})
		}
	}
	for i := range l.Movements {
		acct(adapter.KindMovements, i, l.Movements[i].Locator, l.Movements[i].From)
		acct(adapter.KindMovements, i, l.Movements[i].Locator, l.Movements[i].To)
	}
	return out
}

func (m *matcher) addresses() error {
	if len(m.exp.Addresses) == 0 {
		return nil
	}
	sup := m.supports[adapter.KindAddresses]
	tx, err := m.scope(nil)
	if err != nil {
		return err
	}
	var values []storedRef
	if sup.provided {
		values = m.storedValues(tx)
	}
	for i, item := range m.exp.Addresses {
		e, err := decodeExpected("address", item.Strkey)
		if err != nil {
			return err
		}
		f := Fact{Kind: FactAddress, Index: i, TxHash: tx, Label: "stores " + item.Strkey}
		if !sup.provided {
			f.Status, f.Reason = NotApplicable, sup.reason
			m.add(f)
			continue
		}
		if why, err := m.addressOutOfScope(item); err != nil {
			return err
		} else if why != "" {
			f.Status, f.Reason = NotApplicable, why
			m.add(f)
			continue
		}
		var exact, corrupt []Ref
		var why string
		for _, v := range values {
			found := false
			for _, x := range v.sv.readings {
				if x.Equal(e) {
					found = true
				}
			}
			if found {
				exact = append(exact, v.ref)
				continue
			}
			if !v.sv.carriesKey(e.Key()) {
				continue
			}
			switch {
			case len(v.sv.readings) == 0 && !v.sv.rawKey:
				corrupt, why = append(corrupt, v.ref), fmt.Sprintf("%s does not decode: %s", v.sv.shown, v.sv.err)
			case len(v.sv.readings) > 0 && v.sv.readings[0].Version == e.Version:
				corrupt, why = append(corrupt, v.ref), fmt.Sprintf("%s decodes to %s", v.sv.shown, v.sv.readings[0].String())
			case v.declared != "" && v.declared == e.Kind():
				corrupt, why = append(corrupt, v.ref), fmt.Sprintf("%s is declared %s but does not decode to the expected address", v.sv.shown, v.declared)
			}
		}
		switch {
		case len(exact) > 0:
			f.Status, f.Observed = Matched, exact
		case len(corrupt) > 0:
			f.Status, f.Reason, f.Observed = Wrong, "a stored value carries the key but is not the address: "+why, corrupt
			f.Diffs = []Diff{{"address", item.Strkey, why}}
		default:
			f.Status, f.Reason = Missing, "no stored value of the transaction decodes to this address"
		}
		m.add(f)
	}
	return nil
}

// ---- extras ----

func (m *matcher) extras() {
	tx := m.in.FocusTxHash
	l := m.ledger
	emit := func(kind string, i int, loc adapter.Locator, status func() (ExtraStatus, string)) {
		if !m.inTx(loc, tx) {
			return
		}
		r := Ref{Kind: kind, Ledger: l.LedgerSeq, Index: i, TxHash: tx}
		if why, ok := m.forbidden[r]; ok {
			m.res.Extras = append(m.res.Extras, Extra{Ref: r, Status: Forbidden, Reason: why})
			return
		}
		if m.accounted[r] {
			return
		}
		st, why := status()
		m.res.Extras = append(m.res.Extras, Extra{Ref: r, Status: st, Reason: why})
	}
	// Forbidden hits in other transactions of the ledger (an item scoped elsewhere) are still reported.
	for r, why := range m.forbidden {
		if r.TxHash != tx {
			m.res.Extras = append(m.res.Extras, Extra{Ref: r, Status: Forbidden, Reason: why})
		}
	}
	for i := range l.Participants {
		p := &l.Participants[i]
		emit(adapter.KindParticipants, i, p.Locator, func() (ExtraStatus, string) {
			if m.participantsExact {
				return ExtraInScope, "participants.exact: not in must_include (" + identOf(&p.Account).shown + ")"
			}
			return Ignored, "no exactness flag on participants"
		})
	}
	scSup := m.supports[adapter.KindStateChanges]
	for i := range l.StateChanges {
		sc := &l.StateChanges[i]
		emit(adapter.KindStateChanges, i, sc.Locator, func() (ExtraStatus, string) {
			switch {
			case slices.Contains(manifest.AmbientStateChangeKinds, sc.Kind):
				return Ignored, "ambient " + sc.Kind
			case !scSup.has(sc.Kind):
				return Ignored, "a kind the adapter does not declare"
			case m.stateChangesExact:
				return ExtraInScope, "state_changes_exact: unexpected " + sc.Kind + " for " + identOf(sc.Account).shown
			}
			return Ignored, "no state_changes_exact"
		})
	}
	mvSup := m.supports[adapter.KindMovements]
	for i := range l.Movements {
		mv := &l.Movements[i]
		emit(adapter.KindMovements, i, mv.Locator, func() (ExtraStatus, string) {
			switch {
			case slices.Contains(manifest.AmbientMovementKinds, mv.Kind):
				return Ignored, "ambient " + mv.Kind
			case !mvSup.has(mv.Kind):
				return Ignored, "a kind the adapter does not declare"
			case m.movementsExact:
				return ExtraInScope, "movements_exact: unexpected " + mv.Kind + " of " + mv.Asset
			}
			return Ignored, "no movements_exact"
		})
	}
	for i := range l.Addresses {
		r := Ref{Kind: adapter.KindAddresses, Ledger: l.LedgerSeq, Index: i, TxHash: tx}
		if why, ok := m.forbidden[r]; ok && m.inTx(l.Addresses[i].Locator, tx) {
			m.res.Extras = append(m.res.Extras, Extra{Ref: r, Status: Forbidden, Reason: why})
		}
	}
	sort.SliceStable(m.res.Extras, func(a, b int) bool {
		x, y := m.res.Extras[a], m.res.Extras[b]
		if x.Kind != y.Kind {
			return x.Kind < y.Kind
		}
		if x.TxHash != y.TxHash {
			return x.TxHash < y.TxHash
		}
		return x.Index < y.Index
	})
}

// ---- helpers ----

func short(h string) string {
	if len(h) > 12 {
		return h[:8] + "…"
	}
	return h
}

func show(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}

// jsonEqual compares decoded JSON values; numbers (json.Number, or Go numbers) compare by exact value, and a
// number never equals a string.
func jsonEqual(a, b any) bool {
	if ra, ok := numRat(a); ok {
		rb, ok := numRat(b)
		return ok && ra.Cmp(rb) == 0
	}
	switch av := a.(type) {
	case map[string]any:
		bv, ok := b.(map[string]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for k, x := range av {
			if y, ok := bv[k]; !ok || !jsonEqual(x, y) {
				return false
			}
		}
		return true
	case []any:
		bv, ok := b.([]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for i := range av {
			if !jsonEqual(av[i], bv[i]) {
				return false
			}
		}
		return true
	case string, bool, nil:
		return a == b
	}
	return false
}

func numRat(v any) (*big.Rat, bool) {
	var s string
	switch n := v.(type) {
	case json.Number:
		s = string(n)
	case int:
		s = fmt.Sprint(n)
	case int64:
		s = fmt.Sprint(n)
	case float64:
		r := new(big.Rat)
		if r.SetFloat64(n) == nil {
			return nil, false
		}
		return r, true
	default:
		return nil, false
	}
	r, ok := new(big.Rat).SetString(s)
	return r, ok
}

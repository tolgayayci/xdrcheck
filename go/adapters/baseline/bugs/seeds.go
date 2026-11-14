package bugs

// The defects. Each one is written the way the real bug it imitates is written — a wrong assumption in one
// place — and changes nothing else about the baseline's output.

import (
	"encoding/json"
	"fmt"
	"math/big"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/tolgayayci/xdrcheck/go/adapterkit"
	"github.com/tolgayayci/xdrcheck/go/adapters/baseline/indexer"
)

var keep = indexer.Outcome{}

// ---- stored values ----

// truncateAddresses: every address column is 56 characters wide, the length of a G… address. Signed-payload
// signers (P…, up to 165), muxed accounts (M…, 69) and claimable balances (B…, 58) lose their tails.
func truncateAddresses(l *ledger) indexer.Outcome {
	cut := func(s *string) {
		if len(*s) > 56 {
			*s = (*s)[:56]
		}
	}
	l.accounts(func(a *adapterkit.ObsAccount) {
		cut(&a.Address)
		cut(&a.OnChainForm)
		if a.AsStored != nil {
			cut(&a.AsStored.Value)
		}
	})
	f := l.facts()
	for i := range f.StateChanges {
		if s := f.StateChanges[i].Signer; s != nil {
			cut(&s.Key)
			if s.AsStored != nil {
				cut(&s.AsStored.Value)
			}
		}
	}
	for i := range f.Addresses {
		cut(&f.Addresses[i].AsStored.Value)
	}
	return keep
}

// dropSignerPayload: a signer is stored as its 32-byte ed25519 key, so a signed-payload signer keeps the key and
// loses the payload (the stored value is the key's G… form).
func dropSignerPayload(l *ledger) indexer.Outcome {
	f := l.facts()
	replaced := map[string]string{}
	for i := range f.StateChanges {
		c := &f.StateChanges[i]
		if c.Signer == nil || c.Signer.Type != "ed25519_signed_payload" {
			continue
		}
		key, _ := c.Detail["signer_ed25519_key"].(string)
		if key == "" {
			continue
		}
		replaced[c.Signer.Key] = key
		c.Signer.Key, c.Signer.PayloadHex = key, ""
		c.Signer.AsStored = &adapterkit.Stored{Encoding: "strkey_text", Value: key}
		delete(c.Detail, "payload_bytes")
	}
	for i := range f.Addresses {
		if k, ok := replaced[f.Addresses[i].AsStored.Value]; ok {
			f.Addresses[i].AsStored.Value, f.Addresses[i].Type = k, strkeyType(k)
		}
	}
	return keep
}

// muxedOnlyIdentity: a muxed participant or endpoint is stored only as its M… (or W…) form; the base account
// is not stored anywhere for it.
func muxedOnlyIdentity(l *ledger) indexer.Outcome {
	l.accounts(func(a *adapterkit.ObsAccount) {
		if a.OnChainForm == "" {
			return
		}
		m := a.OnChainForm
		for i := range l.facts().Addresses {
			if x := &l.facts().Addresses[i]; x.AsStored.Value == a.Address && x.Field == "participants.address" {
				x.AsStored.Value, x.Type = m, strkeyType(m)
			}
		}
		a.Address, a.MuxedID = m, ""
		a.AsStored = &adapterkit.Stored{Encoding: "strkey_text", Value: m}
	})
	return keep
}

// floatAmounts: amounts are parsed into a float64 and printed back, so any amount above 2^53 stroops is
// rounded. Movement amounts and the amount-valued details (balances, limits, deltas) all go through it.
func floatAmounts(l *ledger) indexer.Outcome {
	viaFloat := func(s string) string {
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return s
		}
		return strconv.FormatFloat(f, 'f', -1, 64)
	}
	f := l.facts()
	for i := range f.Movements {
		f.Movements[i].Amount = viaFloat(f.Movements[i].Amount)
	}
	amountKeys := []string{"amount", "balance", "balance_after", "balance_transferred", "delta", "limit", "limit_before",
		"starting_balance", "reserve_a", "reserve_b", "total_shares"}
	for i := range f.StateChanges {
		for k, v := range f.StateChanges[i].Detail {
			if s, ok := v.(string); ok && slices.Contains(amountKeys, k) {
				f.StateChanges[i].Detail[k] = viaFloat(s)
			}
		}
	}
	return keep
}

// ---- ledgers and transactions dropped ----

// dropLedgerSilently: a ledger with an empty transaction set, or at an odd protocol, is skipped; the cursor
// moves past it as if it had been stored.
func dropLedgerSilently(l *ledger) indexer.Outcome {
	if len(l.facts().Transactions) == 0 || l.doc.ProtocolVersion%2 == 1 {
		return indexer.Outcome{Skip: true}
	}
	return keep
}

// dropContractTrustlines: trustline history comes from ChangeTrust operations only, so a trustline created,
// removed or re-limited by anything else (a Stellar Asset Contract call) has no history row.
func dropContractTrustlines(l *ledger) indexer.Outcome {
	f := l.facts()
	f.StateChanges = slices.DeleteFunc(f.StateChanges, func(c adapterkit.ObsStateChange) bool {
		switch c.Kind {
		case "trustline_created", "trustline_removed", "trustline_limit_changed":
			return c.Cause != "change_trust"
		}
		return false
	})
	return keep
}

// ---- the control ----

// extraFeeRows stores more rows than the baseline, all of them correct: the fee charged as a balance change of
// the fee payer, and the authorisation a trustline is created with as its own trustline_flags_changed (the
// adapter declares initial_authorization_separate). Neither may be scored as an extra.
func extraFeeRows(l *ledger) indexer.Outcome {
	f := l.facts()
	var add []adapterkit.ObsStateChange
	for _, m := range f.Movements {
		if m.Kind != "fee" || m.From == nil {
			continue
		}
		loc := adapterkit.Locator{TxHash: m.TxHash, TxIndex: m.TxIndex}
		add = append(add, adapterkit.ObsStateChange{Locator: loc, Kind: "balance_changed", Account: account(m.From.Address), Asset: "native",
			Detail: map[string]any{"delta": "-" + m.Amount, "reason": "fee"}})
	}
	for _, c := range f.StateChanges {
		if c.Kind != "trustline_created" {
			continue
		}
		det := map[string]any{"initial": true}
		for _, k := range []string{"flags", "authorized", "authorized_to_maintain_liabilities", "clawback_enabled"} {
			if v, ok := c.Detail[k]; ok {
				det[k] = v
			}
		}
		add = append(add, adapterkit.ObsStateChange{Locator: c.Locator, Kind: "trustline_flags_changed", Account: account(c.Account.Address),
			Asset: c.Asset, Detail: det, Cause: c.Cause})
	}
	f.StateChanges = append(f.StateChanges, add...)
	return keep
}

// ---- stops ----

// panicOnSignedPayload reads a signer key's ed25519 arm without checking the union's type, so a signed-payload
// signer dereferences nil and the process dies of a runtime fault.
func panicOnSignedPayload(l *ledger) indexer.Outcome {
	if _, ok := l.signedPayloadSigner(); ok {
		k := xdr.SignerKey{Type: xdr.SignerKeyTypeSignerKeyTypeEd25519SignedPayload}
		keyByte = k.Ed25519[0] // k.Ed25519 is nil for this arm
	}
	return keep
}

var keyByte byte

// loopOnFailedInnerFeeBump waits for an inner result that a fee-bump whose inner transaction failed never has,
// and spins until it is killed.
func loopOnFailedInnerFeeBump(l *ledger) indexer.Outcome {
	for _, t := range l.facts().Transactions {
		if t.ResultCode == "tx_fee_bump_inner_failed" {
			for {
				time.Sleep(10 * time.Millisecond)
			}
		}
	}
	return keep
}

// exitOnSignedPayload treats a signer longer than its column as a permanent error: it exits non-zero before
// writing anything for the ledger.
func exitOnSignedPayload(l *ledger) indexer.Outcome {
	if key, ok := l.signedPayloadSigner(); ok {
		return indexer.Outcome{Skip: true, Stop: &indexer.ExitRecord{Status: "error", Phase: "persist",
			Message: fmt.Sprintf("ledger %d: permanent error: signer %s does not fit the 56-character signer column", l.doc.LedgerSeq, key)}}
	}
	return keep
}

// haltAfterPartialWrite writes the first half of a multi-transaction ledger's records, then fails.
func haltAfterPartialWrite(l *ledger) indexer.Outcome {
	f := l.facts()
	n := len(f.Transactions)
	if n < 2 {
		return keep
	}
	half := n / 2
	in := func(loc adapterkit.Locator) bool { return loc.TxIndex != nil && *loc.TxIndex < half }
	f.Transactions = f.Transactions[:half]
	f.Participants = slices.DeleteFunc(f.Participants, func(x adapterkit.ObsParticipant) bool { return !in(x.Locator) })
	f.StateChanges = slices.DeleteFunc(f.StateChanges, func(x adapterkit.ObsStateChange) bool { return !in(x.Locator) })
	f.Movements = slices.DeleteFunc(f.Movements, func(x adapterkit.ObsMovement) bool { return !in(x.Locator) })
	f.Addresses = slices.DeleteFunc(f.Addresses, func(x adapterkit.ObsAddress) bool { return !in(x.Locator) })
	return indexer.Outcome{Stop: &indexer.ExitRecord{Status: "error", Phase: "persist",
		Message: fmt.Sprintf("ledger %d: write failed after %d of %d transactions", l.doc.LedgerSeq, half, n)}}
}

// fakeRefusal claims its protocol gate on a Protocol 28 ledger, which its declared envelope (maximum 30)
// accepts.
func fakeRefusal(l *ledger) indexer.Outcome {
	if p := l.lcm.ProtocolVersion(); p == 28 {
		return indexer.Outcome{Skip: true, Stop: &indexer.ExitRecord{Status: "refused", Phase: "decode", Gate: "max_protocol", Observed: int64(p),
			Message: fmt.Sprintf("refusing ledger %d: protocol %d is not supported", l.doc.LedgerSeq, p)}}
	}
	return keep
}

// dirtyRefusal checks its declared protocol gate (28) only after the ledger's records are written.
func dirtyRefusal(l *ledger) indexer.Outcome {
	if p := l.lcm.ProtocolVersion(); p > 28 {
		return indexer.Outcome{Stop: &indexer.ExitRecord{Status: "refused", Phase: "decode", Gate: "max_protocol", Observed: int64(p),
			Message: fmt.Sprintf("refusing ledger %d: protocol %d is newer than the maximum supported protocol 28", l.doc.LedgerSeq, p)}}
	}
	return keep
}

// headerProtocolParser chooses the parser by the header's ledgerVersion. The Protocol 30 parser expects a
// millisecond close time (the *_MS StellarValue arms), which the ledger carrying the Protocol 30 upgrade does
// not have: it was agreed under Protocol 29.
func headerProtocolParser(l *ledger) indexer.Outcome {
	h := l.lcm.LedgerHeaderHistoryEntry().Header
	if h.LedgerVersion < 30 {
		return keep
	}
	switch h.ScpValue.Ext.V {
	case xdr.StellarValueTypeStellarValueSignedMs, xdr.StellarValueTypeStellarValueEmptyTxSetMs:
		return keep
	}
	return indexer.Outcome{Skip: true, Stop: &indexer.ExitRecord{Status: "error", Phase: "decode",
		Message: fmt.Sprintf("ledger %d: protocol %d header parser: StellarValue %s has no closeTimeMs", l.doc.LedgerSeq, h.LedgerVersion, h.ScpValue.Ext.V)}}
}

// memoryHog keeps every ledger it has read — decoded, encoded, as stored, and in a fixed 4 MiB page of its own
// in-memory cache — for the life of the process. The page makes growth per ledger large and fixed, so the
// memory cap is crossed early in a stream and at the same point every run, long before the baseline's own needs.
type memoryHog struct{ kept []any }

const hogPage = 4 << 20

func (h *memoryHog) Ledger(lcm xdr.LedgerCloseMeta, doc *indexer.Doc, _ string) indexer.Outcome {
	raw, _ := lcm.MarshalBinary()
	stored, _ := json.Marshal(doc)
	page := make([]byte, hogPage)
	for i := 0; i < len(page); i += 4096 {
		page[i] = byte(i) // touch every page so it is resident
	}
	copy(page, raw)
	h.kept = append(h.kept, lcm, raw, stored, page)
	return keep
}

// ---- identities taken from claims ----

// fabricateMuxedFromMemo turns a transaction's memo into a muxed destination: a text memo's digits become the
// muxed ID of the destination (0 when there are none), and a hash memo's 32 bytes become the key of an M…
// address with ID 0. Nothing in the ledger says either account is muxed.
func fabricateMuxedFromMemo(l *ledger) indexer.Outcome {
	f := l.facts()
	for _, tx := range l.transactions() {
		memo := tx.Envelope.Memo()
		hash := tx.Hash.HexString()
		var form func(to string) (string, uint64)
		switch {
		case memo.Type == xdr.MemoTypeMemoText && memo.Text != nil:
			id := digits(*memo.Text)
			form = func(to string) (string, uint64) { return muxedForm(to, id), id }
		case memo.Type == xdr.MemoTypeMemoHash && memo.Hash != nil:
			key, _ := strkey.Encode(strkey.VersionByteAccountID, memo.Hash[:])
			m := muxedForm(key, 0)
			form = func(string) (string, uint64) { return m, 0 }
		default:
			continue
		}
		for i := range f.Movements {
			mv := &f.Movements[i]
			if mv.TxHash != hash || mv.To == nil || (mv.Kind != "transfer" && mv.Kind != "mint") {
				continue
			}
			m, id := form(mv.To.Address)
			if m == "" {
				continue
			}
			s := strconv.FormatUint(id, 10)
			mv.To.MuxedID, mv.To.OnChainForm = s, m
			mv.Routing = &adapterkit.ObsRouting{Type: "u64", Value: &s}
			l.addAddress(mv.Locator, "movements.endpoint.on_chain_form", m)
		}
	}
	return keep
}

func digits(s string) uint64 {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	n, _ := strconv.ParseUint(b.String(), 10, 64)
	return n
}

// participantsFromAuth makes every address named in a transaction's Soroban authorisation entries a
// participant: the credentials' addresses and every contract in the authorised invocation trees, whether or not
// the host used the entry.
func participantsFromAuth(l *ledger) indexer.Outcome {
	for _, tx := range l.transactions() {
		loc := txLocator(tx)
		for _, op := range tx.Envelope.Operations() {
			if op.Body.Type != xdr.OperationTypeInvokeHostFunction {
				continue
			}
			for _, a := range op.Body.InvokeHostFunctionOp.Auth {
				for _, addr := range authAddresses(a) {
					l.addParticipant(loc, addr, "authorizer")
				}
			}
		}
	}
	return keep
}

func authAddresses(a xdr.SorobanAuthorizationEntry) []string {
	var out []string
	c := a.Credentials
	for _, ac := range []*xdr.SorobanAddressCredentials{c.Address, c.AddressV2} {
		if ac != nil {
			out = append(out, baseAddress(ac.Address))
		}
	}
	if d := c.AddressWithDelegates; d != nil {
		out = append(out, baseAddress(d.AddressCredentials.Address))
		stack := append([]xdr.SorobanDelegateSignature{}, d.Delegates...)
		for len(stack) > 0 {
			s := stack[len(stack)-1]
			stack = append(stack[:len(stack)-1], s.NestedDelegates...) //xdrlint:ignore XDR202 seeded defect participants-from-auth; the walk runs only in the harness self-test
			out = append(out, baseAddress(s.Address))
		}
	}
	stack := []xdr.SorobanAuthorizedInvocation{a.RootInvocation}
	for len(stack) > 0 {
		inv := stack[len(stack)-1]
		stack = append(stack[:len(stack)-1], inv.SubInvocations...) //xdrlint:ignore XDR202 seeded defect participants-from-auth; the walk runs only in the harness self-test
		if fn := inv.Function.ContractFn; fn != nil {
			out = append(out, baseAddress(fn.ContractAddress))
		}
	}
	return out
}

// participantsFromEnvelope makes the operation destinations of a failed transaction participants, although
// nothing of theirs changed.
func participantsFromEnvelope(l *ledger) indexer.Outcome {
	for _, tx := range l.transactions() {
		if l.successful(tx.Hash.HexString()) {
			continue
		}
		loc := txLocator(tx)
		for _, op := range tx.Envelope.Operations() {
			for _, d := range destinations(op) {
				l.addParticipant(loc, d, "destination")
			}
		}
	}
	return keep
}

func destinations(op xdr.Operation) []string {
	b := op.Body
	muxed := func(m xdr.MuxedAccount) string { return m.ToAccountId().Address() }
	switch b.Type {
	case xdr.OperationTypeCreateAccount:
		return []string{b.CreateAccountOp.Destination.Address()}
	case xdr.OperationTypePayment:
		return []string{muxed(b.PaymentOp.Destination)}
	case xdr.OperationTypePathPaymentStrictReceive:
		return []string{muxed(b.PathPaymentStrictReceiveOp.Destination)}
	case xdr.OperationTypePathPaymentStrictSend:
		return []string{muxed(b.PathPaymentStrictSendOp.Destination)}
	case xdr.OperationTypeAccountMerge:
		return []string{muxed(*b.Destination)}
	case xdr.OperationTypeBeginSponsoringFutureReserves:
		return []string{b.BeginSponsoringFutureReservesOp.SponsoredId.Address()}
	case xdr.OperationTypeCreateClaimableBalance:
		var out []string
		for _, c := range b.CreateClaimableBalanceOp.Claimants {
			if c.V0 != nil {
				out = append(out, c.V0.Destination.Address())
			}
		}
		return out
	}
	return nil
}

// ---- events trusted beyond their emitter ----

type tokenEvent struct {
	kind, from, to, asset, amount string
}

// parseTokenEvent reads an event shaped like a token transfer, mint, burn or clawback whose last topic names an
// asset (SEP-11 text).
func parseTokenEvent(e xdr.ContractEvent) (tokenEvent, bool) {
	if e.Type != xdr.ContractEventTypeContract || e.Body.V0 == nil || len(e.Body.V0.Topics) < 2 {
		return tokenEvent{}, false
	}
	topics := e.Body.V0.Topics
	var t tokenEvent
	if topics[0].Type != xdr.ScValTypeScvSymbol || topics[0].Sym == nil {
		return t, false
	}
	t.kind = string(*topics[0].Sym)
	last := topics[len(topics)-1]
	if last.Type != xdr.ScValTypeScvString || last.Str == nil {
		return t, false
	}
	t.asset = string(*last.Str)
	var addrs []string
	for _, v := range topics[1:] {
		if v.Type == xdr.ScValTypeScvAddress && v.Address != nil {
			addrs = append(addrs, baseAddress(*v.Address))
		}
	}
	d := e.Body.V0.Data
	switch {
	case d.Type == xdr.ScValTypeScvI128:
		t.amount = i128(d)
	case d.Type == xdr.ScValTypeScvMap && d.Map != nil && *d.Map != nil:
		for _, en := range **d.Map {
			if en.Key.Type == xdr.ScValTypeScvSymbol && en.Key.Sym != nil && *en.Key.Sym == "amount" && en.Val.Type == xdr.ScValTypeScvI128 {
				t.amount = i128(en.Val)
			}
		}
	}
	switch {
	case t.amount == "":
		return t, false
	case t.kind == "transfer" && len(addrs) >= 2:
		t.from, t.to = addrs[0], addrs[1]
	case t.kind == "mint" && len(addrs) > 0:
		t.to = addrs[len(addrs)-1]
	case (t.kind == "burn" || t.kind == "clawback") && len(addrs) > 0:
		t.from = addrs[len(addrs)-1]
	default:
		return t, false
	}
	return t, true
}

func i128(v xdr.ScVal) string {
	n := new(big.Int).Lsh(big.NewInt(int64(v.I128.Hi)), 64)
	return n.Add(n, new(big.Int).SetUint64(uint64(v.I128.Lo))).String()
}

func parseAsset(s string) (xdr.Asset, bool) {
	if s == "native" {
		return xdr.MustNewNativeAsset(), true
	}
	code, issuer, ok := strings.Cut(s, ":")
	if !ok {
		return xdr.Asset{}, false
	}
	a, err := xdr.NewCreditAsset(code, issuer)
	return a, err == nil
}

// creditFromForgedEvent believes the asset an event names: a transfer-shaped event from a contract that is not
// that asset's Stellar Asset Contract is recorded as a movement of the classic asset, and its recipient becomes
// a participant. (The baseline already records the events whose emitter is the asset's contract.)
func creditFromForgedEvent(l *ledger) indexer.Outcome {
	for _, tx := range l.transactions() {
		hash := tx.Hash.HexString()
		if !l.successful(hash) {
			continue
		}
		for op, events := range opEvents(tx.UnsafeMeta) {
			for _, e := range events {
				t, ok := parseTokenEvent(e)
				if !ok || e.ContractId == nil {
					continue
				}
				asset, ok := parseAsset(t.asset)
				if !ok {
					continue
				}
				if id, err := asset.ContractID(l.passphrase); err == nil && id == [32]byte(*e.ContractId) {
					continue
				}
				loc := txLocator(tx)
				opi := op
				loc.OpIndex = &opi
				mv := adapterkit.ObsMovement{Locator: loc, Kind: t.kind, Asset: asset.StringCanonical(), Amount: t.amount, //xdrlint:ignore XDR103 seeded defect credit-from-forged-event: this indexer deliberately believes the asset a forged event names
					Routing: &adapterkit.ObsRouting{Type: "absent"}}
				if t.from != "" {
					mv.From = account(t.from)
				}
				if t.to != "" {
					mv.To = account(t.to)
				}
				l.facts().Movements = append(l.facts().Movements, mv)
				for _, a := range []string{t.from, t.to} {
					l.addParticipant(txLocator(tx), a, "counterparty")
				}
			}
		}
	}
	return keep
}

// doubleCountTransfer records each custom-token transfer twice: once as the token event and once more from the
// raw contract event the token event was read from.
func doubleCountTransfer(l *ledger) indexer.Outcome {
	f := l.facts()
	var dup []adapterkit.ObsMovement
	for _, m := range f.Movements {
		if m.Kind == "transfer" && strings.HasPrefix(m.Asset, "C") {
			dup = append(dup, m)
		}
	}
	f.Movements = append(f.Movements, dup...)
	return keep
}

// voidMeansZero reads a Void to_muxed_id as muxed ID 0: the destination becomes the muxed form with ID 0.
func voidMeansZero(l *ledger) indexer.Outcome {
	f := l.facts()
	for i := range f.Movements {
		m := &f.Movements[i]
		if m.Routing == nil || m.Routing.Type != "void" || m.To == nil {
			continue
		}
		zero := "0"
		m.Routing = &adapterkit.ObsRouting{Type: "u64", Value: &zero}
		if form := muxedForm(m.To.Address, 0); form != "" {
			m.To.MuxedID, m.To.OnChainForm = zero, form
			l.addAddress(m.Locator, "movements.endpoint.on_chain_form", form)
		}
	}
	return keep
}

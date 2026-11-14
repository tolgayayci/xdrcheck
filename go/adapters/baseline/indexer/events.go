package indexer

import (
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/tolgayayci/xdrcheck/go/adapterkit"
)

// ---- step 4: token-shaped events ----

type tokenEvent struct {
	kind    string
	from    string
	to      string
	sep11   string
	amount  string
	routing adapterkit.ObsRouting
}

// parseTokenEvent reads a contract event shaped like a token transfer, mint, burn or clawback (CAP-0067), or
// returns false.
func parseTokenEvent(e xdr.ContractEvent) (tokenEvent, bool) {
	if e.Type != xdr.ContractEventTypeContract || e.Body.V0 == nil {
		return tokenEvent{}, false
	}
	topics := e.Body.V0.Topics
	if len(topics) == 0 {
		return tokenEvent{}, false
	}
	kind, _ := sym(topics[0])
	switch kind {
	case "transfer", "mint", "burn", "clawback":
	default:
		return tokenEvent{}, false
	}
	var addrs []string
	for _, t := range topics[1:] {
		if t.Type == xdr.ScValTypeScvAddress && t.Address != nil {
			addrs = append(addrs, baseAddress(*t.Address))
		}
	}
	ev := tokenEvent{kind: kind, routing: adapterkit.ObsRouting{Type: "absent"}}
	if last := topics[len(topics)-1]; len(topics) > 1 && last.Type == xdr.ScValTypeScvString && last.Str != nil {
		ev.sep11 = string(*last.Str)
	}
	data := e.Body.V0.Data
	switch {
	case data.Type == xdr.ScValTypeScvI128:
		n, _ := i128(data)
		ev.amount = n.String()
	case data.Type == xdr.ScValTypeScvMap && data.Map != nil && *data.Map != nil:
		for _, entry := range **data.Map {
			name, _ := sym(entry.Key)
			switch name {
			case "amount":
				if n, ok := i128(entry.Val); ok {
					ev.amount = n.String()
				}
			case "to_muxed_id":
				v := entry.Val
				switch v.Type {
				case xdr.ScValTypeScvVoid:
					ev.routing = adapterkit.ObsRouting{Type: "void"}
				case xdr.ScValTypeScvU64:
					s := strconv.FormatUint(uint64(*v.U64), 10)
					ev.routing = adapterkit.ObsRouting{Type: "u64", Value: &s}
				case xdr.ScValTypeScvString:
					s := string(*v.Str)
					ev.routing = adapterkit.ObsRouting{Type: "text", Value: &s} //xdrlint:ignore XDR103 observation JSON for the harness: encoding/json writes invalid UTF-8 as U+FFFD and NUL as \u0000, the line stays valid; the protocol carries text routing as a JSON string
				case xdr.ScValTypeScvBytes:
					s := hex.EncodeToString(*v.Bytes)
					ev.routing = adapterkit.ObsRouting{Type: "bytes", Value: &s}
				default:
					return tokenEvent{}, false
				}
			}
		}
		if ev.amount == "" {
			return tokenEvent{}, false
		}
	default:
		return tokenEvent{}, false
	}
	switch {
	case kind == "transfer" && len(addrs) >= 2:
		ev.from, ev.to = addrs[0], addrs[1]
	case kind == "mint" && len(addrs) > 0:
		ev.to = addrs[len(addrs)-1]
	case (kind == "burn" || kind == "clawback") && len(addrs) > 0:
		ev.from = addrs[len(addrs)-1]
	default:
		return tokenEvent{}, false
	}
	return ev, true
}

// changedAssets is native plus every classic asset whose trustline this transaction touched: the assets whose
// Stellar Asset Contract may have emitted its events.
func (b *txBuilder) changedAssets() []xdr.Asset {
	out := []xdr.Asset{xdr.MustNewNativeAsset()}
	lists := append([]xdr.LedgerEntryChanges{}, b.parts.before...)
	if b.parts.after != nil {
		lists = append(lists, *b.parts.after)
	}
	lists = append(append(lists, b.parts.ops...), b.tx.FeeChanges)
	for _, l := range lists {
		for _, c := range l {
			var e *xdr.LedgerEntry
			switch c.Type {
			case xdr.LedgerEntryChangeTypeLedgerEntryState:
				e = c.State
			case xdr.LedgerEntryChangeTypeLedgerEntryCreated:
				e = c.Created
			case xdr.LedgerEntryChangeTypeLedgerEntryUpdated:
				e = c.Updated
			case xdr.LedgerEntryChangeTypeLedgerEntryRestored:
				e = c.Restored
			}
			if e == nil || e.Data.Type != xdr.LedgerEntryTypeTrustline {
				continue
			}
			if _, a := trustlineAsset(e.Data.TrustLine.Asset); a != nil && !containsAsset(out, *a) {
				out = append(out, *a)
			}
		}
	}
	return out
}

func containsAsset(list []xdr.Asset, a xdr.Asset) bool {
	for _, x := range list {
		if x.Equals(a) {
			return true
		}
	}
	return false
}

// eventsStep turns token-shaped events into movements, keyed on the emitting contract (rule M-7). An event is a
// movement of a classic asset only when its emitter is that asset's Stellar Asset Contract under this network;
// the asset named in its topics is used only to test that derivation, never trusted on its own. An event from any
// other contract that names a classic asset is a forged claim and records nothing; one that names no classic
// asset is that contract's own token movement, and the addresses it names are its counterparties.
func (b *txBuilder) eventsStep() {
	candidates := b.changedAssets()
	for op, events := range b.parts.opEvents {
		for _, e := range events {
			b.eventMovement(op, e, candidates)
		}
	}
}

func (b *txBuilder) eventMovement(op int, e xdr.ContractEvent, candidates []xdr.Asset) {
	t, ok := parseTokenEvent(e)
	if !ok || e.ContractId == nil {
		return
	}
	emitter := [32]byte(*e.ContractId)
	pool := append([]xdr.Asset{}, candidates...)
	named, namedOK := xdr.Asset{}, false
	if t.sep11 != "" {
		named, namedOK = parseAsset(t.sep11)
		if namedOK && !containsAsset(pool, named) {
			pool = append(pool, named)
		}
	}
	var sac *xdr.Asset
	for i := range pool {
		if id, err := pool[i].ContractID(b.passphrase); err == nil && id == emitter {
			sac = &pool[i]
			break
		}
	}
	routing := t.routing
	from, to := b.endpoint(t.from, nil), b.endpoint(t.to, &routing)
	opi := op
	switch {
	case sac != nil:
		b.movement(t.kind, &opi, assetString(*sac), t.amount, from, to, &routing)
	case namedOK:
		// A forged asset claim: not the named asset's contract. Nothing is recorded, and the address it names
		// is not a participant.
	default:
		b.movement(t.kind, &opi, contractStrkey(emitter), t.amount, from, to, &routing)
		for _, a := range []string{t.from, t.to} {
			if a != "" {
				b.role(a, "counterparty")
			}
		}
	}
}

// endpoint is a movement endpoint as stored: the base address, and for a u64 routing ID the muxed ID and the
// M…/W… form the ledger itself carries.
func (b *txBuilder) endpoint(address string, routing *adapterkit.ObsRouting) *adapterkit.ObsAccount {
	if address == "" {
		return nil
	}
	a := account(address)
	if routing != nil && routing.Type == "u64" && routing.Value != nil {
		if id, err := strconv.ParseUint(*routing.Value, 10, 64); err == nil {
			a.MuxedID = *routing.Value
			a.OnChainForm = muxedForm(address, id)
		}
	}
	return a
}

// feeEventsPresent reports whether the transaction carries fee events from the native asset contract: the node
// emitted classic events, so classic movements come from events rather than balance deltas.
func (b *txBuilder) feeEventsPresent() bool {
	native, err := xdr.MustNewNativeAsset().ContractID(b.passphrase)
	if err != nil {
		return false
	}
	for _, e := range b.parts.txEvents {
		if e.Body.V0 == nil || len(e.Body.V0.Topics) == 0 {
			continue
		}
		if s, _ := sym(e.Body.V0.Topics[0]); s == "fee" && e.ContractId != nil && [32]byte(*e.ContractId) == native {
			return true
		}
	}
	return false
}

// balanceDeltaStep derives classic movements from balance deltas when the ledger carries no classic events: per
// asset, one debit and one equal credit within an operation is a transfer.
func (b *txBuilder) balanceDeltaStep() {
	for op, changes := range b.parts.ops {
		if op < len(b.ops) && b.ops[op].Body.Type == xdr.OperationTypeInvokeHostFunction {
			continue
		}
		type delta struct {
			who string
			n   int64
		}
		deltas := map[string][]delta{}
		var assets []string
		add := func(asset, who string, n int64) {
			if _, ok := deltas[asset]; !ok {
				assets = append(assets, asset)
			}
			deltas[asset] = append(deltas[asset], delta{who, n})
		}
		for _, t := range transitions(changes) {
			if t.kind != "updated" || t.pre == nil || t.pre.Data.Type != t.post.Data.Type {
				continue
			}
			switch t.post.Data.Type {
			case xdr.LedgerEntryTypeAccount:
				a0, a1 := t.pre.Data.Account, t.post.Data.Account
				if a0.Balance != a1.Balance {
					add("native", accountStrkey(a1.AccountId), int64(a1.Balance-a0.Balance))
				}
			case xdr.LedgerEntryTypeTrustline:
				t0, t1 := t.pre.Data.TrustLine, t.post.Data.TrustLine
				if t0.Balance != t1.Balance {
					asset, _ := trustlineAsset(t1.Asset)
					add(asset, accountStrkey(t1.AccountId), int64(t1.Balance-t0.Balance))
				}
			}
		}
		sort.Strings(assets)
		for _, asset := range assets {
			var neg, pos []delta
			for _, d := range deltas[asset] {
				if d.n < 0 {
					neg = append(neg, d)
				} else if d.n > 0 {
					pos = append(pos, d)
				}
			}
			if len(neg) == 1 && len(pos) == 1 && -neg[0].n == pos[0].n {
				opi := op
				b.movement("transfer", &opi, asset, strconv.FormatInt(pos[0].n, 10), account(neg[0].who), account(pos[0].who), nil)
			}
		}
	}
}

// counterpartyStep gives an affected account named as a claimant of a balance the transaction created or claimed
// the role claimant, and an affected address with no specific role the role counterparty.
func (b *txBuilder) counterpartyStep() {
	for _, p := range b.participants {
		if b.claimants[p.address] {
			p.roles["claimant"] = true
		}
		if len(p.roles) == 0 {
			p.roles["counterparty"] = true
		}
	}
}

// aliasStep attaches muxed aliases to participants the meta already established — never adds a participant:
// MuxedAccounts in the envelope (transaction and fee sources, operation sources, payment and merge destinations,
// clawback sources), then u64 routing IDs of the transaction's own token events.
func (b *txBuilder) aliasStep() {
	env := b.tx.Envelope
	all := []xdr.MuxedAccount{env.SourceAccount()}
	if env.IsFeeBump() {
		all = append(all, env.FeeBumpAccount())
	}
	for _, op := range b.ops {
		if op.SourceAccount != nil {
			all = append(all, *op.SourceAccount)
		}
		switch body := op.Body; body.Type {
		case xdr.OperationTypePayment:
			all = append(all, body.PaymentOp.Destination)
		case xdr.OperationTypePathPaymentStrictReceive:
			all = append(all, body.PathPaymentStrictReceiveOp.Destination)
		case xdr.OperationTypePathPaymentStrictSend:
			all = append(all, body.PathPaymentStrictSendOp.Destination)
		case xdr.OperationTypeAccountMerge:
			all = append(all, *body.Destination)
		case xdr.OperationTypeClawback:
			all = append(all, body.ClawbackOp.From)
		}
	}
	attach := func(base, id, form string) {
		for _, p := range b.participants {
			if p.address == base && p.muxedID == "" {
				p.muxedID, p.form = id, form
			}
		}
	}
	for _, m := range all {
		if base, id := muxedBase(m); id != nil {
			form, _ := m.GetAddress()
			attach(base, strconv.FormatUint(*id, 10), form)
		}
	}
	for _, mv := range b.movements {
		if mv.To != nil && mv.To.MuxedID != "" {
			attach(mv.To.Address, mv.To.MuxedID, mv.To.OnChainForm)
		}
	}
}

// ---- records ----

// records appends this transaction's facts to the ledger's: one record per fact, plus every address the records
// store, as stored.
func (b *txBuilder) records(l *adapterkit.Ledger) {
	type stored struct{ field, value string }
	var addrs []stored
	seen := map[stored]bool{}
	keep := func(field, value string) {
		s := stored{field, value}
		if value != "" && !seen[s] {
			seen[s] = true
			addrs = append(addrs, s)
		}
	}
	for _, p := range b.participants {
		a := account(p.address)
		a.MuxedID, a.OnChainForm = p.muxedID, p.form
		for r := range p.roles {
			a.Roles = append(a.Roles, r)
		}
		sort.Strings(a.Roles)
		l.Participants = append(l.Participants, adapterkit.ObsParticipant{Locator: b.loc(nil), Account: *a})
		keep("participants.address", p.address)
		keep("participants.on_chain_form", p.form)
	}
	for _, c := range b.changes {
		l.StateChanges = append(l.StateChanges, c)
		keep("state_changes.account", c.Account.Address)
		if c.Signer != nil {
			keep("state_changes.signer", c.Signer.Key)
		}
	}
	for _, m := range b.movements {
		l.Movements = append(l.Movements, m)
		for _, e := range []*adapterkit.ObsAccount{m.From, m.To} {
			if e != nil {
				keep("movements.endpoint", e.Address)
				keep("movements.endpoint.on_chain_form", e.OnChainForm)
			}
		}
	}
	for _, s := range addrs {
		l.Addresses = append(l.Addresses, adapterkit.ObsAddress{Locator: b.loc(nil), Field: s.field, Type: strkeyType(s.value),
			AsStored: adapterkit.Stored{Encoding: "strkey_text", Value: s.value}})
	}
}

// summary is the transaction's row: hash, outcome, result codes in XDR-JSON names, fee charged.
func (b *txBuilder) summary() adapterkit.ObsTransaction {
	r := b.tx.Result.Result
	i, ok := b.index, b.successful
	t := adapterkit.ObsTransaction{Hash: b.hash, Index: &i, Successful: &ok, ResultCode: txResultCode(r.Result.Code),
		FeeCharged: strconv.FormatInt(int64(r.FeeCharged), 10)}
	switch r.Result.Code {
	case xdr.TransactionResultCodeTxFeeBumpInnerSuccess, xdr.TransactionResultCodeTxFeeBumpInnerFailed:
		inner := r.Result.InnerResultPair
		t.InnerHash = inner.TransactionHash.HexString()
		ic := inner.Result.Result.Code
		innerOK := ic == xdr.TransactionResultCodeTxSuccess
		t.InnerSuccessful, t.InnerResultCode = &innerOK, txResultCode(ic)
		if inner.Result.Result.Results != nil {
			t.OperationResultCodes = opResultCodes(*inner.Result.Result.Results)
		}
	default:
		if r.Result.Results != nil {
			t.OperationResultCodes = opResultCodes(*r.Result.Results)
		}
	}
	return t
}

// claim is what the envelope says. It is stored for display and never mapped to a fact.
func (b *txBuilder) claim() Claim {
	env := b.tx.Envelope
	src := env.SourceAccount()
	c := Claim{TxHash: b.hash, Source: src.Address()}
	if env.IsFeeBump() {
		fs := env.FeeBumpAccount()
		c.FeeSource = fs.Address()
	}
	if m := env.Memo(); m.Type == xdr.MemoTypeMemoText && m.Text != nil {
		if utf8.ValidString(*m.Text) && strings.IndexByte(*m.Text, 0) < 0 {
			c.Memo = *m.Text
		} else {
			c.Memo = hex.EncodeToString([]byte(*m.Text)) // not text: kept as its bytes
		}
	}
	for _, op := range b.ops {
		var d *xdr.MuxedAccount
		switch body := op.Body; body.Type {
		case xdr.OperationTypePayment:
			d = &body.PaymentOp.Destination
		case xdr.OperationTypePathPaymentStrictReceive:
			d = &body.PathPaymentStrictReceiveOp.Destination
		case xdr.OperationTypePathPaymentStrictSend:
			d = &body.PathPaymentStrictSendOp.Destination
		case xdr.OperationTypeAccountMerge:
			d = body.Destination
		}
		if d != nil {
			c.Destinations = append(c.Destinations, d.Address())
		}
	}
	return c
}

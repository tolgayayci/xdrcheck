// Package indexer is the baseline indexer: a minimal, correct reader of LedgerCloseMeta built on go-stellar-sdk
// v0.9.0, written to be read. It is the reference for "what a correct reader extracts and from where", and the
// skeleton a third party copies when it adapts its own indexer.
//
// What it extracts, and from where (docs/manifest.md §6):
//
//   - receipts and the transaction list: the transaction processing list, envelopes, result pairs, meta counts;
//     hashes are recomputed from the envelopes with the pass's passphrase (the SDK's transaction reader does it
//     and fails on a mismatch);
//   - participants: the owners of every ledger entry the meta shows changed (fee processing, transaction-level
//     and operation changes), the fee payer, the source whose sequence number moved; never from the envelope;
//   - muxed identity: a muxed ID only where the ledger carries a u64 — a MuxedAccount in the envelope of an
//     account the meta already made a participant, or a `to_muxed_id` of type u64 in an event — recorded as an
//     alias beside the base address, never instead of it; text and hash memos are never addresses;
//   - state changes: created, updated, removed and restored entries, classified by entry type and by diffing
//     before and after; the envelope only labels the cause;
//   - movements: token-shaped contract events, each keyed on the contract that emitted it (rule M-7: a classic
//     asset only when the emitter is that asset's Stellar Asset Contract); fees and refunds from fee processing;
//     balance deltas only when the ledger carries no classic events;
//   - addresses: every address above, as the strkey text it is stored as.
//
// Each step is its own function on txBuilder, so a seeded-bug variant can replace one step and nothing else.
package indexer

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/stellar/go-stellar-sdk/ingest"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/tolgayayci/xdrcheck/go/adapterkit"
)

// DocSchema tags one stored ledger document.
const DocSchema = "xcc.baseline.ledger/1"

// Doc is what the indexer stores for one ledger: its facts in the protocol's neutral vocabulary, one record per
// fact, and the envelope's claims, which are kept for display and never become facts.
type Doc struct {
	Schema          string            `json:"schema"`
	LedgerSeq       int64             `json:"ledger_seq"`
	LedgerHash      string            `json:"ledger_hash"`
	ProtocolVersion uint32            `json:"protocol_version"`
	Facts           adapterkit.Ledger `json:"facts"`
	Claimed         []Claim           `json:"claimed"`
}

// Claim is what an envelope says, shown as a claim: the guide's point is that none of it is a fact.
type Claim struct {
	TxHash       string   `json:"tx_hash"`
	Source       string   `json:"source"`
	FeeSource    string   `json:"fee_source,omitempty"`
	Memo         string   `json:"memo,omitempty"`
	Destinations []string `json:"destinations,omitempty"`
}

// Derive extracts one ledger's facts. passphrase is the pass's network passphrase.
func Derive(lcm xdr.LedgerCloseMeta, passphrase string) (*Doc, error) {
	reader, err := ingest.NewLedgerTransactionReaderFromLedgerCloseMeta(passphrase, lcm)
	if err != nil {
		return nil, fmt.Errorf("read transactions: %w", err)
	}
	defer reader.Close()
	seq := int64(lcm.LedgerSequence())
	doc := &Doc{Schema: DocSchema, LedgerSeq: seq, LedgerHash: lcm.LedgerHash().HexString(), ProtocolVersion: lcm.ProtocolVersion()}
	doc.Facts = adapterkit.Ledger{LedgerSeq: seq, LedgerHash: doc.LedgerHash}

	var nTx, nOps, nEvents, nChanges int64
	for _, u := range lcm.UpgradesProcessing() {
		nChanges += int64(len(u.Changes))
	}
	for {
		tx, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read transaction: %w", err)
		}
		b := newTxBuilder(tx, passphrase, lcm.V >= 2)
		nTx++
		nOps += int64(len(b.ops))
		nEvents += int64(len(b.parts.txEvents))
		for _, evs := range b.parts.opEvents {
			nEvents += int64(len(evs))
		}
		nChanges += b.changeCount()
		doc.Facts.Transactions = append(doc.Facts.Transactions, b.summary())
		b.derive()
		b.records(&doc.Facts)
		doc.Claimed = append(doc.Claimed, b.claim())
	}
	doc.Facts.Receipt = &adapterkit.Receipt{Transactions: &nTx, Operations: &nOps, Events: &nEvents, EntryChanges: &nChanges}
	return doc, nil
}

// ---- one transaction ----

type metaParts struct {
	before   []xdr.LedgerEntryChanges
	after    *xdr.LedgerEntryChanges
	ops      []xdr.LedgerEntryChanges
	opEvents [][]xdr.ContractEvent
	txEvents []xdr.ContractEvent
}

func splitMeta(m xdr.TransactionMeta) metaParts {
	var p metaParts
	switch m.V {
	case 0:
		for _, o := range *m.Operations {
			p.ops = append(p.ops, o.Changes)
		}
	case 1:
		p.before = []xdr.LedgerEntryChanges{m.V1.TxChanges}
		for _, o := range m.V1.Operations {
			p.ops = append(p.ops, o.Changes)
		}
	case 2:
		p.before, p.after = []xdr.LedgerEntryChanges{m.V2.TxChangesBefore}, &m.V2.TxChangesAfter
		for _, o := range m.V2.Operations {
			p.ops = append(p.ops, o.Changes)
		}
	case 3:
		p.before, p.after = []xdr.LedgerEntryChanges{m.V3.TxChangesBefore}, &m.V3.TxChangesAfter
		for _, o := range m.V3.Operations {
			p.ops = append(p.ops, o.Changes)
		}
		// A Soroban transaction has exactly one operation; its events are that operation's.
		if m.V3.SorobanMeta != nil {
			p.opEvents = [][]xdr.ContractEvent{m.V3.SorobanMeta.Events}
		}
	case 4:
		p.before, p.after = []xdr.LedgerEntryChanges{m.V4.TxChangesBefore}, &m.V4.TxChangesAfter
		for _, o := range m.V4.Operations {
			p.ops = append(p.ops, o.Changes)
			p.opEvents = append(p.opEvents, o.Events)
		}
		for _, e := range m.V4.Events {
			p.txEvents = append(p.txEvents, e.Event)
		}
	}
	for len(p.opEvents) < len(p.ops) {
		p.opEvents = append(p.opEvents, nil)
	}
	return p
}

type participant struct {
	address string
	muxedID string
	form    string
	roles   map[string]bool
}

// txBuilder holds one transaction's inputs and the facts derived so far.
type txBuilder struct {
	index      int
	hash       string
	passphrase string
	tx         ingest.LedgerTransaction
	ops        []xdr.Operation
	parts      metaParts
	successful bool
	// postApplyFees: the ledger's LedgerCloseMeta (v2 and later) has post-apply fee processing.
	postApplyFees bool

	participants []*participant
	changes      []adapterkit.ObsStateChange
	movements    []adapterkit.ObsMovement

	// source is the account whose sequence number the transaction moved. Changes to entries with no address
	// of their own (contract code, a TTL whose entry is not found) are attributed to it.
	source string
	// ttlOwners maps a TTL key (the sha256 of an entry's key) to the contract-data or contract-code key it
	// belongs to, for the keys the transaction touched (its change lists and its Soroban footprint).
	ttlOwners map[[32]byte]xdr.LedgerKey
	// claimants are the accounts named as claimants of a claimable balance the transaction created or claimed.
	claimants map[string]bool
}

func newTxBuilder(tx ingest.LedgerTransaction, passphrase string, postApplyFees bool) *txBuilder {
	code := tx.Result.Result.Result.Code
	b := &txBuilder{
		index: int(tx.Index) - 1, hash: tx.Hash.HexString(), passphrase: passphrase, tx: tx, postApplyFees: postApplyFees,
		ops: tx.Envelope.Operations(), parts: splitMeta(tx.UnsafeMeta),
		successful: code == xdr.TransactionResultCodeTxSuccess || code == xdr.TransactionResultCodeTxFeeBumpInnerSuccess,
		claimants:  map[string]bool{},
	}
	b.ttlOwners = ttlOwners(b.parts, tx.Envelope)
	return b
}

// footprint returns the keys of the envelope's Soroban footprint (read-only and read-write).
func footprint(env xdr.TransactionEnvelope) []xdr.LedgerKey {
	var ext xdr.TransactionExt
	switch env.Type {
	case xdr.EnvelopeTypeEnvelopeTypeTx:
		ext = env.V1.Tx.Ext
	case xdr.EnvelopeTypeEnvelopeTypeTxFeeBump:
		ext = env.FeeBump.Tx.InnerTx.V1.Tx.Ext
	default:
		return nil
	}
	if ext.SorobanData == nil {
		return nil
	}
	f := ext.SorobanData.Resources.Footprint
	return append(append([]xdr.LedgerKey{}, f.ReadOnly...), f.ReadWrite...)
}

// ttlOwners indexes the contract-data and contract-code keys the transaction touched by the sha256 of their
// XDR, which is the key of their TTL entry. A match is proven by the hash, not taken on the envelope's word.
func ttlOwners(p metaParts, env xdr.TransactionEnvelope) map[[32]byte]xdr.LedgerKey {
	out := map[[32]byte]xdr.LedgerKey{}
	add := func(k xdr.LedgerKey) {
		if k.Type != xdr.LedgerEntryTypeContractData && k.Type != xdr.LedgerEntryTypeContractCode {
			return
		}
		if raw, err := k.MarshalBinary(); err == nil {
			out[sha256.Sum256(raw)] = k
		}
	}
	lists := append([]xdr.LedgerEntryChanges{}, p.before...)
	if p.after != nil {
		lists = append(lists, *p.after)
	}
	lists = append(lists, p.ops...)
	for _, l := range lists {
		for _, c := range l {
			switch c.Type {
			case xdr.LedgerEntryChangeTypeLedgerEntryRemoved:
				add(*c.Removed)
			default:
				if e, ok := changedEntry(c); ok {
					if k, err := e.LedgerKey(); err == nil {
						add(k)
					}
				}
			}
		}
	}
	for _, k := range footprint(env) {
		add(k)
	}
	return out
}

func changedEntry(c xdr.LedgerEntryChange) (xdr.LedgerEntry, bool) {
	switch c.Type {
	case xdr.LedgerEntryChangeTypeLedgerEntryState:
		return *c.State, true
	case xdr.LedgerEntryChangeTypeLedgerEntryCreated:
		return *c.Created, true
	case xdr.LedgerEntryChangeTypeLedgerEntryUpdated:
		return *c.Updated, true
	case xdr.LedgerEntryChangeTypeLedgerEntryRestored:
		return *c.Restored, true
	}
	return xdr.LedgerEntry{}, false
}

// entryRole is the role of a participant that is a pool's or a claimable balance's own address.
func entryRole(address string) string {
	switch {
	case len(address) > 0 && address[0] == 'L':
		return "liquidity_pool"
	case len(address) > 0 && address[0] == 'B':
		return "claimable_balance"
	}
	return ""
}

func (b *txBuilder) addClaimants(cb xdr.ClaimableBalanceEntry) {
	for _, c := range cb.Claimants {
		if c.V0 != nil {
			b.claimants[accountStrkey(c.V0.Destination)] = true
		}
	}
}

// sourceChange records a change to an entry with no address of its own against the transaction's source.
func (b *txBuilder) sourceChange(kind string, op *int, detail map[string]any, cause string) {
	if b.source != "" {
		b.change(kind, op, b.source, "", nil, detail, cause)
	}
}

func (b *txBuilder) changeCount() int64 {
	n := len(b.tx.FeeChanges) + len(b.tx.PostTxApplyFeeChanges)
	for _, l := range b.parts.before {
		n += len(l)
	}
	if b.parts.after != nil {
		n += len(*b.parts.after)
	}
	for _, l := range b.parts.ops {
		n += len(l)
	}
	return int64(n)
}

// derive runs the steps in order. A failed transaction stops after the transaction-level changes: only the fee
// payer and the source changed.
func (b *txBuilder) derive() {
	b.feeStep()
	b.txLevelStep()
	if b.successful {
		for i, changes := range b.parts.ops {
			b.opChangesStep(i, changes)
		}
		b.eventsStep()
		if !b.feeEventsPresent() {
			b.balanceDeltaStep()
		}
	}
	b.counterpartyStep()
	b.aliasStep()
}

func (b *txBuilder) role(address, role string) *participant {
	for _, p := range b.participants {
		if p.address == address {
			if role != "" {
				p.roles[role] = true
			}
			return p
		}
	}
	p := &participant{address: address, roles: map[string]bool{}}
	if role != "" {
		p.roles[role] = true
	}
	b.participants = append(b.participants, p)
	return p
}

func (b *txBuilder) isParticipant(address string) bool {
	for _, p := range b.participants {
		if p.address == address {
			return true
		}
	}
	return false
}

func (b *txBuilder) loc(op *int) adapterkit.Locator {
	i := b.index
	return adapterkit.Locator{TxHash: b.hash, TxIndex: &i, OpIndex: op}
}

func account(address string) *adapterkit.ObsAccount {
	return &adapterkit.ObsAccount{Address: address, AsStored: &adapterkit.Stored{Encoding: "strkey_text", Value: address}}
}

func (b *txBuilder) change(kind string, op *int, owner, asset string, signer *adapterkit.ObsSigner, detail map[string]any, cause string) {
	if len(detail) == 0 {
		detail = nil
	}
	b.changes = append(b.changes, adapterkit.ObsStateChange{
		Locator: b.loc(op), Kind: kind, Account: account(owner), Asset: asset, Signer: signer, Detail: detail, Cause: cause,
	})
}

func (b *txBuilder) movement(kind string, op *int, asset, amount string, from, to *adapterkit.ObsAccount, routing *adapterkit.ObsRouting) {
	b.movements = append(b.movements, adapterkit.ObsMovement{
		Locator: b.loc(op), Kind: kind, Asset: asset, Amount: amount, From: from, To: to, Routing: routing, //xdrlint:ignore XDR103 an asset named in an event is recorded only when its contract ID equals the emitter (events.go, case sac != nil), so it is a deployed SAC's asset, which stellar-core validated
	})
}

// cause labels a change with the operation that made it: `contract-call` for a classic entry changed by a
// contract, otherwise the operation type. It is documentation only.
func (b *txBuilder) cause(op int, t xdr.LedgerEntryType) string {
	if op < 0 || op >= len(b.ops) {
		return ""
	}
	if b.ops[op].Body.Type == xdr.OperationTypeInvokeHostFunction && isClassic(t) {
		return "contract-call"
	}
	return opType(b.ops[op].Body.Type)
}

// ---- transitions ----

type transition struct {
	kind string // created, updated, removed, restored
	pre  *xdr.LedgerEntry
	post *xdr.LedgerEntry
	key  xdr.LedgerKey
}

// transitions pairs each `state` with the following update or removal of the same key.
func transitions(changes xdr.LedgerEntryChanges) []transition {
	pre := map[string]*xdr.LedgerEntry{}
	var out []transition
	for _, c := range changes {
		switch c.Type {
		case xdr.LedgerEntryChangeTypeLedgerEntryState:
			pre[entryKey(*c.State)] = c.State
		case xdr.LedgerEntryChangeTypeLedgerEntryCreated:
			out = append(out, transition{kind: "created", post: c.Created})
		case xdr.LedgerEntryChangeTypeLedgerEntryUpdated:
			out = append(out, transition{kind: "updated", pre: pre[entryKey(*c.Updated)], post: c.Updated})
		case xdr.LedgerEntryChangeTypeLedgerEntryRemoved:
			out = append(out, transition{kind: "removed", pre: pre[keyBytes(*c.Removed)], key: *c.Removed})
		case xdr.LedgerEntryChangeTypeLedgerEntryRestored:
			pre[entryKey(*c.Restored)] = c.Restored
			out = append(out, transition{kind: "restored", post: c.Restored})
		}
	}
	return out
}

// ---- step 1: fee and refund ----

// feeStep: in fee processing the account whose balance decreased is the fee payer, the decrease a `fee`
// movement; a balance increase in post-apply fee processing is the `fee_refund`. A LedgerCloseMeta v0/v1 has no
// post-apply fee processing: there the refund is in the changes after, whatever the TransactionMeta version (v3
// as nodes emitted it, v4 in lake objects regenerated by a later stellar-core).
func (b *txBuilder) feeStep() {
	payer := ""
	for _, t := range transitions(b.tx.FeeChanges) {
		a0, a1, ok := accounts(t)
		if !ok {
			continue
		}
		who := accountStrkey(a1.AccountId)
		if a1.Balance < a0.Balance {
			b.role(who, "fee_payer")
			b.movement("fee", nil, "native", strconv.FormatInt(int64(a0.Balance-a1.Balance), 10), account(who), nil, nil)
			payer = who
		}
		if a0.SeqNum != a1.SeqNum {
			b.role(who, "source") // before Protocol 10 the sequence number moved in fee processing
			b.source = who
		}
	}
	refunds := []xdr.LedgerEntryChanges{b.tx.PostTxApplyFeeChanges}
	if !b.postApplyFees && b.parts.after != nil {
		refunds = append(refunds, *b.parts.after)
	}
	for _, list := range refunds {
		for _, t := range transitions(list) {
			a0, a1, ok := accounts(t)
			if !ok {
				continue
			}
			who := accountStrkey(a1.AccountId)
			if a1.Balance > a0.Balance && who == payer {
				b.movement("fee_refund", nil, "native", strconv.FormatInt(int64(a1.Balance-a0.Balance), 10), nil, account(who), nil)
			}
		}
	}
}

func accounts(t transition) (xdr.AccountEntry, xdr.AccountEntry, bool) {
	if t.kind != "updated" || t.pre == nil || t.pre.Data.Type != xdr.LedgerEntryTypeAccount || t.post.Data.Type != xdr.LedgerEntryTypeAccount {
		return xdr.AccountEntry{}, xdr.AccountEntry{}, false
	}
	return *t.pre.Data.Account, *t.post.Data.Account, true
}

// ---- step 2: transaction-level changes ----

// txLevelStep: the account whose sequence number changed is the source (`sequence_bumped`); one-time signers
// removed at transaction level are `signer_removed`.
func (b *txBuilder) txLevelStep() {
	lists := append([]xdr.LedgerEntryChanges{}, b.parts.before...)
	if b.parts.after != nil {
		lists = append(lists, *b.parts.after)
	}
	for _, list := range lists {
		for _, t := range transitions(list) {
			a0, a1, ok := accounts(t)
			if !ok {
				continue
			}
			who := accountStrkey(a1.AccountId)
			if a0.SeqNum != a1.SeqNum {
				b.role(who, "source")
				b.source = who
				b.change("sequence_bumped", nil, who, "", nil, map[string]any{"sequence_after": strconv.FormatInt(int64(a1.SeqNum), 10)}, "")
			}
			removed := false
			for _, s := range a0.Signers {
				if !slices.ContainsFunc(a1.Signers, func(s1 xdr.Signer) bool { return s1.Key.Equals(s.Key) }) {
					removed = true
				}
			}
			if removed {
				b.signerDiff(nil, a0, a1, "")
			}
		}
	}
}

// ---- step 3: operation changes ----

func (b *txBuilder) opChangesStep(op int, changes xdr.LedgerEntryChanges) {
	trs := transitions(changes)
	subEntries := map[string]uint32{}
	var credited []struct {
		who string
		n   int64
	}
	for _, t := range trs {
		if t.post != nil && t.post.Data.Type == xdr.LedgerEntryTypeAccount && (t.kind == "updated" || t.kind == "created") {
			a := t.post.Data.Account
			subEntries[accountStrkey(a.AccountId)] = uint32(a.NumSubEntries)
		}
		if a0, a1, ok := accounts(t); ok && a1.Balance > a0.Balance {
			credited = append(credited, struct {
				who string
				n   int64
			}{accountStrkey(a1.AccountId), int64(a1.Balance - a0.Balance)})
		}
	}
	opi := op
	for _, t := range trs {
		var et xdr.LedgerEntryType
		switch {
		case t.post != nil:
			et = t.post.Data.Type
		case t.pre != nil:
			et = t.pre.Data.Type
		}
		cause := b.cause(op, et)
		switch t.kind {
		case "restored":
			k, _ := t.post.LedgerKey()
			det := map[string]any{"entry_type": entryTypeName(k.Type), "key_xdr_hex": xdrHex(k)}
			if cd := t.post.Data.ContractData; cd != nil {
				owner := baseAddress(cd.Contract)
				b.change("entry_restored", &opi, owner, "", nil, det, cause)
				b.role(owner, "contract")
			} else if cc := t.post.Data.ContractCode; cc != nil {
				// Contract code has no address: the restore is the source's.
				det["wasm_hash"] = hex.EncodeToString(cc.Hash[:])
				b.sourceChange("entry_restored", &opi, det, cause)
			}
		case "created":
			b.created(&opi, *t.post, cause, subEntries)
		case "updated":
			if t.pre != nil {
				b.updated(&opi, *t.pre, *t.post, cause)
			}
		case "removed":
			if t.pre != nil {
				b.removed(&opi, *t.pre, cause, func(owner string, balance int64) string {
					var into []string
					for _, c := range credited {
						if c.n == balance && c.who != owner {
							into = append(into, c.who)
						}
					}
					if len(into) == 1 {
						return into[0]
					}
					return ""
				})
			}
		}
	}
}

func trustlineFlags(flags uint32) map[string]any {
	return map[string]any{
		"flags": flags, "authorized": flags&1 != 0, "authorized_to_maintain_liabilities": flags&2 != 0, "clawback_enabled": flags&4 != 0,
	}
}

func (b *txBuilder) created(op *int, e xdr.LedgerEntry, cause string, subEntries map[string]uint32) {
	sponsor := entrySponsor(e)
	if sponsor != "" {
		b.role(sponsor, "sponsor")
	}
	d := e.Data
	switch d.Type {
	case xdr.LedgerEntryTypeAccount:
		owner := accountStrkey(d.Account.AccountId)
		det := map[string]any{"starting_balance": strconv.FormatInt(int64(d.Account.Balance), 10)}
		if sponsor != "" {
			det["sponsor"] = sponsor
		}
		b.change("account_created", op, owner, "", nil, det, cause)
		b.role(owner, "destination")
	case xdr.LedgerEntryTypeTrustline:
		t := d.TrustLine
		owner := accountStrkey(t.AccountId)
		asset, _ := trustlineAsset(t.Asset)
		det := trustlineFlags(uint32(t.Flags))
		det["balance"] = strconv.FormatInt(int64(t.Balance), 10)
		det["limit"] = strconv.FormatInt(int64(t.Limit), 10)
		if sponsor != "" {
			det["sponsor"] = sponsor
		}
		if n, ok := subEntries[owner]; ok {
			det["num_sub_entries_after"] = n
		}
		if t.Asset.Type == xdr.AssetTypeAssetTypePoolShare {
			det["pool_strkey"] = poolStrkey(*t.Asset.LiquidityPoolId)
		}
		b.change("trustline_created", op, owner, asset, nil, det, cause)
		b.role(owner, "trustline_owner")
	case xdr.LedgerEntryTypeOffer:
		b.offer(op, *d.Offer, "created", cause)
	case xdr.LedgerEntryTypeData:
		b.data(op, *d.Data, "created", cause)
	case xdr.LedgerEntryTypeClaimableBalance:
		cb := d.ClaimableBalance
		id := claimableStrkey(cb.BalanceId)
		det := map[string]any{"balance_id": id, "amount": strconv.FormatInt(int64(cb.Amount), 10), "claimants": len(cb.Claimants)}
		if sponsor != "" {
			det["sponsor"] = sponsor
		}
		b.change("claimable_balance_created", op, id, assetString(cb.Asset), nil, det, cause)
		b.role(id, "claimable_balance")
		b.addClaimants(*cb)
	case xdr.LedgerEntryTypeLiquidityPool:
		id := poolStrkey(d.LiquidityPool.LiquidityPoolId)
		b.change("liquidity_pool_created", op, id, "", nil, poolDetail(*d.LiquidityPool), cause)
		b.role(id, "liquidity_pool")
	case xdr.LedgerEntryTypeContractData:
		cd := d.ContractData
		owner := baseAddress(cd.Contract)
		if cd.Key.Type == xdr.ScValTypeScvLedgerKeyNonce {
			b.role(owner, "authorizer") // a created nonce entry proves this address authenticated
			return
		}
		if cd.Key.Type == xdr.ScValTypeScvLedgerKeyContractInstance && cd.Val.Type == xdr.ScValTypeScvContractInstance && cd.Val.Instance != nil {
			det := map[string]any{"contract": owner}
			switch ex := cd.Val.Instance.Executable; ex.Type {
			case xdr.ContractExecutableTypeContractExecutableWasm:
				det["executable"] = "wasm"
				det["wasm_hash"] = ex.WasmHash.HexString()
			case xdr.ContractExecutableTypeContractExecutableStellarAsset:
				det["executable"] = "stellar_asset"
			default:
				// XDR-JSON arm name: the Go constant repeats the XDR prefix ContractExecutable after the type name.
				det["executable"] = strings.TrimPrefix(enumArm(ex.Type), "contract_executable_")
			}
			b.change("contract_deployed", op, owner, "", nil, det, cause)
			b.role(owner, "contract")
			return
		}
		b.contractData(op, *cd, "created", cause)
	case xdr.LedgerEntryTypeContractCode:
		// Contract code has no address of its own: the upload is the source's.
		cc := d.ContractCode
		b.sourceChange("contract_code_created", op, map[string]any{"wasm_hash": hex.EncodeToString(cc.Hash[:]), "code_bytes": len(cc.Code)}, cause)
	}
	// A new entry's TTL is part of its creation; settings are bookkeeping.
}

func (b *txBuilder) updated(op *int, pre, e xdr.LedgerEntry, cause string) {
	s0, s1 := entrySponsor(pre), entrySponsor(e)
	if s0 != s1 {
		if owner := ownerOf(e.Data); owner != "" {
			k, _ := e.LedgerKey()
			det := map[string]any{"entry_type": entryTypeName(k.Type)}
			if s0 != "" {
				det["sponsor_before"] = s0
				b.role(s0, "sponsor")
			}
			if s1 != "" {
				det["sponsor_after"] = s1
				b.role(s1, "sponsor")
			}
			b.change("sponsorship_changed", op, owner, "", nil, det, cause)
			b.role(owner, entryRole(owner))
		}
	}
	if pre.Data.Type != e.Data.Type {
		return
	}
	switch e.Data.Type {
	case xdr.LedgerEntryTypeAccount:
		a0, a1 := *pre.Data.Account, *e.Data.Account
		owner := accountStrkey(a1.AccountId)
		if a0.Balance != a1.Balance {
			b.change("balance_changed", op, owner, "native", nil, map[string]any{
				"delta": strconv.FormatInt(int64(a1.Balance-a0.Balance), 10), "balance_after": strconv.FormatInt(int64(a1.Balance), 10)}, cause)
		}
		b.signerDiff(op, a0, a1, cause)
		if a0.Thresholds != a1.Thresholds {
			t := a1.Thresholds
			b.change("thresholds_changed", op, owner, "", nil, map[string]any{"master_weight": t[0], "low": t[1], "medium": t[2], "high": t[3]}, cause)
		}
		sponsoring := func(a xdr.AccountEntry) uint32 {
			if v2 := accountV2(a); v2 != nil {
				return uint32(v2.NumSponsoring)
			}
			return 0
		}
		if sponsoring(a1) > sponsoring(a0) {
			b.role(owner, "sponsor")
		}
		b.accountFields(op, owner, a0, a1, cause)
		// A sub-entry count or sequence-ledger change alone has no state-change kind; the account is still
		// affected.
		b.role(owner, "")
	case xdr.LedgerEntryTypeTrustline:
		t0, t1 := *pre.Data.TrustLine, *e.Data.TrustLine
		owner := accountStrkey(t1.AccountId)
		asset, _ := trustlineAsset(t1.Asset)
		if t0.Balance != t1.Balance {
			b.change("balance_changed", op, owner, asset, nil, map[string]any{
				"delta": strconv.FormatInt(int64(t1.Balance-t0.Balance), 10), "balance_after": strconv.FormatInt(int64(t1.Balance), 10)}, cause)
		}
		if t0.Flags != t1.Flags {
			b.change("trustline_flags_changed", op, owner, asset, nil, trustlineFlags(uint32(t1.Flags)), cause)
		}
		if t0.Limit != t1.Limit {
			b.change("trustline_limit_changed", op, owner, asset, nil, map[string]any{
				"limit": strconv.FormatInt(int64(t1.Limit), 10), "limit_before": strconv.FormatInt(int64(t0.Limit), 10)}, cause)
		}
		b.role(owner, "trustline_owner")
	case xdr.LedgerEntryTypeOffer:
		b.offer(op, *e.Data.Offer, "updated", cause)
	case xdr.LedgerEntryTypeData:
		// Like trustline limits and thresholds: an update that writes the same value back is no state change.
		// The owner is still affected.
		if d0, d1 := *pre.Data.Data, *e.Data.Data; !bytes.Equal(d0.DataValue, d1.DataValue) {
			b.data(op, d1, "updated", cause)
		} else {
			b.role(accountStrkey(d1.AccountId), "")
		}
	case xdr.LedgerEntryTypeLiquidityPool:
		id := poolStrkey(e.Data.LiquidityPool.LiquidityPoolId)
		b.change("liquidity_pool_changed", op, id, "", nil, poolDetail(*e.Data.LiquidityPool), cause)
		b.role(id, "liquidity_pool")
	case xdr.LedgerEntryTypeContractData:
		if e.Data.ContractData.Key.Type != xdr.ScValTypeScvLedgerKeyNonce {
			b.contractData(op, *e.Data.ContractData, "updated", cause)
		}
	case xdr.LedgerEntryTypeTtl:
		if t0, t1 := *pre.Data.Ttl, *e.Data.Ttl; t1.LiveUntilLedgerSeq > t0.LiveUntilLedgerSeq {
			b.ttlExtended(op, t0, t1, cause)
		}
	}
}

// accountFields records account flags, home domain and inflation destination changes.
func (b *txBuilder) accountFields(op *int, owner string, a0, a1 xdr.AccountEntry, cause string) {
	if a0.Flags != a1.Flags {
		f := uint32(a1.Flags)
		b.change("account_flags_changed", op, owner, "", nil, map[string]any{
			"flags": f, "flags_before": uint32(a0.Flags), "auth_required": f&1 != 0, "auth_revocable": f&2 != 0,
			"auth_immutable": f&4 != 0, "auth_clawback_enabled": f&8 != 0}, cause)
	}
	if a0.HomeDomain != a1.HomeDomain {
		now, before := string(a1.HomeDomain), string(a0.HomeDomain)
		det := map[string]any{"home_domain_hex": hex.EncodeToString([]byte(now))}
		// The text forms only where the bytes are UTF-8; the hex is always exact.
		if utf8.ValidString(now) {
			det["home_domain"] = now
		}
		if utf8.ValidString(before) {
			det["home_domain_before"] = before
		}
		b.change("home_domain_changed", op, owner, "", nil, det, cause)
	}
	d0, d1 := "", ""
	if a0.InflationDest != nil {
		d0 = accountStrkey(*a0.InflationDest)
	}
	if a1.InflationDest != nil {
		d1 = accountStrkey(*a1.InflationDest)
	}
	if d0 != d1 {
		det := map[string]any{}
		if d1 != "" {
			det["inflation_destination"] = d1
		} else {
			det["cleared"] = true
		}
		if d0 != "" {
			det["inflation_destination_before"] = d0
		}
		b.change("inflation_destination_changed", op, owner, "", nil, det, cause)
	}
}

// ttlExtended records a TTL entry whose live-until ledger grew: the contract's for contract data, the source's for
// contract code or an entry not found among the keys the transaction touched. It makes no participant: the host
// extends TTLs as a side effect of access, so the kind is ambient.
func (b *txBuilder) ttlExtended(op *int, t0, t1 xdr.TtlEntry, cause string) {
	det := map[string]any{
		"key_hash": hex.EncodeToString(t1.KeyHash[:]), "live_until_ledger": uint32(t1.LiveUntilLedgerSeq),
		"live_until_ledger_before": uint32(t0.LiveUntilLedgerSeq),
	}
	k, found := b.ttlOwners[t1.KeyHash]
	if found {
		det["entry_type"] = entryTypeName(k.Type)
		det["key_xdr_hex"] = xdrHex(k)
	}
	switch {
	case found && k.ContractData != nil:
		contract := baseAddress(k.ContractData.Contract)
		det["contract"] = contract
		b.change("ttl_extended", op, contract, "", nil, det, cause)
	case found && k.ContractCode != nil:
		det["wasm_hash"] = hex.EncodeToString(k.ContractCode.Hash[:])
		b.sourceChange("ttl_extended", op, det, cause)
	default:
		b.sourceChange("ttl_extended", op, det, cause)
	}
}

func (b *txBuilder) removed(op *int, pre xdr.LedgerEntry, cause string, mergedInto func(owner string, balance int64) string) {
	d := pre.Data
	switch d.Type {
	case xdr.LedgerEntryTypeAccount:
		owner := accountStrkey(d.Account.AccountId)
		det := map[string]any{"balance_transferred": strconv.FormatInt(int64(d.Account.Balance), 10)}
		if into := mergedInto(owner, int64(d.Account.Balance)); into != "" {
			det["merged_into"] = into
		}
		b.change("account_removed", op, owner, "", nil, det, cause)
		b.role(owner, "")
	case xdr.LedgerEntryTypeTrustline:
		t := d.TrustLine
		owner := accountStrkey(t.AccountId)
		asset, _ := trustlineAsset(t.Asset)
		det := map[string]any{"balance": strconv.FormatInt(int64(t.Balance), 10)}
		if t.Asset.Type == xdr.AssetTypeAssetTypePoolShare {
			det["pool_strkey"] = poolStrkey(*t.Asset.LiquidityPoolId)
		}
		b.change("trustline_removed", op, owner, asset, nil, det, cause)
		b.role(owner, "trustline_owner")
	case xdr.LedgerEntryTypeOffer:
		b.offer(op, *d.Offer, "removed", cause)
	case xdr.LedgerEntryTypeData:
		b.data(op, *d.Data, "removed", cause)
	case xdr.LedgerEntryTypeClaimableBalance:
		cb := d.ClaimableBalance
		id := claimableStrkey(cb.BalanceId)
		b.change("claimable_balance_claimed", op, id, assetString(cb.Asset), nil, map[string]any{"balance_id": id, "amount": strconv.FormatInt(int64(cb.Amount), 10)}, cause)
		b.role(id, "claimable_balance")
		b.addClaimants(*cb)
	case xdr.LedgerEntryTypeLiquidityPool:
		id := poolStrkey(d.LiquidityPool.LiquidityPoolId)
		lp := d.LiquidityPool.LiquidityPoolId
		b.change("liquidity_pool_removed", op, id, "", nil, map[string]any{"pool_id": xdr.Hash(lp).HexString(), "pool_strkey": id}, cause)
		b.role(id, "liquidity_pool")
	case xdr.LedgerEntryTypeContractData:
		if d.ContractData.Key.Type != xdr.ScValTypeScvLedgerKeyNonce {
			b.contractData(op, *d.ContractData, "removed", cause)
		}
	}
}

func ownerOf(d xdr.LedgerEntryData) string {
	switch d.Type {
	case xdr.LedgerEntryTypeAccount:
		return accountStrkey(d.Account.AccountId)
	case xdr.LedgerEntryTypeTrustline:
		return accountStrkey(d.TrustLine.AccountId)
	case xdr.LedgerEntryTypeOffer:
		return accountStrkey(d.Offer.SellerId)
	case xdr.LedgerEntryTypeData:
		return accountStrkey(d.Data.AccountId)
	case xdr.LedgerEntryTypeClaimableBalance:
		return claimableStrkey(d.ClaimableBalance.BalanceId)
	case xdr.LedgerEntryTypeLiquidityPool:
		return poolStrkey(d.LiquidityPool.LiquidityPoolId)
	case xdr.LedgerEntryTypeContractData:
		return baseAddress(d.ContractData.Contract)
	}
	return ""
}

func poolDetail(p xdr.LiquidityPoolEntry) map[string]any {
	cp := p.Body.ConstantProduct
	d := map[string]any{
		"pool_id": xdr.Hash(p.LiquidityPoolId).HexString(), "pool_strkey": poolStrkey(p.LiquidityPoolId),
		"asset_a": assetString(cp.Params.AssetA), "asset_b": assetString(cp.Params.AssetB), "fee_bp": int32(cp.Params.Fee),
		"reserve_a": strconv.FormatInt(int64(cp.ReserveA), 10), "reserve_b": strconv.FormatInt(int64(cp.ReserveB), 10),
		"total_shares":                 strconv.FormatInt(int64(cp.TotalPoolShares), 10),
		"pool_shares_trust_line_count": strconv.FormatInt(int64(cp.PoolSharesTrustLineCount), 10),
	}
	if h, ok := issuerKeyHex(cp.Params.AssetA); ok {
		d["asset_a_issuer_key_hex"] = h
	}
	if h, ok := issuerKeyHex(cp.Params.AssetB); ok {
		d["asset_b_issuer_key_hex"] = h
	}
	return d
}

func (b *txBuilder) offer(op *int, o xdr.OfferEntry, change, cause string) {
	owner := accountStrkey(o.SellerId)
	b.change("offer_changed", op, owner, "", nil, map[string]any{
		"offer_id": strconv.FormatInt(int64(o.OfferId), 10), "change": change, "selling": assetString(o.Selling), "buying": assetString(o.Buying),
		"amount": strconv.FormatInt(int64(o.Amount), 10), "price_n": int32(o.Price.N), "price_d": int32(o.Price.D),
	}, cause)
	b.role(owner, "")
}

func (b *txBuilder) data(op *int, de xdr.DataEntry, change, cause string) {
	owner := accountStrkey(de.AccountId)
	b.change("data_entry_changed", op, owner, "", nil, map[string]any{
		"name": string(de.DataName), "value_hex": fmt.Sprintf("%x", []byte(de.DataValue)), "change": change,
	}, cause)
	b.role(owner, "")
}

func (b *txBuilder) contractData(op *int, cd xdr.ContractDataEntry, change, cause string) {
	owner := baseAddress(cd.Contract)
	durability := "persistent"
	if cd.Durability == xdr.ContractDataDurabilityTemporary {
		durability = "temporary"
	}
	b.change("contract_data_changed", op, owner, "", nil, map[string]any{
		"contract": owner, "key_xdr_hex": xdrHex(cd.Key), "durability": durability, "change": change,
	}, cause)
	b.role(owner, "contract")
}

// ---- signers ----

type signerRow struct {
	weight  uint32
	sponsor string
	key     xdr.SignerKey
}

func signerRows(a xdr.AccountEntry) (map[string]signerRow, []string) {
	var sponsors []xdr.SponsorshipDescriptor
	if v2 := accountV2(a); v2 != nil {
		sponsors = v2.SignerSponsoringIDs
	}
	rows := map[string]signerRow{}
	var order []string
	for i, s := range a.Signers {
		r := signerRow{weight: uint32(s.Weight), key: s.Key}
		if i < len(sponsors) && sponsors[i] != nil {
			r.sponsor = accountStrkey(*sponsors[i])
		}
		k := xdrHex(s.Key)
		rows[k] = r
		order = append(order, k)
	}
	sort.Strings(order)
	return rows, order
}

func signerFact(key xdr.SignerKey, weight uint32) (*adapterkit.ObsSigner, map[string]any) {
	det := map[string]any{"signer_key_xdr_hex": xdrHex(key)}
	text, _ := key.GetAddress()
	w := int(weight)
	s := &adapterkit.ObsSigner{Key: text, Weight: &w, AsStored: &adapterkit.Stored{Encoding: "strkey_text", Value: text}}
	switch key.Type {
	case xdr.SignerKeyTypeSignerKeyTypeEd25519:
		s.Type = "ed25519"
		det["signer_ed25519_key"] = ed25519Strkey(*key.Ed25519)
	case xdr.SignerKeyTypeSignerKeyTypePreAuthTx:
		s.Type = "pre_auth_tx"
	case xdr.SignerKeyTypeSignerKeyTypeHashX:
		s.Type = "hash_x"
	case xdr.SignerKeyTypeSignerKeyTypeEd25519SignedPayload:
		s.Type = "ed25519_signed_payload"
		p := key.Ed25519SignedPayload
		det["signer_ed25519_key"] = ed25519Strkey(p.Ed25519)
		det["payload_bytes"] = len(p.Payload)
		s.PayloadHex = fmt.Sprintf("%x", p.Payload)
	}
	return s, det
}

// signerDiff records added, changed and removed signers between two versions of an account.
func (b *txBuilder) signerDiff(op *int, a0, a1 xdr.AccountEntry, cause string) {
	owner := accountStrkey(a1.AccountId)
	old, oldOrder := signerRows(a0)
	cur, curOrder := signerRows(a1)
	any := false
	for _, k := range curOrder {
		r := cur[k]
		prev, existed := old[k]
		switch {
		case !existed:
			s, det := signerFact(r.key, r.weight)
			if r.sponsor != "" {
				det["sponsor"] = r.sponsor
			}
			b.change("signer_added", op, owner, "", s, det, cause)
			any = true
		case prev.weight != r.weight:
			s, det := signerFact(r.key, r.weight)
			det["weight_before"] = prev.weight
			if r.sponsor != "" {
				det["sponsor"] = r.sponsor
			}
			b.change("signer_changed", op, owner, "", s, det, cause)
			any = true
		}
	}
	for _, k := range oldOrder {
		if _, still := cur[k]; still {
			continue
		}
		r := old[k]
		s, det := signerFact(r.key, r.weight)
		det["weight_before"] = r.weight
		if r.sponsor != "" {
			det["sponsor"] = r.sponsor
		}
		b.change("signer_removed", op, owner, "", s, det, cause)
		any = true
	}
	if any {
		b.role(owner, "signer_owner")
	}
}

package driver

import (
	"bytes"
	"encoding/hex"

	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// rebuildEntry names the rebuild recipe (docs/conformance-protocol.md, "The rebuild fact"). go-stellar-sdk has
// no API that clones a parsed transaction, so the recipe is the driver's, built only from what the parsed
// object exposes: txnbuild.NewTransaction with the parsed source account and sequence number
// (IncrementSequenceNum false), the parsed operations, the parsed memo, the per-operation inclusion fee
// (MaxFee less the resource fee that the parsed Soroban operation's own BuildTransactionExt carries, divided by
// the operation count) and the preconditions. The parsed Transaction has no getter for its preconditions beyond
// Timebounds(), so they are read through the SDK's own converter, Preconditions.FromXDR on the parsed
// object's ToXDR(): a precondition dropped there cannot show here.
const rebuildEntry = "txnbuild.NewTransaction"

// rebuildFact rebuilds a parsed transaction through txnbuild.NewTransaction and hashes it under the passphrase.
// What the builder's API cannot express is not rebuilt, decided before the call: a fee bump (the fact covers
// transactions), a transaction without time bounds (Preconditions documents them as required) and an
// inclusion fee that is not a whole multiple of the operation count (BaseFee is per operation).
func rebuildFact(gt *txnbuild.GenericTransaction, passphrase string) map[string]any {
	fact := map[string]any{"entry_point": rebuildEntry}
	notRebuilt := func(r string) map[string]any {
		fact["outcome"], fact["reason"] = "not_rebuilt", r
		return fact
	}
	tx, isTx := gt.Transaction()
	if !isTx {
		return notRebuilt("fee_bump")
	}
	orig := tx.ToXDR()
	var cond txnbuild.Preconditions
	if err := cond.FromXDR(orig.Preconditions()); err != nil {
		return refusedFact(fact, "Preconditions.FromXDR", err)
	}
	if tb := orig.Preconditions(); tb.Type == xdr.PreconditionTypePrecondNone || (tb.Type == xdr.PreconditionTypePrecondV2 && tb.V2.TimeBounds == nil) {
		return notRebuilt("no_time_bounds")
	}
	ops := tx.Operations()
	var resourceFee int64
	for _, op := range ops {
		if so, isSoroban := op.(txnbuild.SorobanOperation); isSoroban {
			ext, err := so.BuildTransactionExt()
			if err != nil {
				return refusedFact(fact, "SorobanOperation.BuildTransactionExt", err)
			}
			if ext.SorobanData != nil {
				resourceFee = int64(ext.SorobanData.ResourceFee)
			}
		}
	}
	inclusion := tx.MaxFee() - resourceFee
	if len(ops) == 0 || inclusion < 0 || inclusion%int64(len(ops)) != 0 {
		return notRebuilt("fee_not_per_operation")
	}
	src := tx.SourceAccount()
	built, err := txnbuild.NewTransaction(txnbuild.TransactionParams{
		SourceAccount:        &txnbuild.SimpleAccount{AccountID: src.AccountID, Sequence: tx.SequenceNumber()},
		IncrementSequenceNum: false,
		Operations:           ops,
		BaseFee:              inclusion / int64(len(ops)),
		Memo:                 tx.Memo(),
		Preconditions:        cond,
	})
	if err != nil {
		return refusedFact(fact, rebuildEntry, err)
	}
	h, err := built.Hash(passphrase)
	if err != nil {
		return refusedFact(fact, "Transaction.Hash", err)
	}
	fact["outcome"] = "rebuilt"
	fact["tx_hash"] = hex.EncodeToString(h[:])
	if want, err := tx.Hash(passphrase); err == nil && want != h {
		fact["differs"] = differingFields(orig, built.ToXDR())
	}
	return fact
}

func refusedFact(fact map[string]any, entry string, err error) map[string]any {
	fact["outcome"] = "refused"
	fact["message"] = trim(entry + ": " + err.Error())
	return fact
}

// differingFields names the Transaction fields (XDR field names) whose encoding differs between two envelopes:
// a diagnostic only.
func differingFields(a, b xdr.TransactionEnvelope) []string {
	enc := func(v any) []byte {
		m, ok := v.(interface{ MarshalBinary() ([]byte, error) })
		if !ok {
			return nil
		}
		out, _ := m.MarshalBinary()
		return out
	}
	ext := func(e xdr.TransactionEnvelope) xdr.TransactionExt {
		if e.V1 != nil {
			return e.V1.Tx.Ext
		}
		return xdr.TransactionExt{}
	}
	opsOf := func(e xdr.TransactionEnvelope) []byte {
		var buf []byte
		for _, op := range e.Operations() {
			buf = append(buf, enc(op)...)
		}
		return buf
	}
	sa, sb := a.SourceAccount(), b.SourceAccount()
	fa, fb := xdr.Uint32(a.Fee()), xdr.Uint32(b.Fee())
	qa, qb := xdr.SequenceNumber(a.SeqNum()), xdr.SequenceNumber(b.SeqNum())
	ca, cb := a.Preconditions(), b.Preconditions()
	ma, mb := a.Memo(), b.Memo()
	ea, eb := ext(a), ext(b)
	fields := []struct {
		name string
		x, y []byte
	}{
		{"source_account", enc(sa), enc(sb)},
		{"fee", enc(fa), enc(fb)},
		{"seq_num", enc(qa), enc(qb)},
		{"cond", enc(ca), enc(cb)},
		{"memo", enc(ma), enc(mb)},
		{"operations", opsOf(a), opsOf(b)},
		{"ext", enc(ea), enc(eb)},
	}
	var out []string
	for _, f := range fields {
		if !bytes.Equal(f.x, f.y) {
			out = append(out, f.name)
		}
	}
	return out
}

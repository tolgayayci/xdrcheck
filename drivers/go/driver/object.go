package driver

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stellar/go-stellar-sdk/xdr"
)

const parseEntry = "txnbuild.TransactionFromXDR"

// levelObject is L1: the bytes go through the SDK's transaction object layer. A TransactionEnvelope is parsed
// with txnbuild.TransactionFromXDR (which decodes the base64 itself); a ledger is decoded with the strict
// entry point and every envelope of its transaction set, in apply order, is handed to the same parser. The
// transaction hashes read back are computed under the request's passphrase; for a passphrase-independent
// envelope (no passphrase in the request) the hash is left out, because the SDK refuses an empty passphrase.
func levelObject(in *input, raw []byte) result {
	_, goName, found := newValue(in.XDRType)
	if !found {
		return notApplicable("type_not_generated", "the driver does not decode "+in.XDRType)
	}
	switch goName {
	case "TransactionEnvelope", "LedgerCloseMeta", "LedgerCloseMetaBatch":
	default:
		return notApplicable("no_object_layer", "go-stellar-sdk has no object parser for "+goName)
	}
	if goName == "TransactionEnvelope" {
		return envelopeObject(raw, in.Passphrase, in.Focus)
	}
	v, rej := decodeStrict(goName, raw)
	if rej != nil {
		return *rej
	}
	var metas []xdr.LedgerCloseMeta
	if lcm, isLCM := v.(*xdr.LedgerCloseMeta); isLCM {
		metas = []xdr.LedgerCloseMeta{*lcm}
	} else {
		metas = v.(*xdr.LedgerCloseMetaBatch).LedgerCloseMetas
	}
	return ledgerObject(metas, in.Passphrase, in.Focus)
}

// envelopeObject parses one envelope and reads back its hash, operations, derived facts and re-encoding. Each
// operation is also rebuilt through its txnbuild object (BuildXDR); an operation that does not come back
// byte-identical is a self-evident object round-trip mismatch. Derived facts are those of the operation the
// request's focus.op_index names, or of the only operation.
func envelopeObject(raw []byte, passphrase string, f *focus) result {
	gt, err := txnbuild.TransactionFromXDR(base64.StdEncoding.EncodeToString(raw))
	if err != nil {
		return reject(classifyObject(err, len(raw)), parseEntry, err)
	}
	// The SDK refuses to hash under an empty passphrase, so a passphrase-independent envelope is reported
	// without a transaction hash.
	var txHash string
	if passphrase != "" {
		h, err := gt.Hash(passphrase)
		if err != nil {
			return reject("object_validation", "GenericTransaction.Hash", err)
		}
		txHash = hex.EncodeToString(h[:])
	}
	if err := checkPools(gt); err != nil {
		return reject(classifyObject(err, len(raw)), poolEntry, err)
	}
	var env xdr.TransactionEnvelope
	if err := xdr.SafeUnmarshal(raw, &env); err != nil {
		return reject(classifyDecode(err, len(raw), "TransactionEnvelope"), "xdr.SafeUnmarshal(TransactionEnvelope)", err)
	}
	ops := parsedOperations(gt)
	op := -1
	switch {
	case f != nil && f.OpIndex != nil:
		op = *f.OpIndex
		if op >= len(ops) {
			return protocolError(fmt.Sprintf("focus.op_index %d: the transaction has %d operations", op, len(ops)))
		}
	case len(ops) == 1:
		op = 0
	}
	out, err := gt.MarshalBinary()
	if err != nil {
		return reject("object_validation", "GenericTransaction.MarshalBinary", err)
	}
	sum := sha256.Sum256(out)
	xops := env.Operations()
	obj := map[string]any{
		"operation_types":  operationTypes(xops),
		"operations":       len(xops),
		"reencoded_sha256": hex.EncodeToString(sum[:]),
		"derived":          deriveFacts(gt, op),
	}
	if txHash != "" {
		obj["tx_hash"] = txHash
		obj["rebuild"] = rebuildFact(gt, passphrase)
	}
	actual := map[string]any{"object": obj}
	if !bytes.Equal(out, raw) {
		return result{Outcome: "diverge", Reason: &reason{Code: "object_reencode_mismatch", EntryPoint: "GenericTransaction.MarshalBinary"}, Actual: actual}
	}
	if len(ops) != len(xops) {
		return result{Outcome: "diverge", Reason: &reason{Code: "object_reencode_mismatch", EntryPoint: parseEntry,
			Message: fmt.Sprintf("the transaction object has %d operations, the envelope %d", len(ops), len(xops))}, Actual: actual}
	}
	for i, o := range ops {
		built, err := o.BuildXDR()
		if err != nil {
			return outcomeWithActual(reject("object_validation", fmt.Sprintf("%T.BuildXDR", o), fmt.Errorf("operation %d: %w", i, err)), actual)
		}
		a, _ := built.MarshalBinary()
		b, _ := xops[i].MarshalBinary()
		if !bytes.Equal(a, b) {
			return result{Outcome: "diverge", Reason: &reason{Code: "object_reencode_mismatch", EntryPoint: fmt.Sprintf("%T.BuildXDR", o),
				Message: fmt.Sprintf("operation %d does not rebuild byte-identical", i)}, Actual: actual}
		}
	}
	return ok(actual)
}

const poolEntry = "txnbuild.NewLiquidityPoolId"

// checkPools reads the pool ID of every pool-share ChangeTrust line of a parsed transaction back through the
// object API, as an application holding the parsed transaction does; the SDK's asset-order check lives there
// in some versions.
func checkPools(gt *txnbuild.GenericTransaction) error {
	for i, op := range parsedOperations(gt) {
		if _, err := poolOf(op); err != nil {
			return fmt.Errorf("operation %d (change_trust pool share): %w", i, err)
		}
	}
	return nil
}

// poolOf returns the pool ID an operation names ("" when none): the one the SDK computes for a pool-share
// ChangeTrust line, or the ID a liquidity-pool deposit or withdrawal carries.
func poolOf(op txnbuild.Operation) (string, error) {
	switch o := op.(type) {
	case *txnbuild.ChangeTrust:
		line, isPool := o.Line.(txnbuild.LiquidityPoolShareChangeTrustAsset)
		if !isPool {
			return "", nil
		}
		p := line.LiquidityPoolParameters
		id, err := txnbuild.NewLiquidityPoolId(p.AssetA, p.AssetB)
		if err != nil {
			return "", err
		}
		return hex.EncodeToString(id[:]), nil
	case *txnbuild.LiquidityPoolDeposit:
		return hex.EncodeToString(o.LiquidityPoolID[:]), nil
	case *txnbuild.LiquidityPoolWithdraw:
		return hex.EncodeToString(o.LiquidityPoolID[:]), nil
	}
	return "", nil
}

func outcomeWithActual(r result, actual map[string]any) result {
	r.Actual = actual
	return r
}

func parsedOperations(gt *txnbuild.GenericTransaction) []txnbuild.Operation {
	if tx := innerTx(gt); tx != nil {
		return tx.Operations()
	}
	return nil
}

// innerTx is the transaction a generic transaction carries: itself, or a fee bump's inner transaction.
func innerTx(gt *txnbuild.GenericTransaction) *txnbuild.Transaction {
	if tx, isTx := gt.Transaction(); isTx {
		return tx
	}
	if fb, isFB := gt.FeeBump(); isFB {
		return fb.InnerTransaction()
	}
	return nil
}

// operationTypes are the operations' XDR-JSON arm names (change_trust), in operation order.
func operationTypes(ops []xdr.Operation) []string {
	types := make([]string, len(ops))
	for i, op := range ops {
		types[i] = enumName(op.Body.Type)
	}
	return types
}

func assetText(a txnbuild.Asset) string {
	if a == nil {
		return ""
	}
	if a.IsNative() {
		return "native"
	}
	return a.GetCode() + ":" + a.GetIssuer()
}

// muxedID is the decimal ID of an M address, or "".
func muxedID(addr string) string {
	if !strings.HasPrefix(addr, "M") {
		return ""
	}
	m, err := xdr.AddressToMuxedAccount(addr)
	if err != nil {
		return ""
	}
	id, err := m.GetId()
	if err != nil {
		return ""
	}
	return strconv.FormatUint(id, 10)
}

// deriveFacts reads the derived facts back through the parsed transaction object: the transaction's memo type
// and, when op is a valid index, that operation's type, effective source, pool ID, asset, address, muxed ID and
// offer ID, each only where the operation has one.
func deriveFacts(gt *txnbuild.GenericTransaction, op int) map[string]string {
	d := map[string]string{}
	tx := innerTx(gt)
	if tx == nil {
		return d
	}
	switch tx.Memo().(type) {
	case nil:
		d["memo_type"] = "none"
	case txnbuild.MemoText:
		d["memo_type"] = "text"
	case txnbuild.MemoID:
		d["memo_type"] = "id"
	case txnbuild.MemoHash:
		d["memo_type"] = "hash"
	case txnbuild.MemoReturn:
		d["memo_type"] = "return"
	}
	ops := tx.Operations()
	if op < 0 || op >= len(ops) {
		return d
	}
	o := ops[op]
	if built, err := o.BuildXDR(); err == nil {
		d["operation_type"] = enumName(built.Body.Type)
	}
	// operation_source is the operation's own source (none when it inherits the transaction's).
	src := o.GetSourceAccount()
	if src != "" {
		d["operation_source"] = src
	}
	if p, err := poolOf(o); err == nil && p != "" {
		d["pool_id"] = p
	}
	var asset txnbuild.Asset
	address := ""
	switch t := o.(type) {
	case *txnbuild.ChangeTrust:
		if _, isPool := t.Line.(txnbuild.LiquidityPoolShareChangeTrustAsset); !isPool && t.Line != nil {
			if t.Line.IsNative() {
				d["asset"] = "native"
			} else {
				d["asset"] = t.Line.GetCode() + ":" + t.Line.GetIssuer()
			}
		}
	case *txnbuild.Payment:
		asset, address = t.Asset, t.Destination
	case *txnbuild.CreateClaimableBalance:
		asset = t.Asset
	case *txnbuild.Clawback:
		asset, address = t.Asset, t.From
	case *txnbuild.CreateAccount:
		address = t.Destination
	case *txnbuild.AccountMerge:
		address = t.Destination
	case *txnbuild.PathPaymentStrictReceive:
		asset, address = t.DestAsset, t.Destination
	case *txnbuild.PathPaymentStrictSend:
		asset, address = t.DestAsset, t.Destination
	case *txnbuild.AllowTrust:
		address = t.Trustor
	case *txnbuild.SetTrustLineFlags:
		asset, address = t.Asset, t.Trustor
	case *txnbuild.BeginSponsoringFutureReserves:
		address = t.SponsoredID
	case *txnbuild.ManageSellOffer:
		d["offer_id"] = strconv.FormatInt(t.OfferID, 10)
	case *txnbuild.ManageBuyOffer:
		d["offer_id"] = strconv.FormatInt(t.OfferID, 10)
	}
	if s := assetText(asset); s != "" {
		d["asset"] = s
	}
	if address != "" {
		d["address"] = address
	}
	if id := muxedID(address); id != "" {
		d["muxed_id"] = id
	} else if id := muxedID(src); id != "" {
		d["muxed_id"] = id
	}
	return d
}

// appliedEnvelope is one envelope of a ledger, placed at its apply-order index.
type appliedEnvelope struct {
	env        xdr.TransactionEnvelope
	index      int    // apply order, across the ledgers of a batch
	resultHash string // the transaction hash the ledger records in its result pair
}

// applyOrder places each envelope of the ledger's transaction set at its position in the transaction
// processing list (apply order), matching the envelope's hash with the hash each result pair records. An
// envelope that matches no result pair fills the first free position, in set order.
func applyOrder(lcm xdr.LedgerCloseMeta, passphrase string, base int) []appliedEnvelope {
	n := lcm.CountTransactions()
	envs := lcm.TransactionEnvelopes()
	slots := make([]*xdr.TransactionEnvelope, n)
	byHash := map[xdr.Hash]int{}
	for i := 0; i < n; i++ {
		byHash[lcm.TransactionHash(i)] = i
	}
	var unplaced []int
	for j := range envs {
		h, err := network.HashTransactionInEnvelope(envs[j], passphrase)
		i, found := byHash[h]
		if err != nil || !found || slots[i] != nil {
			unplaced = append(unplaced, j)
			continue
		}
		slots[i] = &envs[j]
	}
	out := make([]appliedEnvelope, 0, len(envs))
	for i := 0; i < n; i++ {
		if slots[i] == nil && len(unplaced) > 0 {
			slots[i] = &envs[unplaced[0]]
			unplaced = unplaced[1:]
		}
		if slots[i] != nil {
			rh := lcm.TransactionHash(i)
			out = append(out, appliedEnvelope{env: *slots[i], index: base + i, resultHash: hex.EncodeToString(rh[:])})
		}
	}
	for k, j := range unplaced {
		h, _ := network.HashTransactionInEnvelope(envs[j], passphrase)
		out = append(out, appliedEnvelope{env: envs[j], index: base + n + k, resultHash: hex.EncodeToString(h[:])})
	}
	return out
}

// ledgerObject parses every envelope of every ledger, in apply order, through txnbuild.TransactionFromXDR and
// hashes it under the passphrase. The outcome is ok only if all parse; otherwise reject with the first failure
// in apply order, and every failure listed. With a focus naming a transaction (focus.tx_index, apply order),
// the facts of that transaction and of its operation focus.op_index are read back too.
func ledgerObject(metas []xdr.LedgerCloseMeta, passphrase string, f *focus) result {
	hashes := []string{}
	var rejected []map[string]any
	var first *result
	var focusObj map[string]any
	transactions, operations, parsed, base := 0, 0, 0, 0
	focusSeen := false
	for _, lcm := range metas {
		n := lcm.CountTransactions()
		transactions += n
		placed := map[int]bool{}
		for _, ae := range applyOrder(lcm, passphrase, base) {
			placed[ae.index] = true
			raw, err := ae.env.MarshalBinary()
			if err != nil {
				return reject("other", "TransactionEnvelope.MarshalBinary", err)
			}
			entry := parseEntry
			gt, perr := txnbuild.TransactionFromXDR(base64.StdEncoding.EncodeToString(raw))
			var h [32]byte
			if perr == nil {
				entry = "GenericTransaction.Hash"
				h, perr = gt.Hash(passphrase)
			}
			if perr == nil {
				entry = poolEntry
				perr = checkPools(gt)
			}
			isFocus := f != nil && f.TxIndex != nil && *f.TxIndex == ae.index
			focusSeen = focusSeen || isFocus
			if perr != nil {
				code := classifyObject(perr, len(raw))
				rejected = append(rejected, map[string]any{"tx_index": ae.index, "tx_hash": ae.resultHash, "code": code, "message": trim(perr.Error())})
				if first == nil {
					r := reject(code, entry, fmt.Errorf("transaction %d in apply order: %w", ae.index, perr))
					first = &r
				}
				continue
			}
			hashes = append(hashes, hex.EncodeToString(h[:]))
			parsed++
			operations += len(parsedOperations(gt))
			if isFocus {
				op := -1
				if f.OpIndex != nil {
					op = *f.OpIndex
				}
				focusObj = map[string]any{
					"tx_hash":         hex.EncodeToString(h[:]),
					"operation_types": operationTypes(ae.env.Operations()),
					"derived":         deriveFacts(gt, op),
					"rebuild":         rebuildFact(gt, passphrase),
				}
			}
		}
		// A processed transaction whose envelope the transaction set does not hold cannot be parsed: it is
		// rejected, so that parsed and rejected envelopes still add up to the ledger's transactions.
		for i := 0; i < n; i++ {
			if placed[base+i] {
				continue
			}
			rh := lcm.TransactionHash(i)
			err := fmt.Errorf("transaction %d in apply order: the transaction set holds no envelope for it", base+i)
			rejected = append(rejected, map[string]any{"tx_index": base + i, "tx_hash": hex.EncodeToString(rh[:]), "code": "object_validation", "message": err.Error()})
			if first == nil {
				r := reject("object_validation", "LedgerCloseMeta.TransactionEnvelopes", err)
				first = &r
			}
		}
		base += n
	}
	if f != nil && f.TxIndex != nil && !focusSeen {
		return protocolError(fmt.Sprintf("focus.tx_index %d: the ledger has %d transactions", *f.TxIndex, transactions))
	}
	obj := map[string]any{"transactions": transactions, "envelopes_parsed": parsed, "tx_hashes": hashes}
	if rejected != nil {
		obj["envelopes_rejected"] = rejected
		return outcomeWithActual(*first, map[string]any{"object": obj})
	}
	obj["operations"] = operations
	if focusObj != nil {
		obj["focus"] = focusObj
	}
	return ok(map[string]any{"object": obj})
}

// classifyObject maps a txnbuild parse error to a reason code: decode failures as at L0, the asset-order
// check as ordering, anything else the object layer refused as object_validation.
func classifyObject(err error, inputLen int) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "unable to unmarshal transaction envelope"):
		return classifyDecode(err, inputLen, "TransactionEnvelope")
	case strings.Contains(msg, "AssetA must be") || strings.Contains(msg, "lexicographic"):
		return "ordering"
	}
	return "object_validation"
}

package walletbackend

import (
	"context"
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/tolgayayci/xdrcheck/go/internal/lake"
	"github.com/tolgayayci/xdrcheck/go/internal/rig"
)

// A generated lake: a contract that existed before the run (bound to wasm V) is touched in ledger 101; ledger 102
// uploads wasm W and deploys contract N bound to W; ledger 103 changes N's instance and rebinds the old contract
// to W. The seed must not pre-register W or N (live ingestion sees both happen), and keeps the old contract's
// pre-run binding V. Of the two Stellar Asset Contracts only the pre-existing one is seeded.
func TestSeedSkipsContractsDeployedDuringTheRun(t *testing.T) {
	pass := network.TestNetworkPassphrase
	var old, deployed xdr.ContractId
	old[0], deployed[0] = 1, 2
	var v, w xdr.Hash
	v[0], w[0] = 0xaa, 0xbb

	instance := func(c xdr.ContractId, h xdr.Hash) xdr.LedgerEntry {
		return xdr.LedgerEntry{Data: xdr.LedgerEntryData{Type: xdr.LedgerEntryTypeContractData, ContractData: &xdr.ContractDataEntry{
			Contract:   xdr.ScAddress{Type: xdr.ScAddressTypeScAddressTypeContract, ContractId: &c},
			Key:        xdr.ScVal{Type: xdr.ScValTypeScvLedgerKeyContractInstance},
			Durability: xdr.ContractDataDurabilityPersistent,
			Val: xdr.ScVal{Type: xdr.ScValTypeScvContractInstance, Instance: &xdr.ScContractInstance{
				Executable: xdr.ContractExecutable{Type: xdr.ContractExecutableTypeContractExecutableWasm, WasmHash: &h}}},
		}}}
	}
	code := func(h xdr.Hash) xdr.LedgerEntry {
		return xdr.LedgerEntry{Data: xdr.LedgerEntryData{Type: xdr.LedgerEntryTypeContractCode,
			ContractCode: &xdr.ContractCodeEntry{Hash: h, Code: []byte{0, 'a', 's', 'm'}}}}
	}
	created := func(e xdr.LedgerEntry) xdr.LedgerEntryChange {
		return xdr.LedgerEntryChange{Type: xdr.LedgerEntryChangeTypeLedgerEntryCreated, Created: &e}
	}
	updated := func(pre, post xdr.LedgerEntry) []xdr.LedgerEntryChange {
		return []xdr.LedgerEntryChange{{Type: xdr.LedgerEntryChangeTypeLedgerEntryState, State: &pre},
			{Type: xdr.LedgerEntryChangeTypeLedgerEntryUpdated, Updated: &post}}
	}
	// Stellar Asset Contracts: USD's existed before the run (its instance changes in 101, its trustline is in the
	// ledger); the native one is deployed in 102.
	usd := xdr.MustNewCreditAsset("USD", "GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H")
	usdID, _ := usd.ContractID(pass)
	nativeID, _ := xdr.MustNewNativeAsset().ContractID(pass)
	sacInstance := func(c xdr.ContractId) xdr.LedgerEntry {
		e := instance(c, v)
		e.Data.ContractData.Val.Instance.Executable = xdr.ContractExecutable{Type: xdr.ContractExecutableTypeContractExecutableStellarAsset}
		return e
	}
	var holder xdr.AccountId
	holder.SetAddress("GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H")
	tl := xdr.LedgerEntry{Data: xdr.LedgerEntryData{Type: xdr.LedgerEntryTypeTrustline, TrustLine: &xdr.TrustLineEntry{
		AccountId: holder, Asset: usd.ToTrustLineAsset(), Limit: 1}}}
	ledgers := map[uint32][]xdr.LedgerEntryChange{
		101: append(append(updated(instance(old, v), instance(old, v)), updated(sacInstance(usdID), sacInstance(usdID))...), updated(tl, tl)...),
		102: {created(code(w)), created(instance(deployed, w)), created(sacInstance(nativeID))},
		103: append(updated(instance(deployed, w), instance(deployed, w)), updated(instance(old, v), instance(old, w))...),
	}
	var objs []lake.Ledger
	for seq := uint32(101); seq <= 103; seq++ {
		b := oneTxLedger(t, pass, seq, ledgers[seq])
		objs = append(objs, lake.Ledger{Seq: seq, Load: func() ([]byte, error) { return b, nil }})
	}
	dir := t.TempDir()
	if _, err := lake.Write(dir, lake.NewConfig(pass), objs); err != nil {
		t.Fatal(err)
	}
	lk, err := rig.OpenLake(dir, pass, "", "")
	if err != nil {
		t.Fatal(err)
	}
	var infos []*rig.LedgerInfo
	for seq := uint32(101); seq <= 103; seq++ {
		raw, err := lk.Load(context.Background(), seq)
		if err != nil {
			t.Fatal(err)
		}
		in, err := rig.Analyze(pass, raw)
		if err != nil {
			t.Fatal(err)
		}
		infos = append(infos, in)
	}
	cs := func(c xdr.ContractId) string { return strkey.MustEncode(strkey.VersionByteContract, c[:]) }
	if !infos[1].InstancesCreated[cs(deployed)] || !infos[1].WasmsUploaded[hex.EncodeToString(w[:])] {
		t.Fatalf("ledger 102: deploy not seen: %+v %+v", infos[1].InstancesCreated, infos[1].WasmsUploaded)
	}
	seed := map[string]string{cs(old): hex.EncodeToString(w[:]), cs(deployed): hex.EncodeToString(w[:])}
	wasms, bound := seedBindings(infos, func(c string) (string, bool) { h, ok := seed[c]; return h, ok })
	if want := []string{hex.EncodeToString(v[:])}; !reflect.DeepEqual(wasms, want) {
		t.Errorf("wasms = %v, want %v", wasms, want)
	}
	if want := map[string]string{cs(old): hex.EncodeToString(v[:])}; !reflect.DeepEqual(bound, want) {
		t.Errorf("bound = %v, want %v", bound, want)
	}
	if got, want := seedSACs(infos), map[string]string{cs(usdID): "USD:GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H"}; !reflect.DeepEqual(got, want) {
		t.Errorf("SAC rows = %v, want %v (the native SAC is deployed in the run)", got, want)
	}
}

// oneTxLedger is a LedgerCloseMeta v1 with one transaction whose single operation made the given changes.
func oneTxLedger(t *testing.T, pass string, seq uint32, changes []xdr.LedgerEntryChange) []byte {
	t.Helper()
	var src xdr.Uint256
	src[0] = byte(seq)
	env := xdr.TransactionEnvelope{Type: xdr.EnvelopeTypeEnvelopeTypeTx, V1: &xdr.TransactionV1Envelope{Tx: xdr.Transaction{
		SourceAccount: xdr.MuxedAccount{Type: xdr.CryptoKeyTypeKeyTypeEd25519, Ed25519: &src},
		Fee:           100, SeqNum: xdr.SequenceNumber(seq),
		Operations: []xdr.Operation{{Body: xdr.OperationBody{Type: xdr.OperationTypeBumpSequence,
			BumpSequenceOp: &xdr.BumpSequenceOp{}}}},
	}}}
	h, err := network.HashTransactionInEnvelope(env, pass)
	if err != nil {
		t.Fatal(err)
	}
	opRes := []xdr.OperationResult{{Code: xdr.OperationResultCodeOpInner, Tr: &xdr.OperationResultTr{
		Type: xdr.OperationTypeBumpSequence, BumpSeqResult: &xdr.BumpSequenceResult{Code: xdr.BumpSequenceResultCodeBumpSequenceSuccess}}}}
	base := xdr.Int64(100)
	lcm := xdr.LedgerCloseMeta{V: 1, V1: &xdr.LedgerCloseMetaV1{
		LedgerHeader: xdr.LedgerHeaderHistoryEntry{Header: xdr.LedgerHeader{LedgerSeq: xdr.Uint32(seq), LedgerVersion: 23}},
		TxSet: xdr.GeneralizedTransactionSet{V: 1, V1TxSet: &xdr.TransactionSetV1{Phases: []xdr.TransactionPhase{{V: 0,
			V0Components: &[]xdr.TxSetComponent{{Type: xdr.TxSetComponentTypeTxsetCompTxsMaybeDiscountedFee,
				TxsMaybeDiscountedFee: &xdr.TxSetComponentTxsMaybeDiscountedFee{BaseFee: &base, Txs: []xdr.TransactionEnvelope{env}}}}}}}},
		TxProcessing: []xdr.TransactionResultMeta{{
			Result: xdr.TransactionResultPair{TransactionHash: h, Result: xdr.TransactionResult{FeeCharged: 100,
				Result: xdr.TransactionResultResult{Code: xdr.TransactionResultCodeTxSuccess, Results: &opRes}}},
			TxApplyProcessing: xdr.TransactionMeta{V: 3, V3: &xdr.TransactionMetaV3{
				Operations: []xdr.OperationMeta{{Changes: changes}}}},
		}},
	}}
	b, err := lcm.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

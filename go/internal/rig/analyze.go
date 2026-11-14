package rig

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/stellar/go-stellar-sdk/ingest"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// LedgerInfo is what a ledger holds, read with the SDK's own readers: the expectations an export is checked
// against, and the contracts and assets a seed is built from.
type LedgerInfo struct {
	Seq       uint32 `json:"ledger"`
	Hash      string `json:"hash"`
	Protocol  uint32 `json:"protocol"`
	CloseTime int64  `json:"close_time"`
	Txs       []TxInfo
	// Keys changed in the ledger by entry type (`account`, `trustline`, …): base64 LedgerKey → change kinds seen.
	Changes map[string]map[string][]string `json:"-"`
	// Contracts that emitted an event or own a changed contract-data entry (C… strkeys).
	Contracts []string `json:"-"`
	// SAC contracts verified in this ledger: contract → asset (`native` or `CODE:ISSUER`), from assets seen in the
	// ledger whose SAC id (hash of the asset under the passphrase) is one of Contracts.
	SACs map[string]string `json:"-"`
	// Contract instance entries in the ledger's changes: contract → wasm hash (hex) or "" for a SAC.
	Instances map[string]string `json:"-"`
	// InstancesBefore: the binding of a contract instance before the ledger changed it (the pre-image of its
	// first change in the ledger), for contracts that existed before the ledger.
	InstancesBefore map[string]string `json:"-"`
	// InstancesCreated: contracts whose instance entry was created in this ledger (deployed here).
	InstancesCreated map[string]bool `json:"-"`
	// WasmsUploaded: wasm hashes (hex) whose contract-code entry was created in this ledger (uploaded here).
	WasmsUploaded map[string]bool `json:"-"`
	Events        int             `json:"events"`
	// Returns: the return value (base64 ScVal) of every successful zero-argument contract call in the ledger,
	// keyed "contract|function" (name(), symbol(), decimals() and the like), for a simulation stand-in.
	Returns map[string]string `json:"-"`
}

// TxInfo is one transaction in apply order.
type TxInfo struct {
	Index   int    `json:"tx_index"` // 0-based apply order
	Hash    string `json:"tx_hash"`
	Success bool   `json:"success"`
	Ops     int    `json:"ops"`
	Events  int    `json:"events"`
}

// Analyze reads one LedgerCloseMeta.
func Analyze(passphrase string, lcm []byte) (*LedgerInfo, error) {
	var m xdr.LedgerCloseMeta
	if err := m.UnmarshalBinary(lcm); err != nil {
		return nil, fmt.Errorf("decode LedgerCloseMeta: %w", err)
	}
	h := m.LedgerHeaderHistoryEntry()
	info := &LedgerInfo{Seq: m.LedgerSequence(), Hash: m.LedgerHash().HexString(), Protocol: uint32(h.Header.LedgerVersion),
		CloseTime: int64(h.Header.ScpValue.CloseTime), Changes: map[string]map[string][]string{}, SACs: map[string]string{},
		Instances: map[string]string{}, InstancesBefore: map[string]string{}, InstancesCreated: map[string]bool{},
		WasmsUploaded: map[string]bool{}, Returns: map[string]string{}}
	contracts := map[string]bool{}
	assets := map[string]xdr.Asset{}
	addAsset := func(a xdr.Asset) {
		if s, err := assetString(a); err == nil {
			assets[s] = a
		}
	}
	addAsset(xdr.MustNewNativeAsset())

	r, err := ingest.NewLedgerTransactionReaderFromLedgerCloseMeta(passphrase, m)
	if err != nil {
		return nil, err
	}
	for {
		tx, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("ledger %d: read transaction: %w", info.Seq, err)
		}
		ti := TxInfo{Index: int(tx.Index) - 1, Hash: tx.Result.TransactionHash.HexString(), Success: tx.Result.Successful(),
			Ops: len(tx.Envelope.Operations())}
		for _, op := range tx.Envelope.Operations() {
			for _, a := range opAssets(op) {
				addAsset(a)
			}
		}
		if k, v, ok := zeroArgReturn(tx); ok {
			info.Returns[k] = v
		}
		if evs, err := tx.GetContractEvents(); err == nil {
			ti.Events = len(evs)
			for _, e := range evs {
				if e.ContractId != nil {
					contracts[contractStr(*e.ContractId)] = true
				}
				for _, t := range e.Body.V0.Topics {
					if s, ok := t.GetStr(); ok {
						if a, err := parseAsset(string(s)); err == nil {
							addAsset(a)
						}
					}
				}
			}
		}
		info.Events += ti.Events
		info.Txs = append(info.Txs, ti)
	}
	r.Close()

	cr, err := ingest.NewLedgerChangeReaderFromLedgerCloseMeta(passphrase, m)
	if err != nil {
		return nil, err
	}
	for {
		c, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("ledger %d: read change: %w", info.Seq, err)
		}
		k, err := c.LedgerKey()
		if err != nil {
			continue
		}
		kb, err := k.MarshalBinary()
		if err != nil {
			continue
		}
		typ := EntryTypeName(c.Type)
		if info.Changes[typ] == nil {
			info.Changes[typ] = map[string][]string{}
		}
		key := base64.StdEncoding.EncodeToString(kb)
		kind := changeKind(c)
		if !slices.Contains(info.Changes[typ][key], kind) {
			info.Changes[typ][key] = append(info.Changes[typ][key], kind)
		}
		if c.Pre != nil && c.Pre.Data.Type == xdr.LedgerEntryTypeContractData {
			cd := c.Pre.Data.ContractData
			if cd.Key.Type == xdr.ScValTypeScvLedgerKeyContractInstance && cd.Contract.ContractId != nil {
				if h, ok := wasmOf(cd.Val); ok {
					if _, seen := info.InstancesBefore[contractStr(*cd.Contract.ContractId)]; !seen {
						info.InstancesBefore[contractStr(*cd.Contract.ContractId)] = h
					}
				}
			}
		}
		entry := c.Post
		if entry == nil {
			entry = c.Pre
		}
		if entry == nil {
			continue
		}
		created := c.Pre == nil && c.ChangeType != xdr.LedgerEntryChangeTypeLedgerEntryRestored
		switch entry.Data.Type {
		case xdr.LedgerEntryTypeContractCode:
			if created {
				info.WasmsUploaded[hex.EncodeToString(entry.Data.ContractCode.Hash[:])] = true
			}
		case xdr.LedgerEntryTypeTrustline:
			if a, ok := trustAsset(entry.Data.TrustLine.Asset); ok {
				addAsset(a)
			}
		case xdr.LedgerEntryTypeContractData:
			cd := entry.Data.ContractData
			if cd.Contract.Type == xdr.ScAddressTypeScAddressTypeContract && cd.Contract.ContractId != nil {
				cid := contractStr(*cd.Contract.ContractId)
				contracts[cid] = true
				if cd.Key.Type == xdr.ScValTypeScvLedgerKeyContractInstance {
					if created {
						info.InstancesCreated[cid] = true
					}
					if inst, ok := cd.Val.GetInstance(); ok {
						switch inst.Executable.Type {
						case xdr.ContractExecutableTypeContractExecutableStellarAsset:
							info.Instances[cid] = ""
						case xdr.ContractExecutableTypeContractExecutableWasm:
							if inst.Executable.WasmHash != nil {
								info.Instances[cid] = hex.EncodeToString(inst.Executable.WasmHash[:])
							}
						}
					}
				}
			}
		}
	}
	cr.Close()

	for s, a := range assets {
		id, err := a.ContractID(passphrase)
		if err != nil {
			continue
		}
		cid := contractStr(id)
		if contracts[cid] {
			info.SACs[cid] = s
		}
	}
	for c := range contracts {
		info.Contracts = append(info.Contracts, c)
	}
	slices.Sort(info.Contracts)
	return info, nil
}

func changeKind(c ingest.Change) string {
	switch {
	case c.Pre == nil && c.Post != nil:
		if c.ChangeType == xdr.LedgerEntryChangeTypeLedgerEntryRestored {
			return "restored"
		}
		return "created"
	case c.Pre != nil && c.Post == nil:
		return "removed"
	default:
		return "updated"
	}
}

// EntryTypeName is the lower-case short name of an entry type, as the rows use it.
func EntryTypeName(t xdr.LedgerEntryType) string {
	switch t {
	case xdr.LedgerEntryTypeAccount:
		return "account"
	case xdr.LedgerEntryTypeTrustline:
		return "trustline"
	case xdr.LedgerEntryTypeOffer:
		return "offer"
	case xdr.LedgerEntryTypeData:
		return "data"
	case xdr.LedgerEntryTypeClaimableBalance:
		return "claimable_balance"
	case xdr.LedgerEntryTypeLiquidityPool:
		return "liquidity_pool"
	case xdr.LedgerEntryTypeContractData:
		return "contract_data"
	case xdr.LedgerEntryTypeContractCode:
		return "contract_code"
	case xdr.LedgerEntryTypeConfigSetting:
		return "config_setting"
	case xdr.LedgerEntryTypeTtl:
		return "ttl"
	}
	return fmt.Sprintf("type_%d", int32(t))
}

func contractStr(id xdr.ContractId) string {
	s, _ := strkey.Encode(strkey.VersionByteContract, id[:])
	return s
}

func assetString(a xdr.Asset) (string, error) {
	if a.Type == xdr.AssetTypeAssetTypeNative {
		return "native", nil
	}
	var typ, code, issuer string
	if err := a.Extract(&typ, &code, &issuer); err != nil {
		return "", err
	}
	return code + ":" + issuer, nil
}

func parseAsset(s string) (xdr.Asset, error) {
	if s == "native" {
		return xdr.MustNewNativeAsset(), nil
	}
	a, err := xdr.BuildAssets(s)
	if err != nil || len(a) != 1 {
		return xdr.Asset{}, fmt.Errorf("not an asset: %q", s)
	}
	return a[0], nil
}

func trustAsset(t xdr.TrustLineAsset) (xdr.Asset, bool) {
	switch t.Type {
	case xdr.AssetTypeAssetTypeCreditAlphanum4, xdr.AssetTypeAssetTypeCreditAlphanum12:
		return t.ToAsset(), true
	}
	return xdr.Asset{}, false
}

// opAssets lists the assets an operation names.
func opAssets(op xdr.Operation) []xdr.Asset {
	b := op.Body
	var out []xdr.Asset
	switch b.Type {
	case xdr.OperationTypePayment:
		out = append(out, b.PaymentOp.Asset)
	case xdr.OperationTypePathPaymentStrictReceive:
		out = append(out, b.PathPaymentStrictReceiveOp.SendAsset, b.PathPaymentStrictReceiveOp.DestAsset)
		out = append(out, b.PathPaymentStrictReceiveOp.Path...)
	case xdr.OperationTypePathPaymentStrictSend:
		out = append(out, b.PathPaymentStrictSendOp.SendAsset, b.PathPaymentStrictSendOp.DestAsset)
		out = append(out, b.PathPaymentStrictSendOp.Path...)
	case xdr.OperationTypeManageSellOffer:
		out = append(out, b.ManageSellOfferOp.Selling, b.ManageSellOfferOp.Buying)
	case xdr.OperationTypeManageBuyOffer:
		out = append(out, b.ManageBuyOfferOp.Selling, b.ManageBuyOfferOp.Buying)
	case xdr.OperationTypeCreatePassiveSellOffer:
		out = append(out, b.CreatePassiveSellOfferOp.Selling, b.CreatePassiveSellOfferOp.Buying)
	case xdr.OperationTypeChangeTrust:
		if b.ChangeTrustOp.Line.Type != xdr.AssetTypeAssetTypePoolShare {
			out = append(out, b.ChangeTrustOp.Line.ToAsset())
		}
	case xdr.OperationTypeCreateClaimableBalance:
		out = append(out, b.CreateClaimableBalanceOp.Asset)
	case xdr.OperationTypeClawback:
		out = append(out, b.ClawbackOp.Asset)
	case xdr.OperationTypeInvokeHostFunction:
		hf := b.InvokeHostFunctionOp.HostFunction
		if hf.Type == xdr.HostFunctionTypeHostFunctionTypeCreateContract || hf.Type == xdr.HostFunctionTypeHostFunctionTypeCreateContractV2 {
			var pre xdr.ContractIdPreimage
			if hf.CreateContract != nil {
				pre = hf.CreateContract.ContractIdPreimage
			} else if hf.CreateContractV2 != nil {
				pre = hf.CreateContractV2.ContractIdPreimage
			}
			if pre.FromAsset != nil {
				out = append(out, *pre.FromAsset)
			}
		}
	}
	return out
}

// zeroArgReturn gives "contract|function" and the base64 return value of a successful one-operation
// InvokeContract call with no arguments.
func zeroArgReturn(tx ingest.LedgerTransaction) (string, string, bool) {
	if !tx.Result.Successful() {
		return "", "", false
	}
	ops := tx.Envelope.Operations()
	if len(ops) != 1 || ops[0].Body.Type != xdr.OperationTypeInvokeHostFunction {
		return "", "", false
	}
	hf := ops[0].Body.InvokeHostFunctionOp.HostFunction
	if hf.Type != xdr.HostFunctionTypeHostFunctionTypeInvokeContract || hf.InvokeContract == nil || len(hf.InvokeContract.Args) != 0 {
		return "", "", false
	}
	addr := hf.InvokeContract.ContractAddress
	if addr.Type != xdr.ScAddressTypeScAddressTypeContract || addr.ContractId == nil {
		return "", "", false
	}
	var rv *xdr.ScVal
	switch tx.UnsafeMeta.V {
	case 3:
		if m := tx.UnsafeMeta.V3; m != nil && m.SorobanMeta != nil {
			rv = &m.SorobanMeta.ReturnValue
		}
	case 4:
		if m := tx.UnsafeMeta.V4; m != nil && m.SorobanMeta != nil {
			rv = m.SorobanMeta.ReturnValue
		}
	}
	if rv == nil {
		return "", "", false
	}
	b, err := xdr.MarshalBase64(*rv)
	if err != nil {
		return "", "", false
	}
	return contractStr(*addr.ContractId) + "|" + string(hf.InvokeContract.FunctionName), b, true
}

// wasmOf is the WASM hash (hex) an instance value binds; ok is false for a SAC or a non-instance value.
func wasmOf(v xdr.ScVal) (string, bool) {
	inst, ok := v.GetInstance()
	if !ok || inst.Executable.Type != xdr.ContractExecutableTypeContractExecutableWasm || inst.Executable.WasmHash == nil {
		return "", false
	}
	return hex.EncodeToString(inst.Executable.WasmHash[:]), true
}

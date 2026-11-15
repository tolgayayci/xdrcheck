package ledger

import (
	"strconv"

	"github.com/stellar/go-stellar-sdk/ingest"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// Truth holds values the ledger itself states for one transaction, read from the result and the meta (never
// computed by a helper), so a sweep can judge an SDK's computed values against them. Map keys are operation
// indexes (0-based, decimal).
type Truth struct {
	FeeCharged int64 `json:"fee_charged"`
	Success    bool  `json:"success"`
	// CBIDs: hex of the ClaimableBalanceID XDR in each successful CreateClaimableBalance result.
	CBIDs map[string]string `json:"cb_ids,omitempty"`
	// PoolIDs: hex pool id of the pool-share trustline a successful ChangeTrust changed.
	PoolIDs map[string]string `json:"pool_ids,omitempty"`
	// ContractIDs: C… address of the contract instance a successful InvokeHostFunction created.
	ContractIDs map[string]string `json:"contract_ids,omitempty"`
}

func truthOf(tx ingest.LedgerTransaction) *Truth {
	t := &Truth{FeeCharged: int64(tx.Result.Result.FeeCharged), Success: tx.Result.Successful()}
	if !t.Success {
		return t
	}
	env := tx.Envelope
	ops := env.Operations()
	res, ok := tx.Result.Result.OperationResults()
	if !ok {
		return t
	}
	put := func(m *map[string]string, i int, v string) {
		if *m == nil {
			*m = map[string]string{}
		}
		(*m)[strconv.Itoa(i)] = v
	}
	for i, op := range ops {
		switch op.Body.Type {
		case xdr.OperationTypeCreateClaimableBalance:
			if i < len(res) && res[i].Tr != nil && res[i].Tr.CreateClaimableBalanceResult != nil && res[i].Tr.CreateClaimableBalanceResult.BalanceId != nil {
				if h, err := xdr.MarshalHex(*res[i].Tr.CreateClaimableBalanceResult.BalanceId); err == nil {
					put(&t.CBIDs, i, h)
				}
			}
		case xdr.OperationTypeChangeTrust:
			if op.Body.ChangeTrustOp.Line.Type != xdr.AssetTypeAssetTypePoolShare {
				continue
			}
			chs, err := tx.GetOperationChanges(uint32(i))
			if err != nil {
				continue
			}
			for _, c := range chs {
				if c.Type != xdr.LedgerEntryTypeTrustline {
					continue
				}
				e := c.Post
				if e == nil {
					e = c.Pre
				}
				if e != nil && e.Data.TrustLine != nil && e.Data.TrustLine.Asset.LiquidityPoolId != nil {
					id := *e.Data.TrustLine.Asset.LiquidityPoolId
					put(&t.PoolIDs, i, xdrHex(id[:]))
				}
			}
		case xdr.OperationTypeInvokeHostFunction:
			ht := op.Body.InvokeHostFunctionOp.HostFunction.Type
			if ht != xdr.HostFunctionTypeHostFunctionTypeCreateContract && ht != xdr.HostFunctionTypeHostFunctionTypeCreateContractV2 {
				continue
			}
			chs, err := tx.GetOperationChanges(uint32(i))
			if err != nil {
				continue
			}
			for _, c := range chs {
				if c.Type != xdr.LedgerEntryTypeContractData || c.Pre != nil || c.Post == nil {
					continue
				}
				cd := c.Post.Data.ContractData
				if cd == nil || cd.Key.Type != xdr.ScValTypeScvLedgerKeyContractInstance || cd.Contract.ContractId == nil {
					continue
				}
				id := *cd.Contract.ContractId
				if s, err := strkey.Encode(strkey.VersionByteContract, id[:]); err == nil {
					put(&t.ContractIDs, i, s)
				}
			}
		}
	}
	return t
}

func xdrHex(b []byte) string {
	const d = "0123456789abcdef"
	out := make([]byte, 2*len(b))
	for i, c := range b {
		out[2*i], out[2*i+1] = d[c>>4], d[c&15]
	}
	return string(out)
}

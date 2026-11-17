package xdr203

import "github.com/stellar/go-stellar-sdk/xdr"

const maxAlloc = 1 << 16

func bytesBounded(v xdr.ScVal) []byte {
	if v.U32 == nil {
		return nil
	}
	n := *v.U32
	if n > maxAlloc {
		return nil
	}
	return make([]byte, n)
}

func fromDecoded(vec xdr.ScVec) []string {
	return make([]string, 0, len(vec))
}

// A count of decoded elements is a length, not a decoded integer (the shape
// of a ledger reader sizing its per-transaction buffers).
func perTransaction(lcm xdr.LedgerCloseMeta) []string {
	out := make([]string, 0, lcm.CountTransactions())
	for i := 0; i < lcm.CountTransactions(); i++ {
		out = append(out, "")
	}
	return out
}

func capped(v xdr.ScVal) []byte {
	n, _ := v.GetU32()
	return make([]byte, min(n, 64))
}

func inBound(v xdr.ScVal) []byte {
	n, _ := v.GetU32()
	if n <= maxAlloc {
		return make([]byte, n)
	}
	return nil
}

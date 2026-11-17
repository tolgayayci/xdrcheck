package xdr402

import (
	"math"
	"math/big"
	"strconv"

	"github.com/stellar/go-stellar-sdk/xdr"
)

type wideRow struct {
	MuxedID string
	Reserve int64
	Balance int64
	Ledger  int32
}

// The full width kept as text.
func muxedIDText(m xdr.MuxedAccountMed25519, row *wideRow) {
	row.MuxedID = strconv.FormatUint(uint64(m.Id), 10)
}

// A range check before the conversion.
func muxedIDChecked(m xdr.MuxedAccountMed25519, row *txRow) bool {
	if uint64(m.Id) > math.MaxInt64 {
		return false
	}
	row.SellerMuxedID = int64(m.Id)
	return true
}

// Same width (an xdr.Int64 reserve into int64) is not narrowing; a ledger
// sequence (uint32) into int32 is not reported.
func reserve(pool xdr.LiquidityPoolEntryConstantProduct, seq xdr.Uint32, row *wideRow) {
	row.Reserve = int64(pool.ReserveA)
	row.Ledger = int32(seq)
}

// A big.Int checked before it is narrowed.
func balanceChecked(b *big.Int, row *wideRow) bool {
	if !b.IsInt64() {
		return false
	}
	row.Balance = b.Int64()
	return true
}

type condRow struct {
	MinSeqAge  int64
	MinSeqAge2 int64
}

// A minimum sequence age into a signed 64-bit column: stellar-core admits a
// transaction only while its minSeqAge is at most the ledger's close time,
// so no value a ledger holds reaches 2^63 (the field, and the envelope's
// accessor).
func minSeqAge(env xdr.TransactionEnvelope, c xdr.PreconditionsV2, row *condRow) {
	row.MinSeqAge = int64(c.MinSeqAge)
	if age := env.MinSeqAge(); age != nil {
		row.MinSeqAge2 = int64(*age)
	}
}

package xdr402

import (
	"math/big"
	"strconv"

	"github.com/stellar/go-stellar-sdk/amount"
	"github.com/stellar/go-stellar-sdk/xdr"
)

type txRow struct {
	SellerMuxedID int64
	SetSize       int16
	AmountFloat   float64
	Balance       int64
}

// (a) A muxed ID into a signed 64-bit column: an ID ≥ 2^63 is stored
// negative.
func sellerMuxedID(m xdr.MuxedAccountMed25519, row *txRow) {
	row.SellerMuxedID = int64(m.Id) // want `XDR402 \(error\): int64\(…\) narrows xdr.Uint64 \(uint64\) to int64 with no range check, and the result is stored in field txRow.SellerMuxedID`
}

// (b) A muxed ID into a map of exported details.
func muxedDetails(m xdr.MuxedAccountMed25519, details map[string]interface{}) {
	details["muxed_id"] = int64(m.Id) // want `XDR402 \(error\): int64\(…\) narrows xdr.Uint64 \(uint64\) to int64 .* stored in a map`
}

// (c) A 32-bit header value into a 16-bit column.
func setSize(h xdr.LedgerHeader, row *txRow) {
	row.SetSize = int16(h.MaxTxSetSize) // want `XDR402 \(error\): int16\(…\) narrows xdr.Uint32 \(uint32\) to int16`
}

// (d) An i128 amount rendered to text, parsed back as a float.
func amountFloat(parts xdr.Int128Parts, row *txRow) {
	f, err := strconv.ParseFloat(amount.String128Raw(parts), 64) // want `XDR402 \(warning\): strconv.ParseFloat rounds a token amount to float64`
	if err == nil {
		row.AmountFloat = f
	}
}

// (e) An i128 balance narrowed to 64 bits through big.Int.
func balance(parts xdr.Int128Parts, row *txRow) {
	b := new(big.Int).Lsh(big.NewInt(int64(parts.Hi)), 64)
	b.Add(b, new(big.Int).SetUint64(uint64(parts.Lo)))
	row.Balance = b.Int64() // want `XDR402 \(error\): big.Int.Int64\(\) narrows a wide integer to 64 bits`
}

type ageRow struct {
	MinSeqAge int16
}

// (f) A minimum sequence age is bounded only by the close time, which does
// not fit 16 bits: the exemption covers 64-bit destinations only.
func minSeqAgeNarrow(c xdr.PreconditionsV2, row *ageRow) {
	row.MinSeqAge = int16(c.MinSeqAge) // want `XDR402 \(error\): int16\(…\) narrows a minimum sequence age \(xdr.Duration\) \(uint64\) to int16`
}

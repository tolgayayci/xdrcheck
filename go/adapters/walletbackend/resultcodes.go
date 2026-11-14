package walletbackend

// wallet-backend stores a transaction's result code as the Go enum name of go-stellar-sdk's XDR type
// (TransactionResultCodeTxSuccess). The observation uses the XDR-JSON name (tx_success). The table is built
// once from the XDR enum itself: the Go name is the XDR constant name in CamelCase behind the type's prefix, so
// TransactionResultCodeTxFeeBumpInnerSuccess ↔ txFEE_BUMP_INNER_SUCCESS ↔ tx_fee_bump_inner_success. A label
// that is not in the table is passed through unchanged, so it shows as a wrong value, never as a match.

import (
	"strings"
	"unicode"

	"github.com/stellar/go-stellar-sdk/xdr"
)

var resultCodes = buildResultCodes()

func buildResultCodes() map[string]string {
	m := map[string]string{}
	for v := int32(-64); v <= 64; v++ {
		c := xdr.TransactionResultCode(v)
		if !c.ValidEnum(v) {
			continue
		}
		name := c.String()
		m[name] = snake(strings.TrimPrefix(name, "TransactionResultCode"))
	}
	return m
}

// snake turns TxBadAuthExtra into tx_bad_auth_extra.
func snake(s string) string {
	var b strings.Builder
	for i, r := range s {
		if unicode.IsUpper(r) {
			if i > 0 {
				b.WriteByte('_')
			}
			r = unicode.ToLower(r)
		}
		b.WriteRune(r)
	}
	return b.String()
}

// resultCode maps a stored label to its XDR-JSON name, or returns it unchanged.
func resultCode(label string) string {
	if n, ok := resultCodes[label]; ok {
		return n
	}
	return label
}

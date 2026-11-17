package xdr000

import "github.com/stellar/go-stellar-sdk/xdr"

// storeKey is an account-key sink; the directive is well formed and the key
// is reduced to the base account first.
//
//xdrlint:sink accountkey
func storeKey(keys map[string]bool, a xdr.MuxedAccount) {
	acc := a.ToAccountId()
	keys[acc.Address()] = true
}

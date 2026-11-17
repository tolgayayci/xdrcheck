package xdr102sink

import (
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/tolgayayci/xdrcheck/lint/testdata/xdr1xx/xdr102sink/keys"
)

// A column type whose Value() stores the base key of an M… or W… address and
// refuses every other payload: the identity is the base account whatever
// kind the string has.
func normalisedHolder(addr xdr.ScAddress) (row, error) {
	s, err := addr.String()
	if err != nil {
		return row{}, err
	}
	return row{Holder: keys.NormalisedKey(s)}, nil
}

// A participant setter whose argument only becomes a NormalisedKey.
func normalisedSetter(addr xdr.ScAddress, b keys.Builder) (keys.Builder, error) {
	s, err := addr.String()
	if err != nil {
		return b, err
	}
	return b.WithAccount(s), nil
}

// An address read from contract storage cannot be a claimable balance, a
// liquidity pool or muxed: the host refuses to store them.
func storageHolder(entry xdr.ContractDataEntry) (row, bool) {
	s, ok := addrOf(entry.Val)
	return row{Holder: keys.RawKey(s)}, ok
}

// An event of a protocol's own (its name is one the Stellar Asset Contract
// never emits): a contract emitted it, so its addresses cannot be claimable
// balances or pools, and NormalisedKey reduces the muxed forms.
func protocolEventHolder(ev xdr.ContractEvent) (row, bool) {
	if len(ev.Body.V0.Topics) < 2 {
		return row{}, false
	}
	sym, ok := ev.Body.V0.Topics[0].GetSym()
	if !ok {
		return row{}, false
	}
	switch string(sym) {
	case "supply":
		return eventRow(ev)
	}
	return row{}, false
}

func eventRow(ev xdr.ContractEvent) (row, bool) {
	s, ok := addrOf(ev.Body.V0.Topics[1])
	return row{Holder: keys.NormalisedKey(s)}, ok
}

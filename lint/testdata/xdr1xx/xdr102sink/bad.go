package xdr102sink

import (
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/tolgayayci/xdrcheck/lint/testdata/xdr1xx/xdr102sink/keys"
)

type row struct {
	Holder any
}

// (a) A column type that stores the string as given: M… splits the account.
func rawHolder(addr xdr.ScAddress) (row, error) {
	s, err := addr.String() // want `XDR102 \(error\): xdr.ScAddress.String\(\) .* reaches account-key type keys.RawKey`
	if err != nil {
		return row{}, err
	}
	return row{Holder: keys.RawKey(s)}, nil
}

// (b) A column type that reduces the muxed kind but stores any payload
// length: a B… address is stored as a 33-byte key.
func truncatedHolder(addr xdr.ScAddress) (row, error) {
	s, err := addr.String() // want `XDR102 \(error\): xdr.ScAddress.String\(\) .* reaches account-key type keys.TruncatedKey`
	if err != nil {
		return row{}, err
	}
	return row{Holder: keys.TruncatedKey(s)}, nil
}

// (c) A participant setter that stores the string as given.
func rawSetter(addr xdr.ScAddress, b keys.Builder) (keys.Builder, error) {
	s, err := addr.String() // want `XDR102 \(error\): xdr.ScAddress.String\(\) .* reaches participant sink keys.Builder.WithRaw`
	if err != nil {
		return b, err
	}
	return b.WithRaw(s), nil
}

// addrOf renders an address held in an ScVal; it is shared by event and
// storage readers below.
func addrOf(v xdr.ScVal) (string, bool) {
	a, ok := v.GetAddress()
	if !ok {
		return "", false
	}
	s, err := a.String() // want `XDR102 \(error\): xdr.ScAddress.String\(\) .* reaches account-key type keys.NormalisedKey \(which reduces M… and W… itself but refuses B…, L… and P… with a write error\)`
	return s, err == nil
}

// (d) An event topic of any contract: the Stellar Asset Contract's events
// for classic operations carry B… and L… addresses, which NormalisedKey
// refuses with a write error.
func eventHolder(ev xdr.ContractEvent) (row, bool) {
	if len(ev.Body.V0.Topics) < 2 {
		return row{}, false
	}
	s, ok := addrOf(ev.Body.V0.Topics[1])
	return row{Holder: keys.NormalisedKey(s)}, ok
}

// argAddr renders an address passed as an invocation argument.
func argAddr(op xdr.InvokeHostFunctionOp) (string, bool) {
	args := op.HostFunction.MustInvokeContract().Args
	if len(args) == 0 {
		return "", false
	}
	a, ok := args[0].GetAddress()
	if !ok {
		return "", false
	}
	s, err := a.String() // want `XDR102 \(error\): xdr.ScAddress.String\(\) .* reaches account-key type keys.NormalisedKey \(which reduces`
	return s, err == nil
}

// (e) An invocation argument is submitter bytes the host never converted
// when the transaction failed: it can be a claimable-balance address.
func argHolder(op xdr.InvokeHostFunctionOp) (row, bool) {
	s, ok := argAddr(op)
	return row{Holder: keys.NormalisedKey(s)}, ok
}

// sacAddr renders the second topic of an event the caller dispatched on.
func sacAddr(ev xdr.ContractEvent) (string, bool) {
	a, ok := ev.Body.V0.Topics[1].GetAddress()
	if !ok {
		return "", false
	}
	s, err := a.String() // want `XDR102 \(error\): xdr.ScAddress.String\(\) .* reaches account-key type keys.NormalisedKey \(which reduces`
	return s, err == nil
}

// (f) Dispatched on "transfer", a name the Stellar Asset Contract emits:
// its classic-operation events carry B… and L… addresses.
func transferHolder(ev xdr.ContractEvent) (row, bool) {
	if len(ev.Body.V0.Topics) < 2 {
		return row{}, false
	}
	sym, ok := ev.Body.V0.Topics[0].GetSym()
	if !ok {
		return row{}, false
	}
	switch string(sym) {
	case "transfer":
		s, ok := sacAddr(ev)
		return row{Holder: keys.NormalisedKey(s)}, ok
	}
	return row{}, false
}

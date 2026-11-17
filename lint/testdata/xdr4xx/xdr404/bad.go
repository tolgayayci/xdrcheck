package xdr404

import (
	"github.com/stellar/go-stellar-sdk/xdr"
)

type eventRow struct {
	Name string
	From string
}

// (a) A fixed position read with no length check: a contract that emits one
// topic panics the reader.
func eventName(ev xdr.ContractEvent) string {
	topics := ev.Body.V0.Topics
	sym, ok := topics[1].GetSym() // want `XDR404 \(error\): topics\[1\] reads position 1 of a contract event's topics with no check of len\(topics\)`
	if !ok {
		return ""
	}
	return string(sym)
}

// (b) A kind assumed with Must…: any contract can emit any type there.
func transferRow(ev xdr.ContractEvent) eventRow {
	topics := ev.Body.V0.Topics
	if len(topics) < 2 {
		return eventRow{}
	}
	name := topics[0].MustSym() // want `XDR404 \(error\): topics\[0\].MustSym\(\) assumes a value of a contract event is a Sym`
	return eventRow{Name: string(name)}
}

// (c) The data assumed to be a map.
func dataEntries(ev xdr.ContractEvent) int {
	m := ev.Body.V0.Data.MustMap() // want `XDR404 \(error\): ev.Body.V0.Data.MustMap\(\) assumes a value of a contract event is a Map`
	if m == nil {
		return 0
	}
	return len(*m)
}

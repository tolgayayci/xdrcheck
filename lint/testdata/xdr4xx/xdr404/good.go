package xdr404

import (
	"bytes"

	"github.com/stellar/go-stellar-sdk/xdr"
)

// Length and type checked.
func eventNameChecked(ev xdr.ContractEvent) string {
	topics := ev.Body.V0.Topics
	if len(topics) < 2 {
		return ""
	}
	sym, ok := topics[1].GetSym()
	if !ok {
		return ""
	}
	return string(sym)
}

// The type switched on before Must….
func transferRowChecked(ev xdr.ContractEvent) eventRow {
	topics := ev.Body.V0.Topics
	if len(topics) < 2 || topics[0].Type != xdr.ScValTypeScvSymbol {
		return eventRow{}
	}
	return eventRow{Name: string(topics[0].MustSym())}
}

// The emitting contract checked first: its event shape is known.
func knownContract(ev xdr.ContractEvent, want xdr.ContractId) eventRow {
	if ev.ContractId == nil || !bytes.Equal(ev.ContractId[:], want[:]) {
		return eventRow{}
	}
	if *ev.ContractId != want {
		return eventRow{}
	}
	return eventRow{Name: string(ev.Body.V0.Topics[0].MustSym())}
}

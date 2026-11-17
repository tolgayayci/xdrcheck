// Package xdr304 holds the XDR304 fixtures: contract event topics or data
// trusted without checking which contract emitted the event.
package xdr304

import (
	"strings"

	"github.com/stellar/go-stellar-sdk/ingest"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// recordMovement is listed under sinksmovement by the test.
func recordMovement(key, to string) { _, _ = key, to }

// (a) The recipient topic of a transfer-shaped event becomes a participant.
func transferParticipants(tx ingest.LedgerTransaction, participants map[string]bool) error {
	events, err := tx.GetContractEvents()
	if err != nil {
		return err
	}
	for _, ev := range events {
		topics := ev.Body.V0.Topics // want `XDR304 \(error\): ev.Body.V0.Topics \(contract event topics or data\) reaches participant sink participants`
		if len(topics) < 3 {
			continue
		}
		to, ok := topics[2].GetAddress()
		if !ok {
			continue
		}
		s, _ := to.String()
		participants[s] = true
	}
	return nil
}

// (b) The fourth topic is parsed as CODE:ISSUER and credited as that asset.
func movementAsset(ev xdr.ContractEvent) (xdr.Asset, error) {
	sym, ok := ev.Body.V0.Topics[3].GetStr() // want `XDR304 \(error\): ev.Body.V0.Topics .* reaches asset construction strings.SplitN`
	if !ok {
		return xdr.Asset{}, nil
	}
	parts := strings.SplitN(string(sym), ":", 2)
	if len(parts) != 2 {
		return xdr.Asset{}, nil
	}
	return xdr.BuildAsset("credit_alphanum4", parts[1], parts[0])
}

// (c) A movement keyed by an asset named in the event data.
func movementFromData(ev xdr.ContractEvent) {
	data := ev.Body.V0.Data // want `XDR304 \(error\): ev.Body.V0.Data .* reaches asset construction recordMovement`
	if s, ok := data.GetStr(); ok {
		recordMovement(string(s), "")
	}
}

// (d) The contract check exists, but against the wrong value.
func wrongCheck(ev xdr.ContractEvent, someID xdr.ContractId, participants map[string]bool) {
	if ev.ContractId == nil || *ev.ContractId != someID {
		return
	}
	to, _ := ev.Body.V0.Topics[2].GetAddress() // want `XDR304 \(error\): ev.Body.V0.Topics`
	s, _ := to.String()
	participants[s] = true
}

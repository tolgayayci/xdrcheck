package xdr304

import (
	"github.com/stellar/go-stellar-sdk/ingest"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// (a) The recipient is taken only from the asset's own contract, the shape
// of the SDK's token transfer processor.
func sacTransferParticipants(tx ingest.LedgerTransaction, asset xdr.Asset, passphrase string, participants map[string]bool) error {
	expected, err := asset.ContractID(passphrase)
	if err != nil {
		return err
	}
	events, err := tx.GetContractEvents()
	if err != nil {
		return err
	}
	for _, ev := range events {
		if ev.ContractId == nil || *ev.ContractId != xdr.ContractId(expected) {
			continue
		}
		topics := ev.Body.V0.Topics
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

// (b) The same check in the then-branch.
func sacRecipient(ev xdr.ContractEvent, asset xdr.Asset, passphrase string, participants map[string]bool) {
	id, err := asset.ContractID(passphrase)
	if err != nil {
		return
	}
	if ev.ContractId != nil && *ev.ContractId == xdr.ContractId(id) {
		to, _ := ev.Body.V0.Topics[2].GetAddress()
		s, _ := to.String()
		participants[s] = true
	}
}

// (c) A movement recorded for the emitting contract claims nothing about a
// classic asset.
func movementForContract(ev xdr.ContractEvent) {
	if ev.ContractId == nil {
		return
	}
	to, _ := ev.Body.V0.Topics[2].GetAddress()
	s, _ := to.String()
	recordMovement(xdr.Hash(*ev.ContractId).HexString(), s)
}

// (d) Storing the raw event is not a sink.
func rawTopics(ev xdr.ContractEvent) int { return len(ev.Body.V0.Topics) }

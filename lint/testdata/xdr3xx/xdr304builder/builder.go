// Package xdr304builder holds the XDR304 fixtures for a configured
// participant sink reached through a builder chain: the test lists
// stateChangeBuilder.WithAccount under sinksparticipant, the way the
// wallet-backend profile lists its StateChangeBuilder.WithAccount.
//
// A state change built on a builder that was given the emitting contract's
// ID (WithToken(contract ID), earlier in the chain or on the variable the
// chain starts from) is recorded for that contract and claims nothing about
// another contract's asset, so it is not reported. A builder keyed by
// anything else is.
package xdr304builder

import (
	"errors"

	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"
)

type stateChangeBuilder struct{ category, token, reason, account, amount string }

func (b stateChangeBuilder) WithCategory(c string) stateChangeBuilder { b.category = c; return b }

func (b stateChangeBuilder) WithToken(contractID string) stateChangeBuilder {
	b.token = contractID
	return b
}

func (b stateChangeBuilder) WithReason(r string) stateChangeBuilder { b.reason = r; return b }

func (b stateChangeBuilder) WithAccount(a string) stateChangeBuilder { b.account = a; return b }

func (b stateChangeBuilder) WithAmount(a string) stateChangeBuilder { b.amount = a; return b }

func (b stateChangeBuilder) Build() string { return b.token + b.account + b.amount }

// contractIDString renders the event's emitting contract as a C… strkey.
func contractIDString(ev xdr.ContractEvent) (string, error) {
	if ev.ContractId == nil {
		return "", errors.New("contract event missing contract id")
	}
	return strkey.Encode(strkey.VersionByteContract, ev.ContractId[:])
}

// topicAddress renders topic i of the event as a strkey.
func topicAddress(ev xdr.ContractEvent, i int) string {
	a, ok := ev.Body.V0.Topics[i].GetAddress()
	if !ok {
		return ""
	}
	s, _ := a.String()
	return s
}

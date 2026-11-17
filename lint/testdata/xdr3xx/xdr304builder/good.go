package xdr304builder

import "github.com/stellar/go-stellar-sdk/xdr"

// (a) The shape of a SEP-41 processor: the builder is keyed by the emitting
// contract (WithToken with the event's contract ID) before the chain that
// names the account, through a variable and a helper that renders the ID.
func tokenStateChanges(ev xdr.ContractEvent, opBuilder stateChangeBuilder, tracked map[string]bool) ([]string, error) {
	contractStr, err := contractIDString(ev)
	if err != nil {
		return nil, err
	}
	if !tracked[contractStr] {
		return nil, nil
	}
	scBuilder := opBuilder.
		WithCategory("balance").
		WithToken(contractStr)
	from, to := topicAddress(ev, 1), topicAddress(ev, 2)
	creditBuilder := scBuilder.WithReason("credit").WithAccount(to)
	return []string{
		scBuilder.WithReason("debit").WithAccount(from).Build(),
		creditBuilder.Build(),
	}, nil
}

// (b) The contract ID given to the builder in the same chain.
func mintStateChange(ev xdr.ContractEvent, b stateChangeBuilder) string {
	if ev.ContractId == nil {
		return ""
	}
	to, _ := ev.Body.V0.Topics[2].GetAddress()
	s, _ := to.String()
	return b.WithToken(xdr.Hash(*ev.ContractId).HexString()).WithReason("mint").WithAccount(s).Build()
}

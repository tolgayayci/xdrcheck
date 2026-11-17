package xdr304builder

import "github.com/stellar/go-stellar-sdk/xdr"

// (a) The builder is keyed by a contract the caller names, not by the one
// that emitted the event: any contract can emit this transfer.
func trackedTransfer(ev xdr.ContractEvent, b stateChangeBuilder, trackedContract string) string {
	to, _ := ev.Body.V0.Topics[2].GetAddress() // want `XDR304 \(error\): ev.Body.V0.Topics .* reaches participant sink b.WithToken\(trackedContract\).WithAccount`
	s, _ := to.String()
	return b.WithToken(trackedContract).WithAccount(s).Build()
}

// (b) The builder is keyed by a token named in the event's own topics.
func tokenFromTopic(ev xdr.ContractEvent, b stateChangeBuilder) string {
	topics := ev.Body.V0.Topics // want `XDR304 \(error\): ev.Body.V0.Topics .* reaches participant sink`
	tok, _ := topics[3].GetStr()
	to, _ := topics[2].GetAddress()
	s, _ := to.String()
	return b.WithToken(string(tok)).WithAccount(s).Build()
}

// (c) A builder keyed by the emitting contract does not cover a plain
// participant set written next to it.
func keyedBuilderPlainSet(ev xdr.ContractEvent, b stateChangeBuilder, participants map[string]bool) string {
	cid, err := contractIDString(ev)
	if err != nil {
		return ""
	}
	to := topicAddress(ev, 2) // want `XDR304 \(error\): topicAddress\(\) .* reaches participant sink participants`
	participants[to] = true
	return b.WithToken(cid).WithAccount(to).Build()
}

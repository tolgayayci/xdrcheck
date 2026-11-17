// Package sep41 is an XDR102 regression fixture: wallet-backend just before
// PR #693 ("reduce muxed addresses to their base account"), where
// extractAddressFromScVal rendered every address kind with
// ScAddress.String(), muxed accounts included.
//
// events.go is internal/services/sep41/events.go of
// github.com/stellar/wallet-backend at commit
// 79ea2acd1dc65a07166133cc04b12e76db314db0 (Apache License 2.0), unchanged
// except for the expectation (want) comment; every line keeps its number. The
// fixture's .xdrlint.yml names the decoded event fields as account-key
// sinks, as for wb_sep41_events_ba82157.
package sep41

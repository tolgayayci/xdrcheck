// Package sep41 is the counterpart of wb_sep41_events_79ea2acd at PR #693,
// which added the muxed-account arm to extractAddressFromScVal. It shows
// narrowing, not silence: muxed contracts, claimable balances and pools still
// reach ScAddress.String(), so XDR102 still fires here until PR #756
// (wb_sep41_events_ba82157 and wb_sep41_events_666a64d).
//
// events.go is internal/services/sep41/events.go of
// github.com/stellar/wallet-backend at commit
// 6e5a59101158dc2996295450190142366062cd05 (Apache License 2.0), unchanged
// except for the expectation (want) comment; every line keeps its number. The
// fixture's .xdrlint.yml names the decoded event fields as account-key
// sinks, as for wb_sep41_events_ba82157.
package sep41

// Package sep41 is an XDR102 regression fixture: wallet-backend just before
// PR #756 (audit finding #752), where extractAddressFromScVal reduced a muxed
// account but rendered every other kind with ScAddress.String(), so muxed
// contracts, claimable balances and pools reached balance and allowance
// keys as W…, B… and L… strkeys.
//
// events.go is internal/services/sep41/events.go of
// github.com/stellar/wallet-backend at commit
// ba8215796d8118d3c7d302395b901eec925894ab (Apache License 2.0), unchanged
// except for the expectation (want) comment; every line keeps its number.
//
// The event fields are where the addresses become keys: wallet-backend
// stores them as balance and allowance holders in another package. The
// fixture's .xdrlint.yml names them as account-key sinks, the way a project
// profile names a sink outside the analysed package.
package sep41

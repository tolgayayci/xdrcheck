// Package sep41 is the fixed counterpart of the XDR102 regression fixture
// wb_sep41_events_ba82157: wallet-backend at PR #756, where
// extractAddressFromScVal goes through types.StorableAddressString, which
// reduces a muxed account and rejects the kinds a row cannot key on. The
// rule must be silent here.
//
// events.go is internal/services/sep41/events.go of
// github.com/stellar/wallet-backend at commit
// 666a64d426263fa6bd2a0ee61ee8dfb1f4729019 (Apache License 2.0), unchanged
// except that the types import points at the stand-in under ../stub (a copy
// of StorableAddressString); every line keeps its number.
package sep41

// Package processors is a regression fixture: wallet-backend
// (https://github.com/stellar/wallet-backend, Apache License 2.0) at commit
// 666a64d426263fa6bd2a0ee61ee8dfb1f4729019, the parent of the fix that
// derived Soroban participants from meta instead of the authorization tree
// and moved the success check ahead of the operation's envelope accounts.
//
//   - contract_operations.go, participants.go and contract_deploy.go are
//     internal/indexer/processors at that commit, unchanged except for their
//     import lines (the set package, internal/utils, internal/indexer/types
//     and internal/metrics are replaced by local stand-ins; each import block
//     keeps its length), so every line number matches upstream. The
//     analysistest expectations at the ends of lines mark the reports:
//     contract_operations.go lines 66, 78, 90, 97, 113, 120, 262, 269, 306,
//     313, 350 and 359 (XDR301), lines 66, 113 and 350 (XDR102: an
//     ScAddress from the authorization tree or the invocation arguments
//     rendered with String() and no kind check), line 98 (XDR201, the
//     recursive walk with a per-level merge), participants.go line 167
//     (XDR302) and contract_deploy.go line 104 (XDR201, the closure
//     walkInvocation). With the wallet-backend profile's state-change sinks
//     (StateChangeBuilder.WithAccount and WithCreator) contract_deploy.go
//     also reports XDR301 at line 62 (a declared deploy recorded with no meta
//     check) and XDR303 at line 36; the test that configures them asserts
//     those by position.
//   - support.go is a trimmed copy of transaction_operation_wrapper.go at the
//     same commit (the methods these files call), plus stand-ins for
//     deployerAddressString and StateChangeBuilder, which live in other
//     upstream files.
//
// The fixed counterparts are in ../../wbe967ce8/processors.
package processors

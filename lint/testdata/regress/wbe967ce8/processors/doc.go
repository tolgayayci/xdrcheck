// Package processors is a regression fixture: wallet-backend
// (https://github.com/stellar/wallet-backend, Apache License 2.0) at commit
// e967ce8b7362b79c277e700e789181d76fbb5967, the pinned current commit, after
// the fix that derives Soroban participants from nonce entries in meta and
// returns early for a failed transaction.
//
// contract_operations.go, participants.go, contract_deploy.go and
// transaction_operation_wrapper.go are internal/indexer/processors at that
// commit, unchanged except for imports (the set package and, in
// contract_deploy.go, internal/indexer/types and internal/metrics are
// replaced by local stand-ins; each import block keeps its length), so line
// numbers match upstream. support.go stands in for helpers that live in
// other upstream files.
//
// The participant rules report nothing here. XDR201 reports the closure
// walkInvocation in contract_deploy.go (declared at lines 115-116), at its
// recursive call on line 143: it recurses over SubInvocations with no depth
// parameter.
//
// The pre-fix copies are in ../../wb666a64d/processors.
package processors

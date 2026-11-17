// Package xdr4xx implements the XDR4xx rule family of xdrlint, "assumptions
// about the ledger's form, ranges and outcomes": code that is right for the
// ledgers its authors tested and wrong for other ledgers stellar-core accepts.
//
//	XDR401  a meta version assumed: one arm of TransactionMeta or LedgerCloseMeta read without a version check, or a version check that halts on the others
//	XDR402  a wide integer (u64, i128, u32) narrowed without a range check, and stored
//	XDR403  an error or ok result discarded on a value that is then stored
//	XDR404  contract event topics or data trusted by position or kind without a shape or emitter check
//	XDR405  rows built from diagnostic events without a success gate, or from transaction-level changes in operation scope
//	XDR406  (opt-in) closed switch over an xdr enum that writes rows, with no default or a panicking one
//
// Each rule is its own analyzer. XDR402 works on the SSA form of the package
// (a conversion, the values it was computed from, a dominating comparison);
// the others work on the typed syntax with the guard model of guard.go: a
// check counts when the reported expression sits in the branch it selects, or
// after an early exit on its negation, in an enclosing block.
package xdr4xx

import (
	"github.com/tolgayayci/xdrcheck/lint/internal/framework"
)

// The rules of the family.
var (
	XDR401 = framework.Rule{
		ID: "XDR401", Family: framework.FamilyAssumptions, Severity: framework.SeverityError,
		Title:      "one meta version assumed: an arm read without a version check, or a version check that halts on the others",
		Guide:      "protocol-boundaries",
		Corpus:     "ledger/meta-profile-default-flags-txmeta-v3",
		Checklist:  "HC-506",
		Fix:        "switch on the meta's V and handle every version the SDK declares (or skip the transaction with a typed, logged reason); never Must<Vn>() or .Vn without that switch",
		Assumption: AssumeMetaSubset,
	}
	XDR402 = framework.Rule{
		ID: "XDR402", Family: framework.FamilyAssumptions, Severity: framework.SeverityError,
		Title:      "wide integer narrowed without a range check and stored",
		Guide:      "64-bit-ids",
		Corpus:     "cap-0027/muxed-source-id-above-2-pow-63",
		Checklist:  "HC-404",
		Fix:        "keep the full width (uint64, a decimal string or NUMERIC column, big.Int), or compare with the target type's bounds and reject the value before converting",
		Assumption: AssumeNarrowU64Int64,
	}
	XDR403 = framework.Rule{
		ID: "XDR403", Family: framework.FamilyAssumptions, Severity: framework.SeverityWarning,
		Title:      "error or ok result discarded on a value that is then stored",
		Guide:      "validated-fields",
		Corpus:     "cap-0067/address-types-in-sac-events-golden",
		Checklist:  "HC-108",
		Fix:        "check the error (or ok) and fail or skip the row with a logged reason; a zero value stored in its place is indistinguishable from a real one",
		Assumption: AssumeDiscardedError,
	}
	XDR404 = framework.Rule{
		ID: "XDR404", Family: framework.FamilyAssumptions, Severity: framework.SeverityError,
		Title:      "contract event topics or data trusted by position or kind without a shape or emitter check",
		Guide:      "fields-events",
		Corpus:     "cap-0046/event-topic-count-extremes",
		Checklist:  "HC-306",
		Fix:        "check len(topics) and each value's Type (or use Get<Arm>() and its ok) before reading it, or first compare the event's ContractId with the contract whose event shape you rely on",
		Assumption: AssumeTopicKind,
	}
	XDR405 = framework.Rule{
		ID: "XDR405", Family: framework.FamilyAssumptions, Severity: framework.SeverityError,
		Title:      "rows from diagnostic events without a success gate, or from transaction-level changes in operation scope",
		Guide:      "failed-transactions",
		Corpus:     "cap-0046/failed-soroban-tx-with-sac-transfers-in-diagnostics",
		Checklist:  "HC-307",
		Fix:        "build rows from diagnostic events only after LedgerTransaction.Successful(); attribute to an operation only its own changes (GetOperationChanges), never the fee or transaction-level changes",
		Assumption: AssumeDiagnosticSuccess,
	}
	XDR406 = framework.Rule{
		ID: "XDR406", Family: framework.FamilyAssumptions, Severity: framework.SeverityWarning,
		Title:      "closed switch over an xdr enum that writes rows, with no default or a panicking default",
		Guide:      "protocol-boundaries",
		Corpus:     "cap-0088/first-ledger-with-signed-ms",
		Checklist:  "HC-507",
		Fix:        "add a default that records the unknown value (a counter, a typed skip, an error the operator sees) without halting, and handle every value the SDK declares",
		Assumption: AssumeEnumClosed,
		OptIn:      true,
	}
)

// Assumption keys of the family.
var (
	AssumeMetaSubset = framework.RegisterAssumption("meta-version:subset",
		"a TransactionMeta of a version the code does not accept (v0–v3 from captive core or older history, or a version a later protocol adds)")
	AssumeMetaV = [5]string{
		framework.RegisterAssumption("meta-version:v0-only", "a TransactionMeta that is not v0"),
		framework.RegisterAssumption("meta-version:v1-only", "a TransactionMeta that is not v1"),
		framework.RegisterAssumption("meta-version:v2-only", "a TransactionMeta that is not v2"),
		framework.RegisterAssumption("meta-version:v3-only", "a TransactionMeta that is not v3 (v4 since protocol 23, v0–v2 in older history)"),
		framework.RegisterAssumption("meta-version:v4-only", "a TransactionMeta older than v4 (captive core, older datastores, history before protocol 23)"),
	}
	AssumeLCMSubset = framework.RegisterAssumption("lcm-version:subset",
		"a LedgerCloseMeta of a version the code does not accept")
	AssumeLCMV = [3]string{
		framework.RegisterAssumption("lcm-version:v0-only", "a LedgerCloseMeta that is not v0 (every ledger since protocol 20)"),
		framework.RegisterAssumption("lcm-version:v1-only", "a LedgerCloseMeta that is not v1 (v0 before protocol 20, v2 since protocol 23)"),
		framework.RegisterAssumption("lcm-version:v2-only", "a LedgerCloseMeta older than v2 (ledgers before protocol 23)"),
	}

	AssumeNarrowU64Int64   = framework.RegisterAssumption("narrowing:u64->int64", "a 64-bit unsigned value ≥ 2^63 (a muxed ID, a time bound)")
	AssumeNarrowU64Int32   = framework.RegisterAssumption("narrowing:u64->int32", "a 64-bit unsigned value ≥ 2^31")
	AssumeNarrowU64Float   = framework.RegisterAssumption("narrowing:u64->float64", "a 64-bit unsigned value above 2^53, which float64 cannot hold exactly")
	AssumeNarrowI64Int32   = framework.RegisterAssumption("narrowing:i64->int32", "a 64-bit amount or count outside the int32 range")
	AssumeNarrowU32Int16   = framework.RegisterAssumption("narrowing:u32->int16", "a 32-bit value above 32,767")
	AssumeNarrowI128Int64  = framework.RegisterAssumption("narrowing:i128->int64", "a 128-bit amount or balance ≥ 2^63 (SAC and custom token balances above 2^63 exist on mainnet)")
	AssumeNarrowI128Float  = framework.RegisterAssumption("narrowing:i128->float64", "a 128-bit amount above 2^53 raw units")
	AssumeNarrowOtherSmall = framework.RegisterAssumption("narrowing:int->smaller", "an integer outside the range of the smaller type it is converted to")

	AssumeDiscardedError = framework.RegisterAssumption("discarded-error:stored",
		"an input the called function rejects (a malformed strkey, a number that does not parse, an arm the value does not hold), so a zero value is stored")

	AssumeTopicCount = framework.RegisterAssumption("event-shape:topic-count",
		"a contract event with fewer topics than the code indexes (any contract can emit any number)")
	AssumeTopicKind = framework.RegisterAssumption("event-shape:value-kind",
		"a contract event whose topic or data value has another ScVal type than the code assumes")

	AssumeDiagnosticSuccess = framework.RegisterAssumption("success-gate:diagnostic-events",
		"a failed Soroban transaction whose diagnostic events record token movements of calls that were rolled back")
	AssumeTxChangesInOp = framework.RegisterAssumption("phase:tx-changes-as-op",
		"a transaction whose fee or transaction-level changes (txChangesBefore/After) touch an entry, read as an effect of one operation")

	AssumeEnumClosed = framework.RegisterAssumption("enum-closed:default",
		"an xdr enum value the switch does not handle (one a later protocol adds, or one the code forgot)")
)

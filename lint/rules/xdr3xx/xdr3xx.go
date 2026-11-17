// Package xdr3xx implements the participant rules, the third ingestion mistake
// (deriving participants from the envelope instead of the meta), and the
// event rule that shares their machinery:
//
//	XDR301  participants harvested from the authorization tree or invocation arguments
//	XDR302  envelope operation fields used as participants without a success gate
//	XDR303  participant builder that never reads meta
//	XDR304  token-shaped contract event trusted without checking the emitting contract
//
// One analyzer, "participants", implements all four. It works on the typed
// AST of each function:
//
//   - Sources come from the type catalogue (internal/catalogue): a selector
//     or call whose fully qualified name carries the source role.
//   - Flow is intra-procedural and flow-insensitive: a variable that is ever
//     assigned a value derived from a source is tainted everywhere in its
//     function (closures included). A call's result is tainted by its
//     arguments and receiver. Calls into other functions use summaries:
//     computed to a fixed point for the package itself and exported as facts
//     for importers.
//   - Sinks are participant sinks (see sinks.go), asset construction and the
//     configured sinks.
//   - Guards (a success check, a membership test against a set built from
//     meta, a comparison of the event's contract ID) count when the sink sits
//     in the branch the guard selects, or after an early exit on its
//     negation, in an enclosing block.
//
// Reports point at the source expression (or at the call of a summarised
// helper) whose value reached a sink, once per source position.
package xdr3xx

import (
	"golang.org/x/tools/go/analysis"

	"github.com/tolgayayci/xdrcheck/lint/internal/framework"
)

// The four rules of the family. Technique per rule:
//
//   - XDR301: sources are the catalogued authorization-tree and
//     invocation-argument fields and accessors; a report where such a value
//     reaches a participant sink, unless the sink sits under a membership or
//     equality test between that value and a set built from meta (the
//     nonce-entry shape). Reported at the source, or at the call of a helper
//     that returns the value without reporting it itself.
//   - XDR302: sources are operation sources and body accounts; a report
//     where one reaches a participant sink outside a success check
//     (LedgerTransaction.Successful, TransactionResult(Pair).Successful, or a
//     variable holding one). A function with no success check that returns
//     the accounts, or writes them into a set it was passed, is a helper: it
//     is silent and its unguarded call sites are reported. A function that
//     checks success is responsible for every unguarded flow in it.
//   - XDR303: a function that writes a participant sink, where neither it,
//     its same-package callees, nor any same-package caller reads meta (a
//     catalogued meta field, accessor or type, or a contract event).
//     Reported at the function name.
//   - XDR304: sources are contract event topics and data; sinks are
//     participant sinks and asset construction (catalogued constructors, an
//     xdr.Asset literal, a split on ":", configured sinksmovement calls). A
//     report unless the sink sits under `ContractId == asset.ContractID(…)`
//     (or a configured sanitizersevent call), or the sink is keyed by the
//     event's ContractId: a movement sink that takes it as an argument, or a
//     configured sink called on a builder that was given it earlier in the
//     chain (b.WithToken(contractID).WithAccount(to), directly or through a
//     variable or a helper that renders the ID).
var (
	XDR301 = framework.Rule{
		ID: "XDR301", Family: framework.FamilyParticipants, Severity: framework.SeverityError,
		Title:      "participants harvested from the authorization tree or invocation arguments",
		Guide:      "participants-from-meta",
		Corpus:     "cap-0046/auth-unmatched-entries-succeed",
		Checklist:  "HC-301",
		Fix:        "take participants from meta (entry changes, nonce entries, events of a verified contract), not from the authorization tree or call arguments",
		Assumption: AssumeAuthTree,
	}
	XDR302 = framework.Rule{
		ID: "XDR302", Family: framework.FamilyParticipants, Severity: framework.SeverityError,
		Title:      "envelope operation fields used as participants without a success gate",
		Guide:      "participants-from-meta",
		Corpus:     "cap-0015/fee-bump-inner-failed",
		Checklist:  "HC-302",
		Fix:        "add operation accounts only after a success check (LedgerTransaction.Successful()), or take them from meta",
		Assumption: AssumeFailedTx,
	}
	XDR303 = framework.Rule{
		ID: "XDR303", Family: framework.FamilyParticipants, Severity: framework.SeverityWarning,
		Title:      "participant builder that never reads meta",
		Guide:      "participants-from-meta",
		Corpus:     "cap-0073/sac-trust-creates-trustline",
		Checklist:  "HC-303",
		Fix:        "derive participants from the transaction meta (changes and events), not from the envelope alone",
		Assumption: AssumeEnvelopeOnly,
	}
	XDR304 = framework.Rule{
		ID: "XDR304", Family: framework.FamilyParticipants, Severity: framework.SeverityError,
		Title:      "token-shaped contract event trusted without checking the emitting contract",
		Guide:      "participant-algorithm",
		Corpus:     "cap-0067/forged-token-event-from-unrelated-contract",
		Checklist:  "HC-305",
		Fix:        "compare the event's ContractId with asset.ContractID(passphrase) before trusting its asset or accounts",
		Assumption: AssumeEmitter,
	}
)

// Analyzer is the participants analyzer.
var Analyzer = framework.Register(framework.Spec{
	Name:      "participants",
	Doc:       "participants reports participant sets built from the envelope, the authorization tree or unverified contract events (XDR301–XDR304)",
	Rules:     []framework.Rule{XDR301, XDR302, XDR303, XDR304},
	FactTypes: []analysis.Fact{(*funcFact)(nil)},
	Run:       run,
})

// Assumption keys of the rules of this family (see framework.RegisterAssumption).
var (
	AssumeAuthTree = framework.RegisterAssumption("participant:auth-tree",
		"an authorization entry or invocation argument that names an account the transaction never touched")
	AssumeFailedTx = framework.RegisterAssumption("participant:failed-tx",
		"a failed transaction whose operations name accounts that were never touched")
	AssumeEnvelopeOnly = framework.RegisterAssumption("participant:envelope-only",
		"an account touched only through meta (fee changes, entry changes, events)")
	AssumeEmitter = framework.RegisterAssumption("event-emitter:token",
		"a token-shaped event emitted by a contract that is not the asset's contract")
)

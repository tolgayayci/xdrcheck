// Package xdr2xx implements the caps rules, the second ingestion mistake
// (missing depth and size caps on recursive structures):
//
//	XDR201  recursion over a self-referential xdr type with no depth bound
//	XDR202  iterative walker with an unbounded worklist
//	XDR203  decoded integer as allocation size or loop bound
//	XDR204  persisted serialisation of a recursive value with no length check (opt-in)
//	XDR205  decoder with limits disabled
//	XDR206  behaviour at a bound differs from the declared overflow policy
//	XDR207  bound below what stellar-core admits, on a path fed from ledger meta
//
// One analyzer, "caps", implements all seven on the typed AST of the
// package. The three questions are kept apart: does a bound exist (XDR201,
// XDR202), is it too low for a reader of ledger meta (XDR207), and what
// happens at it (XDR206). A low fixed cap silences XDR201 and is then
// examined by XDR207; it is never the quiet option.
//
// The recursive-type set is computed from the loaded xdr package
// (internal/catalogue.RecursiveTypes), so a new recursive arm in a later SDK
// is picked up without a code change.
package xdr2xx

import (
	"github.com/tolgayayci/xdrcheck/lint/internal/framework"
)

// XDR201. Technique: per-package call graph over function declarations and
// literals (static calls, plus calls through a variable holding a literal),
// Tarjan's strongly connected components; a recursive call counts when an
// argument or the receiver has a type in the recursive-type set. A
// recursive call is bounded when a comparison of a depth counter tied to the
// recursion guards it: it sits inside `if d < max` or after
// `if d > max { return … }`. A counter is an integer parameter the call
// passes as d+c (a depth, bounded from above) or b-c (a budget, bounded from
// below: `if b <= 0 { return … }`, `if b == 0 …`), or an integer field,
// captured variable or package variable the function increments (a depth)
// or only decrements (a budget). A loop index or any other variable declared
// inside the function is never a counter: it starts again at every level.
// The error of a configured budget method (budgetmethods) is a bound too.
// Reported once per component, at the first unbounded recursive call; error
// when a member merges child results per level (Union, append(x, ys...)).
//
// Known false negatives: recursion through interface dispatch or through
// fmt and Stringer (ScVal.String), and recursion that crosses packages.
var XDR201 = framework.Rule{
	ID: "XDR201", Family: framework.FamilyCaps, Severity: framework.SeverityWarning,
	Title:      "recursion over a self-referential xdr type with no depth bound",
	Guide:      "caps-meta-readers",
	Corpus:     "cap-0046/scval-nested-vec-99-in-event",
	Checklist:  "HC-201",
	Fix:        "pass a depth counter down the recursion and stop at a limit at or above what stellar-core admits",
	Assumption: AssumeDepth,
}

// XDR202. Technique: a `for` loop that appends to a slice of a recursive
// xdr type values read from a field leading to children (catalogue role
// recursive-edge), and pops from that slice (it appears in the loop
// condition or is sliced or indexed in the body). Bounded when the append is
// guarded by a comparison of len(worklist) or of a counter incremented in
// the loop, in the loop condition or an enclosing if.
var XDR202 = framework.Rule{
	ID: "XDR202", Family: framework.FamilyCaps, Severity: framework.SeverityWarning,
	Title:      "iterative walker with an unbounded worklist",
	Guide:      "caps-meta-readers",
	Corpus:     "cap-0046/scval-nested-vec-99-in-event",
	Checklist:  "HC-202",
	Fix:        "count nodes (or the worklist length) inside the loop and stop at a limit at or above what stellar-core admits",
	Assumption: AssumeWorklist,
}

// XDR203. Technique: local flow from integer fields of xdr structs and
// integer results of xdr methods (ScVal.GetU32, …; not Count…/…Count/Len
// methods such as LedgerCloseMeta.CountTransactions, which count elements
// the decoder already materialised, like len) through assignments,
// conversions and arithmetic (not through other calls: min(n, max) ends
// it); sinks are make sizes, strings/bytes.Repeat counts and loop
// conditions. Sanitised by an enclosing upper-bound comparison of the value.
var XDR203 = framework.Rule{
	ID: "XDR203", Family: framework.FamilyCaps, Severity: framework.SeverityWarning,
	Title:      "decoded integer used as an allocation size or loop bound",
	Guide:      "caps-meta-readers",
	Corpus:     "xdr-strict/length-prefix-exceeds-input",
	Checklist:  "HC-203",
	Fix:        "compare the decoded integer with an upper bound before allocating or looping on it",
	Assumption: AssumeAllocSize,
}

// XDR204 (opt-in). Technique: local flow from a serialisation of a value of
// a recursive type (MarshalBinary/MarshalBase64 on it, xdr.MarshalBase64,
// xdr.MarshalHex, fmt.Sprint…) into a database/sql argument, with no
// enclosing comparison of its length.
var XDR204 = framework.Rule{
	ID: "XDR204", Family: framework.FamilyCaps, Severity: framework.SeverityInfo,
	Title:      "persisted serialisation of a recursive value with no length check",
	Guide:      "caps-meta-readers",
	Corpus:     "cap-0046/overly-large-values-golden",
	Checklist:  "HC-209",
	Fix:        "check the serialised length before writing it to the database",
	Assumption: AssumeStoredSize,
	OptIn:      true,
}

// XDR205. Technique: (a) any use of go-xdr's DecodeUnlimitedDepth, or a
// DecodeOptions literal whose MaxDepth is a constant of 2^62 or more
// (error); (b) xdr.Unmarshal or xdr.UnmarshalWithOptions on a reader whose
// static type has no Len() int method while MaxInputLen is not set in a
// DecodeOptions literal (warning). Options held in a variable are not
// examined.
var XDR205 = framework.Rule{
	ID: "XDR205", Family: framework.FamilyCaps, Severity: framework.SeverityError,
	Title:      "decoder with limits disabled",
	Guide:      "caps-meta-readers",
	Corpus:     "limits/scvec-nesting-100",
	Checklist:  "HC-204",
	Fix:        "decode with limits: keep the default MaxDepth and set MaxInputLen, or use xdr.SafeUnmarshal",
	Assumption: AssumeDecoderLimits,
}

// XDR206. Technique: for every bound XDR201 or XDR202 accepted, the branch
// taken past the bound (the early-exit body, or the else of an in-bound
// test) is checked against the configured overflowpolicy: a panic, os.Exit,
// log.Fatal… or configured halting function is reported under any policy;
// under halt-ledger, a branch that returns no error (return nil, a function
// with no error result, break, continue, falling through); under
// skip-and-flag, a branch that sets none of the configured overflowflags
// (a field of that name, or a call of that function). With no policy
// declared only the crash case is reported, and the message asks for a
// declaration.
var XDR206 = framework.Rule{
	ID: "XDR206", Family: framework.FamilyCaps, Severity: framework.SeverityWarning,
	Title:      "behaviour at a bound differs from the declared overflow policy",
	Guide:      "at-a-bound",
	Corpus:     "cap-0046/scval-nested-vec-99-in-event",
	Checklist:  "HC-205",
	Fix:        "make the branch past the bound do what overflowpolicy declares (fail the ledger, or skip and set the flag); never exit the process",
	Assumption: AssumeOverflowPolicy,
}

// XDR207. Technique: for every bound XDR201 accepted whose limit is a
// compile-time constant (for a budget counted down, the constant every call
// into the recursion starts it with), in a function fed from ledger meta
// (it, a callee, or a caller reads meta; literals inherit from their
// declaration), the constant is compared with the floor shipped for the
// structure walked (floors.go, overridable with `floors`). For the ScVal
// group: below 100 (the host's value depth limit) is a warning on every
// meta path; 100 to 498 is info ("envelope limit not established; 499 is
// the decoder upper bound"), and silent when every call into the walk starts
// from a value the host wrote (contract events, contract data, return
// values; traced through local variables and same-package callers); 499 and
// above is silent. For ClaimPredicate below 4 is a warning. A structure with
// no floor established is info. A DecodeOptions literal with a constant
// MaxDepth below 1500 go-xdr units, in a meta-fed function or decoding into
// a meta type, is a warning. Bounds taken from configuration or variables
// are not examined; worklist size bounds (XDR202) are not examined.
//
// Known false negatives: a walker in another package than the code that
// feeds it from meta (no facts cross packages, so its bound is examined only
// when its own package reads meta), and bounds computed at run time.
var XDR207 = framework.Rule{
	ID: "XDR207", Family: framework.FamilyCaps, Severity: framework.SeverityWarning,
	Title:      "bound below what stellar-core admits, on a path fed from ledger meta",
	Guide:      "core-limits",
	Corpus:     "cap-0046/scval-nested-vec-99-in-event",
	Checklist:  "HC-206",
	Fix:        "raise the constant to at least what stellar-core admits for that structure, or read the bound from configuration",
	Assumption: AssumeCoreBound,
}

// Analyzer is the caps analyzer.
var Analyzer = framework.Register(framework.Spec{
	Name:  "caps",
	Doc:   "caps reports missing, too-low or mishandled depth and size bounds on recursive xdr structures and decoders (XDR201–XDR207)",
	Rules: []framework.Rule{XDR201, XDR202, XDR203, XDR204, XDR205, XDR206, XDR207},
	Run:   run,
})

// Assumption keys of the rules of this family (see framework.RegisterAssumption).
var (
	AssumeDepth = framework.RegisterAssumption("depth:recursion",
		"an authorization tree or ScVal nested as deep as stellar-core admits")
	AssumeWorklist = framework.RegisterAssumption("depth:worklist",
		"a tree with as many nodes as stellar-core admits")
	AssumeAllocSize = framework.RegisterAssumption("size:decoded-length",
		"a decoded count or length as large as its type allows")
	AssumeStoredSize = framework.RegisterAssumption("size:serialised-value",
		"a recursive value whose serialisation is as long as stellar-core admits")
	AssumeDecoderLimits = framework.RegisterAssumption("size:decoder-limits",
		"hostile XDR bytes with a huge length prefix or nesting")
	AssumeOverflowPolicy = framework.RegisterAssumption("limit:overflow-policy",
		"an input at the bound the code enforces")
	AssumeCoreBound = framework.RegisterAssumption("limit:below-core",
		"an input between the code's bound and what stellar-core admits")
)

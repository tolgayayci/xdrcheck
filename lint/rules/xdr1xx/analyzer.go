// Package xdr1xx implements the XDR1xx rule family of xdrlint, "trusting
// unvalidated fields":
//
//   - XDR101: a value derived from the transaction memo reaches the
//     construction of a muxed address;
//   - XDR102: an address string that can be muxed, a signed payload or a
//     non-account kind is used as a participant or account key without being
//     reduced to its base account or kind-checked;
//   - XDR103: submitter- or contract-controlled bytes reach a text sink
//     without UTF-8 and NUL handling;
//   - XDR105 (opt-in): Must<Arm>() on a multi-arm union with no dominating
//     check of the discriminant of the same value.
//
// All four share one analyzer, "unvalidated", and one engine: a package-wide
// taint analysis over the buildssa form of the package.
//
//   - Sources, sinks and sanitisers are taken from internal/catalogue (keyed
//     by fully qualified go-stellar-sdk names, including the read-only View
//     API), from the configuration (sinksparticipant, sinksaccountkey,
//     sinkstext, sanitizersaddress, sanitizerstext) and from
//     `//xdrlint:sink participant|accountkey|text` directives on functions
//     and struct fields of the package.
//   - Flow is SSA def-use inside a function; through memory with one
//     abstract location per allocation and field path; into closures through
//     their captured variables; and between functions of the same package
//     through parameters and results (context-insensitive, to a fixpoint).
//     Struct values are tracked field by field into and out of same-package
//     functions, so reading one field of a decoded value does not pick up
//     what another field carries. Calls through a method value
//     (`f := addr.String; f()`), a method expression, or an interface whose
//     concrete types the package converts to it are resolved to their
//     methods. Calls into other packages pass the taint of every argument to
//     the result unless the callee is a catalogued or configured sanitiser.
//   - Guards are found by dominance: a kind switch on ScAddress.Type,
//     MuxedAccount.Type or SignerKey.Type (a forward dataflow of the possible
//     discriminant values), a type switch admitting only *MuxedInfo_Id, and
//     a utf8.Valid*/NUL test (or a same-package helper that does both and
//     reports it in a bool or error result) whose passing branch dominates
//     the use: the failing branch must leave (return, continue, break,
//     panic) or the use must sit on the passing branch only. A check whose
//     failing branch merely logs and falls through guards nothing.
//
// XDR101 and XDR103 are reported at the sink. XDR102 is reported once at
// the call that renders the address (the place to insert ToAccountId() or a
// kind check), naming the first sink it reaches. An address from the
// authorization tree or invocation arguments is a source like any other
// (XDR301 also reports it when it becomes a participant); the only address
// exempted by origin is one the host wrote into a contract-data entry. What
// the rules do not catch is listed under Limits.
//
// # Limits
//
//   - Taint through interface{} maps, channels, reflection or goroutine
//     hand-offs is not tracked (for example the signer path that crossed
//     effect.Details["public_key"] before it reached an account-key column).
//   - Stores through a pointer parameter are not seen by the caller, and a
//     function in another package is assumed to pass taint from its
//     arguments to its result and nothing else (a callee that writes through
//     an argument, such as binary.BigEndian.PutUint64(buf, id), is missed).
//   - What a pointer field points to is one location: its fields are not
//     told apart.
//   - Sinks in another package are found only through configuration or a
//     directive; a flow into one is otherwise a false negative.
//   - A method value passed to another function, and an interface value
//     whose concrete type is converted in another package, are not resolved.
//   - A guard counts only on the same SSA value it tested, or on the same
//     field of the same variable.
//   - XDR105 ignores the View API (its accessors return errors instead of
//     panicking) and accepts any dominating test of the discriminant, not
//     only one that selects the arm being read.
package xdr1xx

import (
	"go/ast"
	"go/token"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"

	"github.com/tolgayayci/xdrcheck/lint/internal/framework"
)

// The rules of this family.
var (
	XDR101 = framework.Rule{
		ID: "XDR101", Family: framework.FamilyUnvalidated, Severity: framework.SeverityError,
		Title:      "address built from a memo",
		Guide:      "event-routing-id",
		Corpus:     "cap-0067/to-muxed-id-text-from-memo",
		Checklist:  "HC-101",
		Fix:        "route only a u64 to_muxed_id (or a MEMO_ID) into a muxed address; keep memo text and hash as data, never as an ID",
		Assumption: AssumeMemoNotID,
	}
	XDR102 = framework.Rule{
		ID: "XDR102", Family: framework.FamilyUnvalidated, Severity: framework.SeverityError,
		Title:      "unnormalised address used as an identity key",
		Guide:      "muxed-and-signed-payload",
		Corpus:     "cap-0027/muxed-source-and-destination-max-ids",
		Checklist:  "HC-102",
		Fix:        "key on the base account: MuxedAccount.ToAccountId(), or a switch on ScAddress.Type that handles the muxed, claimable-balance and pool kinds",
		Assumption: AssumeBaseAddress,
	}
	XDR103 = framework.Rule{
		ID: "XDR103", Family: framework.FamilyUnvalidated, Severity: framework.SeverityError,
		Title:      "unvalidated bytes or string into text storage",
		Guide:      "validated-fields",
		Corpus:     "cap-0067/to-muxed-id-text-non-utf8-memo",
		Checklist:  "HC-103",
		Fix:        "check utf8.ValidString and reject or strip NUL before storing as text, or store the bytes as bytea, hex or base64",
		Assumption: AssumeText,
	}
	XDR105 = framework.Rule{
		ID: "XDR105", Family: framework.FamilyUnvalidated, Severity: framework.SeverityWarning,
		Title:      "Must<Arm>() on a multi-arm union without a dominating discriminant check",
		Guide:      "validated-fields",
		Corpus:     "cap-0067/token-events-bytes-and-bad-type-muxed-id",
		Checklist:  "HC-107",
		Fix:        "switch on the union's type, or use the ok result of Get<Arm>(), before calling Must<Arm>()",
		Assumption: AssumeUnionArm,
		OptIn:      true,
	}
)

// Analyzer is the "unvalidated" analyzer: XDR101, XDR102, XDR103, XDR105.
var Analyzer = framework.Register(framework.Spec{
	Name:     "unvalidated",
	Doc:      "unvalidated reports trusted use of unvalidated xdr fields (XDR101, XDR102, XDR103, opt-in XDR105)",
	Rules:    []framework.Rule{XDR101, XDR102, XDR103, XDR105},
	Requires: []*analysis.Analyzer{buildssa.Analyzer, inspect.Analyzer, Normalisers},
	Run:      run,
})

func run(p *framework.Pass) (any, error) {
	ssaRes := p.ResultOf[buildssa.Analyzer].(*buildssa.SSA)
	insp := p.ResultOf[inspect.Analyzer].(*inspector.Inspector)

	e := newEngine(p, ssaRes, newASTIndex(insp))
	e.bindFreeVars()
	if p.Enabled(XDR101.ID) || p.Enabled(XDR102.ID) || p.Enabled(XDR103.ID) {
		e.prepare()
		e.solve()
		e.checkSinks()
	}
	if p.Enabled(XDR105.ID) {
		e.checkMustArm()
	}
	e.flush()
	return nil, nil
}

// astIndex maps the positions SSA keeps for calls (the opening parenthesis)
// and map updates (the opening bracket) back to the syntax around them, which
// the participant-sink heuristics need (variable and field names).
type astIndex struct {
	stacks map[token.Pos][]ast.Node
	// selectors maps the position of a selector's name to the selector:
	// where SSA puts a method value (x.M used as a value).
	selectors map[token.Pos]*ast.SelectorExpr
}

func newASTIndex(insp *inspector.Inspector) *astIndex {
	idx := &astIndex{stacks: map[token.Pos][]ast.Node{}, selectors: map[token.Pos]*ast.SelectorExpr{}}
	insp.Preorder([]ast.Node{(*ast.SelectorExpr)(nil)}, func(n ast.Node) {
		sel := n.(*ast.SelectorExpr)
		idx.selectors[sel.Sel.Pos()] = sel
	})
	insp.WithStack([]ast.Node{(*ast.CallExpr)(nil), (*ast.IndexExpr)(nil)}, func(n ast.Node, push bool, stack []ast.Node) bool {
		if !push {
			return true
		}
		var pos token.Pos
		switch n := n.(type) {
		case *ast.CallExpr:
			pos = n.Lparen
		case *ast.IndexExpr:
			pos = n.Lbrack
		}
		idx.stacks[pos] = append([]ast.Node(nil), stack...)
		return true
	})
	return idx
}

// stack returns the syntax path (file first) of the call or index expression
// at pos, or nil.
func (a *astIndex) stack(pos token.Pos) []ast.Node { return a.stacks[pos] }

// Assumption keys of the rules of this family (see framework.RegisterAssumption).
var (
	AssumeMemoText = framework.RegisterAssumption("text-to-db:memo",
		"a text memo with invalid UTF-8 or a NUL byte")
	AssumeMemoNotID = framework.RegisterAssumption("memo:not-an-id",
		"a payment with a text or hash memo to an account that is not muxed")
	AssumeBaseAddress = framework.RegisterAssumption("address-kind:base-account",
		"an M… (muxed account), W… (muxed contract), B… (claimable balance) or L… (liquidity pool) address where a G… or C… address is expected")
	AssumeText = framework.RegisterAssumption("text-to-db:bytes",
		"a string or bytes value with invalid UTF-8 or a NUL byte (a memo, symbol, string or asset code chosen by a submitter or a contract)")
	AssumeUnionArm = framework.RegisterAssumption("union-arm:single",
		"a union value that holds another arm than the one the code reads")
)

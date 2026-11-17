// Package suppress is the placement fixture for inline suppressions. The
// framework test registers a demonstration rule, XDR990, that reports every
// call of sink().
package suppress

func sink() {}

func unsuppressed() {
	sink() // want `XDR990 \(error\): demo sink called`
}

func trailing() {
	sink() //xdrlint:ignore XDR990 the trailing form
}

func above() {
	//xdrlint:ignore XDR990 the form on its own line, above the report
	sink()
}

func aboveWithExplanation() {
	//xdrlint:ignore XDR990 -- a reason after the separator
	// and a second comment line
	sink()
}

// docScoped is suppressed as a whole, closures included.
//
//xdrlint:ignore XDR990 function-level suppression
func docScoped() {
	sink()
	func() { sink() }()
}

func severalRules() {
	sink() //xdrlint:ignore XDR201,XDR990 two rules named, one used
}

func trailingCoversItsLineOnly() {
	sink() //xdrlint:ignore XDR990 this line only
	sink() // want `XDR990`
}

func blankLineEndsTheScope() {
	//xdrlint:ignore XDR990 too far from the report

	sink() // want `XDR990`
}

func noReasonSuppressesNothing() {
	//xdrlint:ignore XDR990
	sink() // want `XDR990`
}

func otherRuleSuppressesNothing() {
	sink() //xdrlint:ignore XDR201 another rule // want `XDR990`
}

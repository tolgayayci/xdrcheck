// Package hygiene is the XDR000 fixture with a rule that runs: the
// framework test registers XDR990, which reports every call of sink().
package hygiene

func sink() {}

func cases() {
	// want +1 `XDR000 \(error\): suppression of XDR990 has no reason`
	//xdrlint:ignore XDR990
	sink()

	// want +1 `XDR000 \(error\): suppression of XDR990 suppresses nothing`
	//xdrlint:ignore XDR990 nothing on the next line reports XDR990
	_ = 1

	// want +1 `XDR000 \(error\): suppression names unknown rule XDR999`
	//xdrlint:ignore XDR999 not a rule
	_ = 2

	//xdrlint:ignore XDR201 a reserved rule this registry does not run: not checked
	_ = 3

	sink() //xdrlint:ignore XDR990 used, so silent

	// want +1 `XDR000 \(error\): ignore directive names no rule`
	//xdrlint:ignore

	// want +1 `XDR000 \(error\): sink directive names no sink kind`
	//xdrlint:sink
}

// docUnused has a function-level suppression that matches nothing.
//
//xdrlint:ignore XDR990 nothing in this function calls sink // want `XDR000 \(error\): suppression of XDR990 suppresses nothing`
func docUnused() {}

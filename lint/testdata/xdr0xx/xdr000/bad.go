// Package xdr000 is the XDR000 fixture of the shipped build: directives that
// are malformed whatever rules exist. It imports the real go-stellar-sdk
// v0.8.0, which proves the fixture harness loads the module (no stub).
package xdr000

import "github.com/stellar/go-stellar-sdk/xdr"

func describe(tx xdr.TransactionEnvelope) []string {
	var names []string

	// want +1 `XDR000 \(error\): suppression of XDR201 has no reason`
	//xdrlint:ignore XDR201
	names = append(names, tx.SourceAccount().ToAccountId().Address())

	// want +1 `XDR000 \(error\): suppression names unknown rule XDR999`
	//xdrlint:ignore XDR999 not a rule of this linter
	names = append(names, tx.Memo().Type.String())

	// want +1 `XDR000 \(error\): malformed directive`
	// xdrlint:ignore XDR102 a space after the slashes would hide the directive

	// want +1 `XDR000 \(error\): unknown directive "//xdrlint:allow"`
	//xdrlint:allow XDR102 wrong verb

	// want +1 `XDR000 \(error\): XDR000 cannot be suppressed`
	//xdrlint:ignore XDR000 hygiene is not optional

	// want +1 `XDR000 \(error\): ignore directive: "XDR10" is not a rule ID \(XDRnnn\)`
	//xdrlint:ignore XDR10 a typo

	return names
}

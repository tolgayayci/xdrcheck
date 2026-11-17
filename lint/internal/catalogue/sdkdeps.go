//go:build xdrlint_sdkdeps

// This file is never compiled. It keeps the packages the catalogue describes
// (and the fixtures under lint/testdata import) in go.mod and go.sum at the
// pinned versions, so that `go mod tidy` does not drop them: the catalogue
// test loads them with go/packages, and analysistest loads the fixtures with
// GOPROXY=off.
package catalogue

import (
	_ "github.com/stellar/go-stellar-sdk/ingest"
	_ "github.com/stellar/go-stellar-sdk/processors/token_transfer"
	_ "github.com/stellar/go-stellar-sdk/strkey"
	_ "github.com/stellar/go-stellar-sdk/xdr"
	_ "github.com/stellar/go-xdr/xdr3"
)

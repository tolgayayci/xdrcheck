// Command xdrcheck-driver is the conformance driver for one pinned go-stellar-sdk version: this directory's go.mod
// chooses the SDK version (and, through it, the go-xdr version the SDK pins); the code is the shared driver
// package in ../driver, with the view path (decode profile "views") from ../views.
package main

import (
	"github.com/stellar/go-stellar-sdk/xdr"
	"github.com/tolgayayci/xdrcheck/drivers/go/driver"
	"github.com/tolgayayci/xdrcheck/drivers/go/views"
)

func main() {
	d := views.Decoder{}
	driver.RegisterViews(d, func(goName string, raw []byte, passphrase string, full []xdr.LedgerCloseMeta, batch *xdr.LedgerCloseMetaBatch) driver.ViewsReport {
		return driver.ViewsReport(d.Ledgers(goName, raw, passphrase, full, batch))
	})
	driver.Main()
}

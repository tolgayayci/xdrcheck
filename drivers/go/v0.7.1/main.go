// Command xdrcheck-driver is the conformance driver for one pinned go-stellar-sdk version: this directory's go.mod
// chooses the SDK version (and, through it, the go-xdr version the SDK pins); the code is the shared driver
// package in ../driver.
package main

import "github.com/tolgayayci/xdrcheck/drivers/go/driver"

func main() { driver.Main() }

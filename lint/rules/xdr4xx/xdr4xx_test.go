package xdr4xx_test

import (
	"testing"

	"github.com/tolgayayci/xdrcheck/lint/internal/fixture"
	"github.com/tolgayayci/xdrcheck/lint/rules/xdr4xx"
)

// Seeded fixtures: every violating line carries a `// want`; the compliant
// files carry none. They import the real go-stellar-sdk v0.9.0.

func TestXDR401(t *testing.T) { fixture.Run(t, xdr4xx.Analyzer401, "xdr4xx/xdr401") }
func TestXDR402(t *testing.T) { fixture.Run(t, xdr4xx.Analyzer402, "xdr4xx/xdr402") }
func TestXDR403(t *testing.T) { fixture.Run(t, xdr4xx.Analyzer403, "xdr4xx/xdr403") }
func TestXDR404(t *testing.T) { fixture.Run(t, xdr4xx.Analyzer404, "xdr4xx/xdr404") }
func TestXDR405(t *testing.T) { fixture.Run(t, xdr4xx.Analyzer405, "xdr4xx/xdr405") }

// XDR406 is opt-in; the fixture's .xdrlint.yml enables it.
func TestXDR406(t *testing.T) { fixture.Run(t, xdr4xx.Analyzer406, "xdr4xx/xdr406") }

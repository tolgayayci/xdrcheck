package main

import (
	"testing"

	"github.com/tolgayayci/xdrcheck/go/adapterkit"
	"github.com/tolgayayci/xdrcheck/go/adapterkit/kittest"
)

// TestProtocol runs the adapter through the protocol checks in process. Keep it when you copy this template:
// it needs nothing but adapterkit. Give kittest.Check a Probe (a SEP-54 directory and its range) to check
// ingest and determinism too; `xdrcheck replay --adapter <your binary> --selftest` checks the real binary.
func TestProtocol(t *testing.T) {
	kittest.Check(t, func() adapterkit.Handler { return &minimal{sessions: map[string]*session{}} }, nil)
}

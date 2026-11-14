package plan

import (
	"github.com/tolgayayci/xdrcheck/go/internal/lake"
	"github.com/tolgayayci/xdrcheck/go/internal/rpcmock"
)

// WriteLayout publishes the unit as a SEP-54 layout under dir, on the unit's passphrase with the public lake's
// configuration. A history ledger of a single unit is the vendored lake object at its original key; every other
// ledger is wrapped from its (checked, and for streams renumbered) bytes.
func (u *Unit) WriteLayout(dir string) (*lake.Layout, error) {
	return lake.Write(dir, lake.NewConfig(u.Passphrase), u.LakeLedgers())
}

// RPCLedgers returns the unit's ledgers for the mock getLedgers server.
func (u *Unit) RPCLedgers() []rpcmock.Ledger {
	out := make([]rpcmock.Ledger, len(u.Ledgers))
	for i := range u.Ledgers {
		out[i] = rpcmock.Ledger{Seq: u.Ledgers[i].Seq, Load: u.Ledgers[i].Load}
	}
	return out
}

// RPCServer builds the mock getLedgers server for the unit.
func (u *Unit) RPCServer(nonce string, log *lake.DeliveryLog) (*rpcmock.Server, error) {
	return rpcmock.New(rpcmock.Config{Passphrase: u.Passphrase, Nonce: nonce, Log: log}, u.RPCLedgers())
}

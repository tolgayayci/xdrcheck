// The shared driver package. Each drivers/go/<version> module points here with a replace directive and
// chooses the SDK version itself. The requirements below are deliberately the lowest pinned versions (the SDK
// at v0.7.1 and the go-xdr that v0.7.1 pins), so that minimal version selection always resolves to the
// version module's own SDK and to the go-xdr that SDK pins; nothing is ever raised or replaced on its behalf.
module github.com/tolgayayci/xdrcheck/drivers/go/driver

go 1.26.11

require (
	github.com/stellar/go-stellar-sdk v0.7.1
	github.com/stellar/go-xdr v0.0.0-20260529210834-0bf8f4956364
)

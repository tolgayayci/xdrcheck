module example.com/sdkci

go 1.26.11

require (
	github.com/stellar/go-stellar-sdk v0.9.0
	github.com/tolgayayci/xdrcheck/packages/go v0.0.0
)

require (
	github.com/klauspost/compress v1.17.6 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/stellar/go-xdr v0.0.0-20260806060815-dc590f17552a // indirect
)

// In the SDK's own repository (this module copied to xdrcheck/), test the SDK itself with
//
//	replace github.com/stellar/go-stellar-sdk => ../
//
// and drop the replace below, pinning the loader by commit instead:
//
//	go get github.com/tolgayayci/xdrcheck/packages/go@<commit>
replace github.com/tolgayayci/xdrcheck/packages/go => ../../../packages/go

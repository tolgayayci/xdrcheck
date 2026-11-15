// The view-path half of the Go conformance driver (decode profile "views"): go-stellar-sdk's zero-copy XDR views
// and the view-based ingest extractors, which first shipped in v0.8.0. Only the drivers/go/<version> modules of
// v0.8.0 and later import it, pointing here with a replace directive; the requirement below is the lowest SDK
// version that has the views, so minimal version selection resolves to each version module's own SDK.
module github.com/tolgayayci/xdrcheck/drivers/go/views

go 1.26.11

require github.com/stellar/go-stellar-sdk v0.8.0

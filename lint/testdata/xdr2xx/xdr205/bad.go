// Package xdr205 holds the XDR205 fixtures: decoders with their limits
// disabled.
package xdr205

import (
	"bytes"
	"io"
	"math"

	xdr3 "github.com/stellar/go-xdr/xdr3"

	"github.com/stellar/go-stellar-sdk/xdr"
)

// Depth unlimited, from a network body.
func decodeUnlimited(body io.Reader) (xdr.ScVal, error) {
	var v xdr.ScVal
	_, err := xdr.UnmarshalWithOptions(body, &v, xdr.DecodeOptions{MaxDepth: xdr3.DecodeUnlimitedDepth}) // want `XDR205 \(warning\): UnmarshalWithOptions reads from body` `XDR205 \(error\): decoder depth limit disabled with DecodeUnlimitedDepth`
	return v, err
}

// Depth set to an unlimited value by hand.
func decodeMaxUint(b []byte) (xdr.ScVal, error) {
	var v xdr.ScVal
	_, err := xdr.UnmarshalWithOptions(bytes.NewReader(b), &v, xdr.DecodeOptions{MaxDepth: math.MaxUint}) // want `XDR205 \(error\): decoder depth limit set to an unlimited value`
	return v, err
}

// A stream whose length the decoder cannot see, with no MaxInputLen.
func decodeStream(zr io.Reader) (xdr.LedgerCloseMeta, error) {
	var lcm xdr.LedgerCloseMeta
	_, err := xdr.Unmarshal(zr, &lcm) // want `XDR205 \(warning\): Unmarshal reads from zr`
	return lcm, err
}

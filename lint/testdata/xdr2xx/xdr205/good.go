package xdr205

import (
	"bytes"
	"io"

	"github.com/stellar/go-stellar-sdk/xdr"
)

// Defaults: depth 1500, input length known.
func decodeBytes(b []byte) (xdr.ScVal, error) {
	var v xdr.ScVal
	err := xdr.SafeUnmarshal(b, &v)
	return v, err
}

// A stream with MaxInputLen set.
func decodeLimited(r io.Reader, n int) (xdr.ScVal, error) {
	var v xdr.ScVal
	_, err := xdr.UnmarshalWithOptions(r, &v, xdr.DecodeOptions{MaxInputLen: n})
	return v, err
}

// A reader with Len(): the decoder bounds allocations by it.
func decodeReader(b []byte) (xdr.LedgerCloseMeta, error) {
	var lcm xdr.LedgerCloseMeta
	_, err := xdr.Unmarshal(bytes.NewReader(b), &lcm)
	return lcm, err
}

// An explicit depth at the go-xdr default.
func decodeExplicit(b []byte) (xdr.LedgerCloseMeta, error) {
	var lcm xdr.LedgerCloseMeta
	_, err := xdr.UnmarshalWithOptions(bytes.NewReader(b), &lcm, xdr.DecodeOptions{MaxDepth: 1500})
	return lcm, err
}

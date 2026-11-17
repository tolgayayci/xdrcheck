// Package xdr206halt holds the XDR206 fixtures under overflowpolicy
// halt-ledger: past the bound the walk must stop with an error.
package xdr206halt

import (
	"errors"

	"github.com/stellar/go-stellar-sdk/xdr"
)

type limits struct{ MaxAuthDepth int }

var ErrAuthTreeTooDeep = errors.New("authorization tree deeper than the configured bound")

func walkReturnsNil(l limits, inv xdr.SorobanAuthorizedInvocation, depth int) error {
	if depth > l.MaxAuthDepth { // want `XDR206 \(warning\): the bound on xdr.SorobanAuthorizedInvocation gives up without an error`
		return nil
	}
	for _, sub := range inv.SubInvocations {
		if err := walkReturnsNil(l, sub, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func walkNoErrorResult(l limits, inv xdr.SorobanAuthorizedInvocation, depth int, out *[]string) {
	if depth > l.MaxAuthDepth { // want `XDR206 \(warning\): .* gives up without an error`
		return
	}
	for _, sub := range inv.SubInvocations {
		walkNoErrorResult(l, sub, depth+1, out)
	}
}

func walkContinue(l limits, inv xdr.SorobanAuthorizedInvocation, depth int) error {
	for _, sub := range inv.SubInvocations {
		if depth+1 > l.MaxAuthDepth { // want `XDR206 \(warning\): .* gives up without an error`
			continue
		}
		if err := walkContinue(l, sub, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func walkInBranchNoElse(l limits, inv xdr.SorobanAuthorizedInvocation, depth int) error {
	if depth < l.MaxAuthDepth { // want `XDR206 \(warning\): .* gives up without an error`
		for _, sub := range inv.SubInvocations {
			if err := walkInBranchNoElse(l, sub, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

// Compliant: a typed error.
func walkHalts(l limits, inv xdr.SorobanAuthorizedInvocation, depth int) error {
	if depth > l.MaxAuthDepth {
		return ErrAuthTreeTooDeep
	}
	for _, sub := range inv.SubInvocations {
		if err := walkHalts(l, sub, depth+1); err != nil {
			return err
		}
	}
	return nil
}

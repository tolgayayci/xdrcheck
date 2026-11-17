// Package xdr206 holds the XDR206 fixtures with no overflow policy
// declared: only a crash at the bound is reported.
package xdr206

import (
	"errors"
	"log"

	"github.com/stellar/go-stellar-sdk/xdr"
)

type limits struct{ MaxAuthDepth int }

var errTooDeep = errors.New("authorization tree deeper than the configured bound")

func walkPanics(l limits, inv xdr.SorobanAuthorizedInvocation, depth int) {
	if depth > l.MaxAuthDepth { // want `XDR206 \(warning\): the bound on xdr.SorobanAuthorizedInvocation ends the process.*declare which in the configuration`
		panic("auth tree too deep")
	}
	for _, sub := range inv.SubInvocations {
		walkPanics(l, sub, depth+1)
	}
}

func walkFatal(l limits, v xdr.ScVal, depth int) {
	if depth >= l.MaxAuthDepth { // want `XDR206 \(warning\): the bound on xdr.ScVal ends the process`
		log.Fatalf("value nested deeper than %d", l.MaxAuthDepth)
	}
	if vec, ok := v.GetVec(); ok && vec != nil {
		for _, x := range *vec {
			walkFatal(l, x, depth+1)
		}
	}
}

// Without a declared policy, stopping with an error and skipping are both
// left alone.
func walkError(l limits, inv xdr.SorobanAuthorizedInvocation, depth int) error {
	if depth > l.MaxAuthDepth {
		return errTooDeep
	}
	for _, sub := range inv.SubInvocations {
		if err := walkError(l, sub, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func walkSkip(l limits, inv xdr.SorobanAuthorizedInvocation, depth int) error {
	if depth > l.MaxAuthDepth {
		return nil
	}
	for _, sub := range inv.SubInvocations {
		if err := walkSkip(l, sub, depth+1); err != nil {
			return err
		}
	}
	return nil
}

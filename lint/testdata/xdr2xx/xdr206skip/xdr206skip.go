// Package xdr206skip holds the XDR206 fixtures under overflowpolicy
// skip-and-flag, with overflowflags [Truncated, MarkIncomplete]: past the
// bound the record must be marked incomplete.
package xdr206skip

import "github.com/stellar/go-stellar-sdk/xdr"

type limits struct{ MaxAuthDepth int }

type record struct {
	Contracts []string
	Truncated bool
}

func MarkIncomplete(r *record) { r.Truncated = true }

func walkUnflagged(l limits, inv xdr.SorobanAuthorizedInvocation, depth int, out *record) error {
	if depth > l.MaxAuthDepth { // want `XDR206 \(warning\): the bound on xdr.SorobanAuthorizedInvocation skips without marking the record incomplete`
		return nil
	}
	for _, sub := range inv.SubInvocations {
		if err := walkUnflagged(l, sub, depth+1, out); err != nil {
			return err
		}
	}
	return nil
}

func walkPanics(l limits, inv xdr.SorobanAuthorizedInvocation, depth int, out *record) {
	if depth > l.MaxAuthDepth { // want `XDR206 \(warning\): .* ends the process`
		panic("too deep")
	}
	for _, sub := range inv.SubInvocations {
		walkPanics(l, sub, depth+1, out)
	}
}

// Compliant: the record is flagged.
func walkFlagged(l limits, inv xdr.SorobanAuthorizedInvocation, depth int, out *record) error {
	if depth > l.MaxAuthDepth {
		out.Truncated = true
		return nil
	}
	for _, sub := range inv.SubInvocations {
		if err := walkFlagged(l, sub, depth+1, out); err != nil {
			return err
		}
	}
	return nil
}

func walkMarked(l limits, inv xdr.SorobanAuthorizedInvocation, depth int, out *record) error {
	if depth > l.MaxAuthDepth {
		MarkIncomplete(out)
		return nil
	}
	for _, sub := range inv.SubInvocations {
		if err := walkMarked(l, sub, depth+1, out); err != nil {
			return err
		}
	}
	return nil
}

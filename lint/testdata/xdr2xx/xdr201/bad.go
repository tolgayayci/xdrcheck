// Package xdr201 holds the XDR201 fixtures: recursion over a
// self-referential xdr type with no depth bound.
package xdr201

import "github.com/stellar/go-stellar-sdk/xdr"

// (a) A named function over SubInvocations.
func countContracts(inv xdr.SorobanAuthorizedInvocation) int {
	n := 0
	if inv.Function.Type == xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn {
		n++
	}
	for _, sub := range inv.SubInvocations {
		n += countContracts(sub) // want `XDR201 \(warning\): unbounded recursion over xdr.SorobanAuthorizedInvocation in countContracts`
	}
	return n
}

// (b) A closure assigned to a variable and calling itself through it.
func collect(entries []xdr.SorobanAuthorizationEntry) []string {
	var out []string
	var walk func(inv xdr.SorobanAuthorizedInvocation)
	walk = func(inv xdr.SorobanAuthorizedInvocation) {
		if fn, ok := inv.Function.GetContractFn(); ok {
			s, _ := fn.ContractAddress.String()
			out = append(out, s)
		}
		for _, sub := range inv.SubInvocations {
			walk(sub) // want `XDR201 \(warning\): unbounded recursion over xdr.SorobanAuthorizedInvocation in walk \(a closure in collect\)`
		}
	}
	for _, e := range entries {
		walk(e.RootInvocation)
	}
	return out
}

// (c) Mutual recursion between a value and a map walker: one report for the
// component.
func walkVal(v xdr.ScVal) int {
	switch v.Type {
	case xdr.ScValTypeScvVec:
		n := 0
		if vec, ok := v.GetVec(); ok && vec != nil {
			for _, x := range *vec {
				n += walkVal(x) // want `XDR201 \(warning\): unbounded recursion over xdr.ScVal in walkVal`
			}
		}
		return n
	case xdr.ScValTypeScvMap:
		if m, ok := v.GetMap(); ok && m != nil {
			return walkMap(m)
		}
	}
	return 1
}

func walkMap(m *xdr.ScMap) int {
	n := 0
	for _, e := range *m {
		n += walkVal(e.Key) + walkVal(e.Val)
	}
	return n
}

// (d) Nested delegates.
func delegateCount(d xdr.SorobanDelegateSignature) int {
	n := 1
	for _, nd := range d.NestedDelegates {
		n += delegateCount(nd) // want `XDR201 \(warning\): unbounded recursion over xdr.SorobanDelegateSignature`
	}
	return n
}

// (e) A depth parameter passed as depth+1 but never compared.
func depthNeverChecked(inv xdr.SorobanAuthorizedInvocation, depth int) int {
	total := depth
	for _, sub := range inv.SubInvocations {
		total += depthNeverChecked(sub, depth+1) // want `XDR201 \(warning\): unbounded recursion`
	}
	return total
}

// (f) A per-level merge of the children's results makes it an error.
func contractsMerged(inv xdr.SorobanAuthorizedInvocation) []string {
	var out []string
	if fn, ok := inv.Function.GetContractFn(); ok {
		s, _ := fn.ContractAddress.String()
		out = append(out, s)
	}
	for _, sub := range inv.SubInvocations {
		out = append(out, contractsMerged(sub)...) // want `XDR201 \(error\): .*per-level merge is O\(n·depth\)`
	}
	return out
}

// (g) A loop index is not a depth: comparing it bounds the fan-out of one
// level, not the depth of the tree.
func firstChildren(inv xdr.SorobanAuthorizedInvocation) int {
	n := 1
	for i := 0; i < len(inv.SubInvocations); i++ {
		if i >= 8 {
			break
		}
		n += firstChildren(inv.SubInvocations[i]) // want `XDR201 \(warning\): unbounded recursion over xdr.SorobanAuthorizedInvocation in firstChildren`
	}
	return n
}

// (h) A local counter starts again at every level, so it bounds nothing.
func localCounter(inv xdr.SorobanAuthorizedInvocation) error {
	visited := 0
	for _, sub := range inv.SubInvocations {
		visited++
		if visited > 100 {
			return nil
		}
		if err := localCounter(sub); err != nil { // want `XDR201 \(warning\): unbounded recursion over xdr.SorobanAuthorizedInvocation in localCounter`
			return err
		}
	}
	return nil
}

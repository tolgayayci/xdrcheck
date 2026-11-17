// Package xdr202 holds the XDR202 fixtures: iterative walkers whose
// worklist nothing bounds.
package xdr202

import "github.com/stellar/go-stellar-sdk/xdr"

// The natural rewrite that silences XDR201 and moves the problem.
func contractsIterative(root xdr.SorobanAuthorizedInvocation) []string {
	var out []string
	stack := []xdr.SorobanAuthorizedInvocation{root}
	for len(stack) > 0 {
		inv := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if fn, ok := inv.Function.GetContractFn(); ok {
			s, _ := fn.ContractAddress.String()
			out = append(out, s)
		}
		stack = append(stack, inv.SubInvocations...) // want `XDR202 \(warning\): worklist stack of xdr.SorobanAuthorizedInvocation grows`
	}
	return out
}

// A queue of values.
func countValues(v xdr.ScVal) int {
	n := 0
	queue := []xdr.ScVal{v}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		n++
		if cur.Vec != nil && *cur.Vec != nil {
			queue = append(queue, (**cur.Vec)...) // want `XDR202 \(warning\): worklist queue of xdr.ScVal`
		}
	}
	return n
}

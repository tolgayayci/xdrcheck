package xdr202

import (
	"errors"

	"github.com/stellar/go-stellar-sdk/xdr"
)

var errTooMany = errors.New("authorization tree larger than the configured bound")

// An explicit stack with a node counter and a length check.
func contractsBounded(root xdr.SorobanAuthorizedInvocation, maxNodes int) ([]string, error) {
	var out []string
	stack := []xdr.SorobanAuthorizedInvocation{root}
	visited := 0
	for len(stack) > 0 {
		visited++
		if visited > maxNodes || len(stack) > maxNodes {
			return nil, errTooMany
		}
		inv := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if fn, ok := inv.Function.GetContractFn(); ok {
			s, _ := fn.ContractAddress.String()
			out = append(out, s)
		}
		stack = append(stack, inv.SubInvocations...)
	}
	return out, nil
}

// The bound in the loop condition.
func countBounded(v xdr.ScVal, maxNodes int) int {
	n := 0
	queue := []xdr.ScVal{v}
	for len(queue) > 0 && n < maxNodes {
		cur := queue[0]
		queue = queue[1:]
		n++
		if cur.Vec != nil && *cur.Vec != nil {
			queue = append(queue, (**cur.Vec)...)
		}
	}
	return n
}

// A slice that is only ever appended to is not a worklist.
func flatten(entries []xdr.SorobanAuthorizationEntry) []xdr.SorobanAuthorizedInvocation {
	var all []xdr.SorobanAuthorizedInvocation
	for i := 0; i < len(entries); i++ {
		all = append(all, entries[i].RootInvocation.SubInvocations...)
	}
	return all
}

package xdr201

import (
	"errors"

	"github.com/stellar/go-stellar-sdk/xdr"
)

var errTooDeep = errors.New("structure deeper than the configured bound")

type config struct{ MaxAuthDepth int }

// (a) A depth parameter compared with a bound from configuration.
func walkBounded(cfg config, inv xdr.SorobanAuthorizedInvocation, depth int) error {
	if depth > cfg.MaxAuthDepth {
		return errTooDeep
	}
	for _, sub := range inv.SubInvocations {
		if err := walkBounded(cfg, sub, depth+1); err != nil {
			return err
		}
	}
	return nil
}

// (b) A counter in a receiver field, decremented on the way out.
type walker struct{ depth, max int }

func (w *walker) visit(v xdr.ScVal) error {
	w.depth++
	defer func() { w.depth-- }()
	if w.depth > w.max {
		return errTooDeep
	}
	if vec, ok := v.GetVec(); ok && vec != nil {
		for _, x := range *vec {
			if err := w.visit(x); err != nil {
				return err
			}
		}
	}
	return nil
}

// (c) The recursion runs inside the in-bound branch.
func walkInBranch(inv xdr.SorobanAuthorizedInvocation, depth, max int) int {
	n := 1
	if depth < max {
		for _, sub := range inv.SubInvocations {
			n += walkInBranch(sub, depth+1, max)
		}
	}
	return n
}

// (d) Recursion over a type that is not recursive.
func assetDepth(a xdr.Asset, n int) int {
	if n == 0 {
		return 0
	}
	return assetDepth(a, n-1) + 1
}

// (e) A depth budget whose method is configured (budgetmethods).
type budget struct{ left int }

func (b *budget) Enter() error {
	if b.left == 0 {
		return errTooDeep
	}
	b.left--
	return nil
}

func walkWithBudget(b *budget, d xdr.SorobanDelegateSignature) error {
	if err := b.Enter(); err != nil {
		return err
	}
	for _, nd := range d.NestedDelegates {
		if err := walkWithBudget(b, nd); err != nil {
			return err
		}
	}
	return nil
}

// (f) A budget counted down and compared with zero.
func walkCountdown(inv xdr.SorobanAuthorizedInvocation, remaining int) error {
	if remaining <= 0 {
		return errTooDeep
	}
	for _, sub := range inv.SubInvocations {
		if err := walkCountdown(sub, remaining-1); err != nil {
			return err
		}
	}
	return nil
}

// (g) The same budget tested for equality, recursing inside the in-bound
// branch.
func walkCountdownInBranch(v xdr.ScVal, remaining uint32) int {
	n := 1
	if remaining != 0 {
		if vec, ok := v.GetVec(); ok && vec != nil {
			for _, x := range *vec {
				n += walkCountdownInBranch(x, remaining-1)
			}
		}
	}
	return n
}

// (h) A captured depth counter of a closure, incremented around the call.
func closureDepth(root xdr.ScVal, max int) int {
	depth, n := 0, 0
	var walk func(v xdr.ScVal)
	walk = func(v xdr.ScVal) {
		n++
		if depth >= max {
			return
		}
		depth++
		if vec, ok := v.GetVec(); ok && vec != nil {
			for _, x := range *vec {
				walk(x)
			}
		}
		depth--
	}
	walk(root)
	return n
}

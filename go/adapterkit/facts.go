package adapterkit

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// SortFacts orders a ledger's facts as the protocol asks, so that two sessions over the same unit give
// byte-identical observation sets: by transaction index, operation index, then the fact's JSON text.
func SortFacts(l *Ledger) {
	key := func(loc Locator, v any) string {
		tx, op := -1, -1
		if loc.TxIndex != nil {
			tx = *loc.TxIndex
		}
		if loc.OpIndex != nil {
			op = *loc.OpIndex
		}
		b, _ := json.Marshal(v)
		return fmt.Sprintf("%010d|%010d|%s", tx+1, op+1, b)
	}
	sortBy(l.Participants, func(x ObsParticipant) string { return key(x.Locator, x) })
	sortBy(l.StateChanges, func(x ObsStateChange) string { return key(x.Locator, x) })
	sortBy(l.Movements, func(x ObsMovement) string { return key(x.Locator, x) })
	sortBy(l.Addresses, func(x ObsAddress) string { return key(x.Locator, x) })
}

func sortBy[T any](xs []T, key func(T) string) {
	keys := make([]string, len(xs))
	idx := make([]int, len(xs))
	for i := range xs {
		idx[i], keys[i] = i, key(xs[i])
	}
	slices.SortStableFunc(idx, func(a, b int) int { return strings.Compare(keys[a], keys[b]) })
	sorted := make([]T, len(xs))
	for i, j := range idx {
		sorted[i] = xs[j]
	}
	copy(xs, sorted)
}

// Int64 returns a pointer to n, for the protocol's nullable integers (cursor_before, last_ledger, …).
func Int64(n int64) *int64 { return &n }

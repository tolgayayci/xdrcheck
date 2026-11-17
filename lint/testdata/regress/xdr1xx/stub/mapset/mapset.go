// Package mapset stands in for github.com/deckarep/golang-set/v2, which the
// regression fixtures import but the lint module does not depend on. Only
// the API the copied files use is declared.
package mapset

// Set is a set of comparable values.
type Set[T comparable] interface {
	Add(val T) bool
	Union(other Set[T]) Set[T]
	ToSlice() []T
}

type unsafeSet[T comparable] map[T]struct{}

// NewThreadUnsafeSet returns a set holding vals.
func NewThreadUnsafeSet[T comparable](vals ...T) Set[T] {
	s := unsafeSet[T]{}
	for _, v := range vals {
		s[v] = struct{}{}
	}
	return s
}

func (s unsafeSet[T]) Add(val T) bool {
	_, had := s[val]
	s[val] = struct{}{}
	return !had
}

func (s unsafeSet[T]) Union(other Set[T]) Set[T] {
	out := unsafeSet[T]{}
	for v := range s {
		out[v] = struct{}{}
	}
	for _, v := range other.ToSlice() {
		out[v] = struct{}{}
	}
	return out
}

func (s unsafeSet[T]) ToSlice() []T {
	out := make([]T, 0, len(s))
	for v := range s {
		out = append(out, v)
	}
	return out
}

// Package set stands in for github.com/deckarep/golang-set/v2 in the
// regression fixtures: the subset of its API the trimmed files call, with
// the same names, so the copied code compiles unchanged.
package set

// Set is a set of comparable values.
type Set[T comparable] interface {
	Add(v T) bool
	Append(vs ...T) int
	Contains(vs ...T) bool
	Each(f func(T) bool)
	IsEmpty() bool
	ToSlice() []T
	Union(other Set[T]) Set[T]
}

type mapSet[T comparable] map[T]struct{}

// NewThreadUnsafeSet returns a set holding vals.
func NewThreadUnsafeSet[T comparable](vals ...T) Set[T] {
	s := mapSet[T]{}
	s.Append(vals...)
	return s
}

// NewThreadUnsafeSetWithSize returns an empty set.
func NewThreadUnsafeSetWithSize[T comparable](n int) Set[T] { return make(mapSet[T], n) }

func (s mapSet[T]) Add(v T) bool {
	_, had := s[v]
	s[v] = struct{}{}
	return !had
}

func (s mapSet[T]) Append(vs ...T) int {
	n := 0
	for _, v := range vs {
		if s.Add(v) {
			n++
		}
	}
	return n
}

func (s mapSet[T]) Contains(vs ...T) bool {
	for _, v := range vs {
		if _, ok := s[v]; !ok {
			return false
		}
	}
	return true
}

func (s mapSet[T]) Each(f func(T) bool) {
	for v := range s {
		if f(v) {
			return
		}
	}
}

func (s mapSet[T]) IsEmpty() bool { return len(s) == 0 }

func (s mapSet[T]) ToSlice() []T {
	out := make([]T, 0, len(s))
	for v := range s {
		out = append(out, v)
	}
	return out
}

func (s mapSet[T]) Union(other Set[T]) Set[T] {
	out := mapSet[T]{}
	for v := range s {
		out[v] = struct{}{}
	}
	other.Each(func(v T) bool { out[v] = struct{}{}; return false })
	return out
}

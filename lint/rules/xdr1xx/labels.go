package xdr1xx

import (
	"go/token"
	"math/bits"
)

// An aspect is what a tainted value may be wrong about. One source can carry
// several: memo text is both memo-derived (XDR101) and unchecked text
// (XDR103).
type aspect int

const (
	aMemo aspect = iota // derived from the transaction memo (XDR101)
	aAddr               // an address string that may be in muxed form, M… or W… (XDR102)
	aKind               // an address string that may be of a non-account kind, B…, L…, P…, T… or X… (XDR102)
	aUTF8               // may be invalid UTF-8 (XDR103)
	aNUL                // may contain NUL bytes (XDR103)
	nAspects
)

type aspectMask uint8

const (
	mMemo aspectMask = 1 << aMemo
	mAddr aspectMask = 1 << aAddr
	mKind aspectMask = 1 << aKind
	// mAddress is both XDR102 aspects.
	mAddress            = mAddr | mKind
	mUTF8    aspectMask = 1 << aUTF8
	mNUL     aspectMask = 1 << aNUL
	mText               = mUTF8 | mNUL
)

func (m aspectMask) has(a aspect) bool { return m&(1<<a) != 0 }

// An origin is one source occurrence: the call, field read, type assertion
// or parameter where tainted data enters the package.
type origin struct {
	pos     token.Pos
	aspects aspectMask
	what    string // the source as written in a message, for example "xdr.ScAddress.String()"
	why     string // XDR102: what the source can render
	info    bool   // XDR103: a host-restricted symbol, reported at info severity only
}

// A set is a bit set of labels; label = origin index × nAspects + aspect.
type set []uint64

func label(o int, a aspect) int { return o*int(nAspects) + int(a) }

func (s *set) add(l int) bool {
	w, b := l/64, uint(l%64)
	for len(*s) <= w {
		*s = append(*s, 0)
	}
	if (*s)[w]&(1<<b) != 0 {
		return false
	}
	(*s)[w] |= 1 << b
	return true
}

// union adds o to s and reports whether s grew.
func (s *set) union(o set) bool {
	grew := false
	for len(*s) < len(o) {
		*s = append(*s, 0)
	}
	for i, w := range o {
		if n := (*s)[i] | w; n != (*s)[i] {
			(*s)[i] = n
			grew = true
		}
	}
	return grew
}

func (s set) empty() bool {
	for _, w := range s {
		if w != 0 {
			return false
		}
	}
	return true
}

// each calls f for every label of s, in increasing order.
func (s set) each(f func(o int, a aspect)) {
	for i, w := range s {
		for w != 0 {
			b := bits.TrailingZeros64(w)
			w &^= 1 << uint(b)
			l := i*64 + b
			f(l/int(nAspects), aspect(l%int(nAspects)))
		}
	}
}

// any reports whether s holds a label with an aspect in m.
func (s set) any(m aspectMask) bool {
	found := false
	s.each(func(_ int, a aspect) {
		if m.has(a) {
			found = true
		}
	})
	return found
}

// drop returns a copy of s without the labels whose aspect is in m.
func (s set) drop(m aspectMask) set {
	if m == 0 || s.empty() {
		return s
	}
	var out set
	s.each(func(o int, a aspect) {
		if !m.has(a) {
			out.add(label(o, a))
		}
	})
	return out
}

// minus returns a new set with the labels of s that are not in o.
func (s set) minus(o set) set {
	var out set
	for i, w := range s {
		if i < len(o) {
			w &^= o[i]
		}
		if w != 0 {
			for len(out) <= i {
				out = append(out, 0)
			}
			out[i] = w
		}
	}
	return out
}

// origins returns the origins of s that carry an aspect in m, in order.
func (s set) origins(m aspectMask) []int {
	var out []int
	last := -1
	s.each(func(o int, a aspect) {
		if m.has(a) && o != last {
			out = append(out, o)
			last = o
		}
	})
	return out
}

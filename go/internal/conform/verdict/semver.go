package verdict

import (
	"fmt"
	"strconv"
	"strings"
)

// version is a parsed semantic version. A leading "v" (Go module versions) is ignored.
type version struct {
	nums [3]int
	pre  []string // prerelease identifiers; nil for a release
}

func parseVersion(s string) (version, error) {
	var v version
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i] // build metadata does not order
	}
	core, pre, hasPre := strings.Cut(s, "-")
	parts := strings.Split(core, ".")
	if len(parts) == 0 || len(parts) > 3 || core == "" {
		return v, fmt.Errorf("version %q is not MAJOR.MINOR.PATCH", s)
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return v, fmt.Errorf("version %q is not MAJOR.MINOR.PATCH", s)
		}
		v.nums[i] = n
	}
	if hasPre {
		v.pre = strings.Split(pre, ".")
	}
	return v, nil
}

func (a version) cmp(b version) int {
	for i := range a.nums {
		if a.nums[i] != b.nums[i] {
			if a.nums[i] < b.nums[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case a.pre == nil && b.pre == nil:
		return 0
	case a.pre == nil:
		return 1
	case b.pre == nil:
		return -1
	}
	for i := 0; i < len(a.pre) && i < len(b.pre); i++ {
		x, y := a.pre[i], b.pre[i]
		nx, ex := strconv.Atoi(x)
		ny, ey := strconv.Atoi(y)
		switch {
		case ex == nil && ey == nil && nx != ny:
			if nx < ny {
				return -1
			}
			return 1
		case ex == nil && ey != nil:
			return -1
		case ex != nil && ey == nil:
			return 1
		case x != y:
			if x < y {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(a.pre) < len(b.pre):
		return -1
	case len(a.pre) > len(b.pre):
		return 1
	}
	return 0
}

// CompareVersions orders two semantic versions (-1, 0, 1).
func CompareVersions(a, b string) (int, error) {
	va, err := parseVersion(a)
	if err != nil {
		return 0, err
	}
	vb, err := parseVersion(b)
	if err != nil {
		return 0, err
	}
	return va.cmp(vb), nil
}

// InRange reports whether version satisfies a semver range as manifest known divergences write them:
// alternatives joined by "||", each a space-separated list of comparators (=, <, <=, >, >=, or a bare version
// for equality), a hyphen range "A - B" (inclusive), or "*". A commit range ("A..B", for repositories) is not a
// version range and is an error.
func InRange(ver, rng string) (bool, error) {
	if strings.Contains(rng, "..") {
		return false, fmt.Errorf("range %q is a commit range, not a version range", rng)
	}
	v, err := parseVersion(ver)
	if err != nil {
		return false, err
	}
	// Every alternative and comparator is parsed, whatever the version: a range is valid or not on its own.
	in := false
	for _, alt := range strings.Split(rng, "||") {
		ok, err := satisfiesAll(v, strings.TrimSpace(alt))
		if err != nil {
			return false, fmt.Errorf("range %q: %w", rng, err)
		}
		in = in || ok
	}
	return in, nil
}

func satisfiesAll(v version, set string) (bool, error) {
	if set == "*" {
		return true, nil
	}
	if set == "" {
		return false, fmt.Errorf("empty alternative")
	}
	if lo, hi, ok := strings.Cut(set, " - "); ok {
		a, err := parseVersion(lo)
		if err != nil {
			return false, err
		}
		b, err := parseVersion(hi)
		if err != nil {
			return false, err
		}
		return v.cmp(a) >= 0 && v.cmp(b) <= 0, nil
	}
	all := true
	for _, c := range strings.Fields(set) {
		op := ""
		for _, p := range []string{">=", "<=", ">", "<", "="} {
			if strings.HasPrefix(c, p) {
				op = p
				break
			}
		}
		w, err := parseVersion(c[len(op):])
		if err != nil {
			return false, err
		}
		d := v.cmp(w)
		ok := false
		switch op {
		case "", "=":
			ok = d == 0
		case "<":
			ok = d < 0
		case "<=":
			ok = d <= 0
		case ">":
			ok = d > 0
		case ">=":
			ok = d >= 0
		}
		all = all && ok
	}
	return all, nil
}

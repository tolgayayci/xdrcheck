package manifest

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Substitution of ${derived.<path>} tokens (docs/manifest.md §4.6): any string inside expect (and api.input) may
// carry tokens; <path> is dot-separated keys or array indexes into the variant's derived block. Substitution is
// textual, single-pass, applies to string values only (never keys), and a token with no value is an error.

var (
	tokenRe     = regexp.MustCompile(`\$\{derived\.([^}]*)\}`)
	tokenPathRe = regexp.MustCompile(`^[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)*$`)
)

// HasTokens reports whether s contains a ${derived.…} token.
func HasTokens(s string) bool { return strings.Contains(s, "${derived.") }

// LookupDerived returns the value at a dot-separated path inside derived.
func LookupDerived(derived map[string]any, path string) (any, error) {
	if !tokenPathRe.MatchString(path) {
		return nil, fmt.Errorf("malformed derived path %q", path)
	}
	var cur any = derived
	for _, part := range strings.Split(path, ".") {
		switch node := cur.(type) {
		case map[string]any:
			v, ok := node[part]
			if !ok {
				return nil, fmt.Errorf("derived.%s: no value", path)
			}
			cur = v
		case []any:
			i, err := strconv.Atoi(part)
			if err != nil || i < 0 || i >= len(node) {
				return nil, fmt.Errorf("derived.%s: %q is not an index of a %d-element array", path, part, len(node))
			}
			cur = node[i]
		default:
			return nil, fmt.Errorf("derived.%s: cannot descend into a %T", path, cur)
		}
	}
	return cur, nil
}

// ResolveString replaces every ${derived.<path>} token in s. The value must be a string or a number.
func ResolveString(s string, derived map[string]any) (string, error) {
	if !HasTokens(s) {
		return s, nil
	}
	var firstErr error
	out := tokenRe.ReplaceAllStringFunc(s, func(tok string) string {
		path := tokenRe.FindStringSubmatch(tok)[1]
		v, err := LookupDerived(derived, path)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			return tok
		}
		switch x := v.(type) {
		case string:
			return x
		case json.Number:
			return x.String()
		default:
			if firstErr == nil {
				firstErr = fmt.Errorf("derived.%s is a %T, not a string", path, v)
			}
			return tok
		}
	})
	if firstErr != nil {
		return "", firstErr
	}
	// A "${derived." that the token pattern did not consume (an unterminated token) is an error too.
	if HasTokens(tokenRe.ReplaceAllString(s, "")) {
		return "", fmt.Errorf("malformed token in %q", s)
	}
	return out, nil
}

// ResolveExpect returns a copy of e with every token replaced by its value in derived.
func ResolveExpect(e *Expect, derived map[string]any) (*Expect, error) {
	var out Expect
	if err := resolveVia(e, derived, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ResolveInput returns a copy of an api input with every token replaced.
func ResolveInput(in map[string]any, derived map[string]any) (map[string]any, error) {
	v, err := resolveValue(in, derived)
	if err != nil {
		return nil, err
	}
	m, _ := v.(map[string]any)
	return m, nil
}

// resolveVia round-trips src through a generic JSON tree, substitutes strings and decodes strictly into dst.
func resolveVia(src any, derived map[string]any, dst any) error {
	raw, err := json.Marshal(src)
	if err != nil {
		return err
	}
	var tree any
	if err := decodeStrict(raw, &tree); err != nil {
		return err
	}
	tree, err = resolveValue(tree, derived)
	if err != nil {
		return err
	}
	raw, err = json.Marshal(tree)
	if err != nil {
		return err
	}
	return decodeStrict(raw, dst)
}

func resolveValue(v any, derived map[string]any) (any, error) {
	switch x := v.(type) {
	case string:
		return ResolveString(x, derived)
	case []any:
		out := make([]any, len(x))
		for i, item := range x {
			r, err := resolveValue(item, derived)
			if err != nil {
				return nil, err
			}
			out[i] = r
		}
		return out, nil
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, item := range x {
			r, err := resolveValue(item, derived)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", k, err)
			}
			out[k] = r
		}
		return out, nil
	}
	return v, nil
}

// containsTokens reports whether any string inside v (after a JSON round trip) carries a token.
func containsTokens(v any) bool {
	raw, err := json.Marshal(v)
	return err == nil && strings.Contains(string(raw), "${derived.")
}

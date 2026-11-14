package verdict

import (
	"fmt"
	"sort"
	"strings"

	"github.com/tolgayayci/xdrcheck/go/internal/conform"
	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
)

// ExpectedValue is a one-line, human-readable statement of what the corpus expects of a cell at one level: the
// facts the engine compares, read from the manifest entry and its variant only (never from a reader under
// test). It is what the summary and the cross-SDK page print as "expected".
func ExpectedValue(e *manifest.Entry, v *manifest.Variant, level string) string {
	refuse, exact := MustRefuse(e, v), ExactOrRefuse(e, v)
	lenient := ""
	if e.CoreBehaviour != nil && e.CoreBehaviour.Accepts && refuse {
		lenient = "; stellar-core's own decoder accepts it, so the stellar-core column conforms by accepting"
	}
	switch {
	case exact:
		return "refused, or accepted with exactly " + apiExpectation(e.API) + lenient
	case refuse:
		s := "refused"
		if r := e.Expect.Reject; r != nil && r.Reason != "" {
			s += " (reason " + r.Reason + ")"
		}
		return s + lenient
	}
	switch level {
	case "L0":
		if v == nil {
			return "decoded and re-encoded byte for byte"
		}
		return fmt.Sprintf("all %d bytes decoded as %s and re-encoded byte for byte (sha256 %s)", v.Blob.Bytes, v.XDRType, abbrev(v.Blob.SHA256))
	case "L1":
		return expectedObject(v)
	case "L2":
		if v == nil || v.Resolved == nil || len(v.Resolved.Values) == 0 {
			return "the decoded value as the sidecar holds it"
		}
		var parts []string
		for i, w := range v.Resolved.Values {
			if i == 3 {
				parts = append(parts, fmt.Sprintf("and %d more", len(v.Resolved.Values)-3))
				break
			}
			parts = append(parts, w.Path+" = "+short(mustJSON(w.Equals)))
		}
		return strings.Join(parts, "; ")
	case "L3":
		n := e.Expect.Native
		if v != nil && v.Resolved != nil && v.Resolved.Native != nil {
			n = v.Resolved.Native
		}
		var parts []string
		if n != nil && n.MapEntries != nil {
			parts = append(parts, fmt.Sprintf("a native map with %d entries", *n.MapEntries))
		}
		if n != nil && n.BytesPreserved != nil {
			parts = append(parts, fmt.Sprintf("bytes preserved: %v", *n.BytesPreserved))
		}
		if len(parts) == 0 {
			return "converted to a native value"
		}
		return strings.Join(parts, ", ")
	case "L4":
		return apiExpectation(e.API)
	case "spec":
		s := e.Expect.Spec
		if s == nil {
			return "the contract interface the bytes hold"
		}
		names := make([]string, 0, len(s.Entries))
		for _, x := range s.Entries {
			names = append(names, x.Kind+" "+x.Name)
		}
		if len(names) > 4 {
			names = append(names[:4], fmt.Sprintf("and %d more", len(s.Entries)-4))
		}
		if len(s.Entries) == 0 {
			return "no spec entries"
		}
		return fmt.Sprintf("%d spec entries: %s", len(s.Entries), strings.Join(names, ", "))
	case conform.JSONLevel:
		return "JSON valid against the converter's own schema, and back to the same bytes"
	}
	return "accepted"
}

// expectedObject states a variant's L1 expectation: the ledger's counts and the focus transaction, or the
// object's hash and derived facts.
func expectedObject(v *manifest.Variant) string {
	if v == nil {
		return "parsed by the SDK's object layer"
	}
	var parts []string
	if v.XDRType == conform.LedgerXDRType {
		if r := v.Resolved; r != nil && r.Ledger != nil {
			if n := r.Ledger.Transactions; n != nil {
				parts = append(parts, fmt.Sprintf("%d transactions parsed", *n))
			}
			if n := r.Ledger.Operations; n != nil {
				parts = append(parts, fmt.Sprintf("%d operations", *n))
			}
		}
		if hs, ok := derivedStrings(v.Derived, "tx_hashes"); ok {
			parts = append(parts, fmt.Sprintf("%d transaction hashes in apply order", len(hs)))
		}
	}
	if h := derivedString(v.Derived, "tx_hash"); h != "" {
		parts = append(parts, "tx hash "+abbrev(h))
	} else if v.Focus != nil && v.Focus.TxHash != "" {
		parts = append(parts, "focus tx hash "+abbrev(v.Focus.TxHash))
	}
	l1 := derivedMap(v.Derived, "l1")
	keys := make([]string, 0, len(l1))
	for k := range l1 {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		parts = append(parts, k+" "+short(mustJSON(l1[k])))
	}
	if len(parts) == 0 {
		return "parsed by the SDK's object layer"
	}
	return strings.Join(parts, ", ")
}

func apiExpectation(a *manifest.APIVector) string {
	if a == nil {
		return "the expected result"
	}
	var parts []string
	if len(a.ExpectValue) > 0 {
		parts = append(parts, "value "+short(a.ExpectValue))
	}
	if a.ExpectXDRHex != "" {
		parts = append(parts, "xdr "+abbrev(a.ExpectXDRHex))
	}
	if len(parts) == 0 {
		return "accepted"
	}
	return strings.Join(parts, ", ")
}

// abbrev shortens a long hex string to its first 16 characters.
func abbrev(s string) string {
	if len(s) > 20 {
		return s[:16] + "…"
	}
	return s
}

package memtest

import (
	"fmt"
	"os"
	"reflect"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
)

// Pick is one replayable ledger variant of the corpus chosen for its size or depth.
type Pick struct {
	Entry   string `json:"entry"`
	Network string `json:"network"`
	Bytes   int64  `json:"bytes"`
	Depth   int    `json:"depth"` // nesting levels of the decoded LedgerCloseMeta
}

// Extremes finds the corpus's maximum-length and maximum-depth ledgers among the variants a single unit can
// replay (kind ledger, not sdk-only, not needing earlier state): the most bytes, and the deepest nesting of the
// decoded value (structs, unions and arrays, opaque bytes not counted). Ties go to the first entry by ID.
func Extremes(c *manifest.Corpus) (longest, deepest Pick, err error) {
	for _, e := range c.Entries {
		if e.Kind != "ledger" || e.IndexerScope() == "sdk-only" || e.RequiresPriorState() {
			continue
		}
		for _, v := range e.Variants {
			if v.Network == "none" || v.Blob.Path == "" {
				continue
			}
			raw, err := os.ReadFile(c.BlobPath(v))
			if err != nil {
				return Pick{}, Pick{}, err
			}
			var m xdr.LedgerCloseMeta
			if err := m.UnmarshalBinary(raw); err != nil {
				return Pick{}, Pick{}, fmt.Errorf("%s %s: %w", e.ID, v.Network, err)
			}
			p := Pick{Entry: e.ID, Network: v.Network, Bytes: v.Blob.Bytes, Depth: Depth(reflect.ValueOf(m))}
			if p.Bytes > longest.Bytes {
				longest = p
			}
			if p.Depth > deepest.Depth {
				deepest = p
			}
		}
	}
	if longest.Entry == "" {
		return Pick{}, Pick{}, fmt.Errorf("the corpus has no replayable ledger")
	}
	return longest, deepest, nil
}

// Depth is the nesting depth of a decoded XDR value: one level per struct (a union is a struct holding its
// arm) and per array or slice; byte strings and scalars add none.
func Depth(v reflect.Value) int {
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			return 0
		}
		return Depth(v.Elem())
	case reflect.Struct:
		d := 0
		for i := 0; i < v.NumField(); i++ {
			d = max(d, Depth(v.Field(i)))
		}
		return d + 1
	case reflect.Slice, reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return 0
		}
		d := 0
		for i := 0; i < v.Len(); i++ {
			d = max(d, Depth(v.Index(i)))
		}
		return d + 1
	}
	return 0
}

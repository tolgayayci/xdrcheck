package manifest

// Key-selected pinpoints (manifest.md, expect.values). stellar-core writes an operation's ledger-entry changes
// from an unordered map, so the position of one entry's change in a change list differs between runs and
// passphrases. A pinpoint with select {in, key, change?} names the element of the array at the pointer in by
// its ledger key, and its path is relative to that element. An element matches when it is
//
//   - a LedgerEntryChange ({created|updated|state|restored: LedgerEntry} or {removed: LedgerKey}) whose entry
//     has the key (whose removed key equals it), with the arm change when one is given;
//   - a LedgerEntry with the key (only without change);
//   - a LedgerKey equal to key (only without change).
//
// An entry has a key when the key's arm names the entry's data arm and every field of the key is a field of the
// entry with the same value (a LedgerKey arm's fields are a subset of its entry's, under the same names); a
// config_setting key matches the entry whose union arm is its config_setting_id. Exactly one element must
// match. The Rust oracle (xdrcheck-corpus verify) applies the same rules.
//
// Drivers receive plain JSON Pointers (driver protocol, L2 pinpoints), so Load resolves every selection against
// the variant's sidecar and the orchestrator sends, and the verdict engine compares, the resolved pointer.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/klauspost/compress/zstd"
)

var changeArms = map[string]bool{"created": true, "updated": true, "removed": true, "state": true, "restored": true}

// HasSelect reports whether any pinpoint of the block is key-selected.
func (e *Expect) HasSelect() bool {
	for _, v := range e.Values {
		if v.Select != nil {
			return true
		}
	}
	return false
}

// ResolveSelect returns the JSON Pointer of the one element of doc that sel names (tokens already replaced).
func ResolveSelect(doc any, sel *Select) (string, error) {
	if sel.Change != "" && !changeArms[sel.Change] {
		return "", fmt.Errorf("select.change %q is not a change type", sel.Change)
	}
	key, ok := sel.Key.(map[string]any)
	if !ok || len(key) != 1 {
		return "", fmt.Errorf("select.key %s is not a ledger key", short(sel.Key))
	}
	at, found := Pointer(doc, sel.In)
	if !found {
		return "", fmt.Errorf("select.in %s does not resolve in the sidecar", sel.In)
	}
	items, ok := at.([]any)
	if !ok {
		return "", fmt.Errorf("select.in %s is not an array", sel.In)
	}
	var hits []int
	for i, el := range items {
		if elementMatches(el, key, sel.Change) {
			hits = append(hits, i)
		}
	}
	what := short(sel.Key)
	if sel.Change != "" {
		what = "a `" + sel.Change + "` change of " + what
	}
	switch len(hits) {
	case 1:
		return sel.In + "/" + strconv.Itoa(hits[0]), nil
	case 0:
		return "", fmt.Errorf("select: no element of %s is %s (%d elements)", sel.In, what, len(items))
	default:
		return "", fmt.Errorf("select: elements %v of %s are all %s; add `change` or a narrower `in`", hits, sel.In, what)
	}
}

func elementMatches(el any, key map[string]any, change string) bool {
	if o, ok := el.(map[string]any); ok {
		if arm, v, ok := single(o); ok && changeArms[arm] {
			if change != "" && change != arm {
				return false
			}
			if arm == "removed" {
				return jsonEqual(v, key)
			}
			entry, _ := v.(map[string]any)
			return dataHasKey(entry["data"], key)
		}
		if _, hasData := o["data"]; hasData {
			if _, hasSeq := o["last_modified_ledger_seq"]; hasSeq {
				return change == "" && dataHasKey(o["data"], key)
			}
		}
	}
	return change == "" && jsonEqual(el, key)
}

func dataHasKey(data any, key map[string]any) bool {
	d, ok := data.(map[string]any)
	if !ok {
		return false
	}
	dArm, dv, ok1 := single(d)
	kArm, kv, ok2 := single(key)
	if !ok1 || !ok2 || dArm != kArm {
		return false
	}
	kf, ok := kv.(map[string]any)
	if !ok || len(kf) == 0 {
		return false
	}
	if kArm == "config_setting" {
		id, _ := kf["config_setting_id"].(string)
		setting, ok := dv.(map[string]any)
		if !ok {
			return false
		}
		arm, _, ok := single(setting)
		return ok && id != "" && arm == id
	}
	df, ok := dv.(map[string]any)
	if !ok {
		return false
	}
	for f, want := range kf {
		got, ok := df[f]
		if !ok || !jsonEqual(got, want) {
			return false
		}
	}
	return true
}

func single(o map[string]any) (string, any, bool) {
	if len(o) != 1 {
		return "", nil, false
	}
	for k, v := range o {
		return k, v, true
	}
	return "", nil, false
}

// jsonEqual compares two decoded JSON values by their canonical encoding (map keys sorted, json.Number kept as
// written).
func jsonEqual(a, b any) bool {
	x, err1 := json.Marshal(a)
	y, err2 := json.Marshal(b)
	return err1 == nil && err2 == nil && bytes.Equal(x, y)
}

func short(v any) string {
	b, _ := json.Marshal(v)
	if len(b) > 160 {
		return string(b[:160]) + "…"
	}
	return string(b)
}

// Pointer resolves an RFC 6901 JSON Pointer in a decoded JSON value.
func Pointer(doc any, ptr string) (any, bool) {
	if ptr == "" {
		return doc, true
	}
	if !strings.HasPrefix(ptr, "/") {
		return nil, false
	}
	cur := doc
	for _, tok := range strings.Split(ptr[1:], "/") {
		tok = strings.ReplaceAll(strings.ReplaceAll(tok, "~1", "/"), "~0", "~")
		switch c := cur.(type) {
		case map[string]any:
			v, ok := c[tok]
			if !ok {
				return nil, false
			}
			cur = v
		case []any:
			i, err := strconv.Atoi(tok)
			if err != nil || i < 0 || i >= len(c) || (len(tok) > 1 && tok[0] == '0') {
				return nil, false
			}
			cur = c[i]
		default:
			return nil, false
		}
	}
	return cur, true
}

// ReadSidecar reads a zstd-compressed SEP-51 sidecar (decoded/<aa>/<sha>.json.zst) relative to the corpus root,
// numbers kept as json.Number.
func ReadSidecar(root, rel string) (any, error) {
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		return nil, err
	}
	dec, err := zstd.NewReader(nil, zstd.WithDecoderConcurrency(1))
	if err != nil {
		return nil, err
	}
	defer dec.Close()
	text, err := dec.DecodeAll(raw, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", rel, err)
	}
	d := json.NewDecoder(bytes.NewReader(text))
	d.UseNumber()
	var doc any
	if err := d.Decode(&doc); err != nil {
		return nil, fmt.Errorf("%s: %w", rel, err)
	}
	return doc, nil
}

// ResolvePinpoints replaces every key-selected pinpoint of the variant's resolved expect block with a plain
// pointer, read against the variant's sidecar under root.
func ResolvePinpoints(root string, v *Variant) error {
	if v.Resolved == nil || !v.Resolved.HasSelect() {
		return nil
	}
	if v.Decoded == "" {
		return fmt.Errorf("key-selected pinpoints need the variant's sidecar, and it has none")
	}
	doc, err := ReadSidecar(root, v.Decoded)
	if err != nil {
		return err
	}
	for i := range v.Resolved.Values {
		val := &v.Resolved.Values[i]
		if val.Select == nil {
			continue
		}
		at, err := ResolveSelect(doc, val.Select)
		if err != nil {
			return fmt.Errorf("expect.values[%d]: %w", i, err)
		}
		val.Path, val.Select = at+val.Path, nil
	}
	return nil
}

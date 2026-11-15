package driver

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// The corpus tests run the driver over the repository's curated entries. They need XDRCHECK_ROOT (the Makefile's
// test target sets it) and skip without it.

// readSidecar returns a decoded sidecar's JSON. Sidecars are stored zstd-compressed (decoded/<aa>/<sha>.json.zst);
// the zstd command decompresses them, so the driver modules need no compression dependency.
func readSidecar(path string) ([]byte, error) {
	if !strings.HasSuffix(path, ".zst") {
		return os.ReadFile(path)
	}
	out, err := exec.Command("zstd", "-dcq", path).Output()
	if err != nil {
		return nil, fmt.Errorf("zstd -dc %s: %w", path, err)
	}
	return out, nil
}

type manifestEntry struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Variants []struct {
		Network    string `json:"network"`
		Passphrase string `json:"passphrase"`
		Protocol   int    `json:"protocol"`
		XDRType    string `json:"xdr_type"`
		Blob       struct {
			Path string `json:"path"`
		} `json:"blob"`
		Decoded string `json:"decoded"`
	} `json:"variants"`
	Conformance struct {
		KnownDivergences []knownDivergence `json:"known_divergences"`
	} `json:"conformance"`
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root := os.Getenv("XDRCHECK_ROOT")
	if root == "" {
		t.Skip("XDRCHECK_ROOT is not set")
	}
	return root
}

func loadEntries(t *testing.T, root string) []manifestEntry {
	t.Helper()
	var out []manifestEntry
	err := filepath.WalkDir(filepath.Join(root, "corpus", "manifest"), func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".json") {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		var e manifestEntry
		if err := json.Unmarshal(b, &e); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		out = append(out, e)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// diffJSON lists the JSON Pointers at which two JSON values differ, at most max of them.
func diffJSON(a, b any, path string, out *[]string, max int) {
	if len(*out) >= max {
		return
	}
	switch x := a.(type) {
	case map[string]any:
		y, isMap := b.(map[string]any)
		if !isMap {
			*out = append(*out, fmt.Sprintf("%s: %s vs %s", orSlash(path), short(a), short(b)))
			return
		}
		keys := map[string]bool{}
		for k := range x {
			keys[k] = true
		}
		for k := range y {
			keys[k] = true
		}
		sorted := make([]string, 0, len(keys))
		for k := range keys {
			sorted = append(sorted, k)
		}
		sort.Strings(sorted)
		for _, k := range sorted {
			xv, inX := x[k]
			yv, inY := y[k]
			switch {
			case !inX:
				*out = append(*out, fmt.Sprintf("%s/%s: missing in projection (oracle %s)", path, k, short(yv)))
			case !inY:
				*out = append(*out, fmt.Sprintf("%s/%s: extra in projection (%s)", path, k, short(xv)))
			default:
				diffJSON(xv, yv, path+"/"+k, out, max)
			}
		}
	case []any:
		y, isArr := b.([]any)
		if !isArr || len(x) != len(y) {
			*out = append(*out, fmt.Sprintf("%s: %s vs %s", orSlash(path), short(a), short(b)))
			return
		}
		for i := range x {
			diffJSON(x[i], y[i], fmt.Sprintf("%s/%d", path, i), out, max)
		}
	default:
		if !reflect.DeepEqual(a, b) {
			*out = append(*out, fmt.Sprintf("%s: %s vs %s", orSlash(path), short(a), short(b)))
		}
	}
}

func short(v any) string {
	b, _ := json.Marshal(v)
	if len(b) > 120 {
		return string(b[:120]) + "…"
	}
	return string(b)
}

func decodeJSON(t *testing.T, b []byte) any {
	t.Helper()
	var v any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

// TestProjectionMatchesOracleSidecars is the walker self-test: the whole L2 projection of every curated blob
// the SDK can decode must equal the oracle's decoded sidecar as a JSON value. A difference is a walker bug
// (or, after triage, an SDK one); either way it must not pass silently. A blob the manifest declares a known
// divergence for at L0 or L2 (this SDK version) must show it instead, and one the pending list names is
// acknowledged (expected_test.go).
func TestProjectionMatchesOracleSidecars(t *testing.T) {
	root := repoRoot(t)
	p30 := schemaProbes()["stellar_value_signed_ms"]
	expect := loadExpectations(t, root, startDriver(t).sdkVersion())
	for _, e := range loadEntries(t, root) {
		for _, v := range e.Variants {
			if v.Blob.Path == "" || v.Decoded == "" {
				continue
			}
			key := e.variantKey(v.Network, v.Protocol)
			name := e.ID + "/" + key
			t.Run(name, func(t *testing.T) {
				raw, err := os.ReadFile(filepath.Join(root, "corpus", v.Blob.Path))
				if err != nil {
					t.Fatal(err)
				}
				in := &input{Kind: "xdr", XDRType: v.XDRType}
				res := levelValues(in, raw)
				code := ""
				if res.Reason != nil {
					code = res.Reason.Code
				}
				// Beyond this schema's reach (a Protocol 30 ledger, no Protocol 30 types) known divergences are
				// not evaluated.
				beyondReach := !p30 && v.Protocol >= 30
				if k, pending := expect.at(&e, key, "L0", "L2"); k != nil && !beyondReach {
					if res.Outcome != k.Outcome || (k.Match.Reason != "" && code != k.Match.Reason) {
						t.Errorf("the declared %s/%s, got %s/%s", k.Outcome, k.Match.Reason, res.Outcome, code)
					}
					return
				} else if pending && (res.Outcome != "ok" || expect.pendingAt(&e, key, "L2")) {
					return // a divergence awaiting a finding: a refusal, or an acknowledged L2 cell
				}
				if res.Outcome != "ok" {
					if !p30 && v.Protocol >= 30 && res.Outcome == "reject" &&
						(res.Reason.Code == "union_arm_undeclared" || res.Reason.Code == "enum_undeclared") {
						return // a clean pre-Protocol-30 refusal
					}
					t.Fatalf("L2 %s: %+v", res.Outcome, res.Reason)
				}
				got, err := marshalValue(res.Actual["projection"])
				if err != nil {
					t.Fatal(err)
				}
				want, err := readSidecar(filepath.Join(root, "corpus", v.Decoded))
				if err != nil {
					t.Fatal(err)
				}
				var diffs []string
				diffJSON(decodeJSON(t, got), decodeJSON(t, want), "", &diffs, 25)
				if len(diffs) > 0 {
					t.Errorf("projection differs from the oracle sidecar at %d+ paths:\n  %s", len(diffs), strings.Join(diffs, "\n  "))
				}
			})
		}
	}
}

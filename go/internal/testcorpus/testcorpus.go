// Package testcorpus builds scratch corpus roots for tests: the vendored corpus with only the named manifest
// entries, so a test written against a few entries keeps its shape as the corpus grows.
//
// Everything except manifest/ mirrors the vendored corpus (blobs, sidecars, chains, objects, schemas):
// directories are real, so walks see them, and files are symlinks. The named entries are copied, by default
// without their core-golden variants. The root's parent links the repository's other top-level entries,
// because chain indexes cite meta streams by repository path (evidence/...).
//
// An entry whose vendored bytes were regenerated after tests were written against it is served from a
// frozen copy under testdata/frozen/, together with the blobs, sidecars and chain indexes that copy
// cites; tests that need the live entry read corpus/ directly. cap-0073/sac-trust-creates-trustline is one: its research-probe ledgers were
// replaced by scenario-generated ones.
package testcorpus

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Original are the first three vendored entries, which most harness tests are written against.
var Original = []string{
	"cap-0038/pool-issuers-order-by-bytes-not-strkey",
	"cap-0040/signed-payload-signer-added",
	"cap-0073/sac-trust-creates-trustline",
}

// Vendored is the absolute path of the repository's corpus directory.
func Vendored() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", "corpus"))
}

// Frozen is the absolute path of the frozen corpus fragment (same layout as corpus/).
func Frozen() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "testdata", "frozen")
}

// Options select what Build copies.
type Options struct {
	// KeepGoldens keeps core-golden variants; by default they are dropped, so entries keep the variants
	// their tests were written against.
	KeepGoldens bool
	// DropGenerated drops variants generated from the repository's scenarios (local-core variants whose
	// source names corpus/scenarios/…). Those scenarios reuse ledger numbers on one passphrase, which test
	// doubles that look expectations up by (passphrase, ledger) cannot tell apart.
	DropGenerated bool
	// DropOpenReplayAt, a commit, drops the replay known divergences whose range ends at that commit
	// ("A..<commit>"): defects still open at it. A test double that reads every ledger correctly cannot show
	// them, so a test that expects every entry to pass at that commit runs without them.
	DropOpenReplayAt string
}

// Build returns a corpus root under t.TempDir() holding the entries ids. Nil ids means every vendored entry;
// then an entry left with no variant once core-golden variants are dropped is omitted.
func Build(t testing.TB, ids []string, o Options) string {
	t.Helper()
	src := Vendored()
	all := ids == nil
	if all {
		ids = entryIDs(t, src)
	}
	root := filepath.Join(t.TempDir(), "corpus")
	if err := os.MkdirAll(filepath.Join(root, "manifest"), 0o755); err != nil {
		t.Fatal(err)
	}
	siblings, err := os.ReadDir(filepath.Dir(src))
	if err != nil {
		t.Fatal(err)
	}
	for _, de := range siblings {
		if de.Name() != "corpus" {
			if err := os.Symlink(filepath.Join(filepath.Dir(src), de.Name()), filepath.Join(filepath.Dir(root), de.Name())); err != nil {
				t.Fatal(err)
			}
		}
	}
	err = filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		switch {
		case rel == "manifest":
			return filepath.SkipDir
		case d.IsDir():
			return os.MkdirAll(filepath.Join(root, rel), 0o755)
		default:
			return os.Symlink(p, filepath.Join(root, rel))
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	usedFrozen := false
	for _, id := range ids {
		manifestDir := filepath.Join(src, "manifest")
		if f := filepath.Join(Frozen(), "manifest", id+".json"); fileExists(f) {
			manifestDir, usedFrozen = filepath.Join(Frozen(), "manifest"), true
		}
		data, err := os.ReadFile(filepath.Join(manifestDir, id+".json"))
		if err != nil {
			t.Fatal(err)
		}
		if !o.KeepGoldens || o.DropGenerated {
			var empty bool
			data, empty = dropVariants(t, data, o)
			if empty && all {
				continue
			}
		}
		if o.DropOpenReplayAt != "" {
			data = dropOpenReplay(t, data, o.DropOpenReplayAt)
		}
		dst := filepath.Join(root, "manifest", id+".json")
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if usedFrozen {
		copyFrozenFiles(t, root)
	}
	return root
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// copyFrozenFiles copies every frozen file outside manifest/ (blobs, sidecars, chain indexes) into root.
func copyFrozenFiles(t testing.TB, root string) {
	t.Helper()
	fr := Frozen()
	err := filepath.WalkDir(fr, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(fr, p)
		switch {
		case rel == "manifest":
			return filepath.SkipDir
		case d.IsDir():
			return os.MkdirAll(filepath.Join(root, rel), 0o755)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		dst := filepath.Join(root, rel)
		_ = os.Remove(dst)
		return os.WriteFile(dst, data, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// entryIDs lists every manifest entry under the corpus src.
func entryIDs(t testing.TB, src string) []string {
	t.Helper()
	var ids []string
	dir := filepath.Join(src, "manifest")
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && filepath.Ext(p) == ".json" {
			rel, _ := filepath.Rel(dir, p)
			ids = append(ids, filepath.ToSlash(rel[:len(rel)-len(".json")]))
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return ids
}

// dropOpenReplay removes the replay known divergences whose version range ends at commit, keeping every other
// field as a JSON value; data is returned unchanged when there is none.
func dropOpenReplay(t testing.TB, data []byte, commit string) []byte {
	t.Helper()
	var e map[string]json.RawMessage
	if err := json.Unmarshal(data, &e); err != nil {
		t.Fatal(err)
	}
	if e["conformance"] == nil {
		return data
	}
	var c map[string]json.RawMessage
	if err := json.Unmarshal(e["conformance"], &c); err != nil {
		t.Fatal(err)
	}
	if c["known_divergences"] == nil {
		return data
	}
	var kds []json.RawMessage
	if err := json.Unmarshal(c["known_divergences"], &kds); err != nil {
		t.Fatal(err)
	}
	kept := kds[:0]
	for _, k := range kds {
		var probe struct {
			Level    string `json:"level"`
			Versions string `json:"versions"`
		}
		if err := json.Unmarshal(k, &probe); err != nil {
			t.Fatal(err)
		}
		if probe.Level != "replay" || !strings.HasSuffix(probe.Versions, ".."+commit) {
			kept = append(kept, k)
		}
	}
	if len(kept) == len(kds) {
		return data
	}
	if len(kept) == 0 {
		delete(c, "known_divergences")
	} else {
		raw, err := json.Marshal(kept)
		if err != nil {
			t.Fatal(err)
		}
		c["known_divergences"] = raw
	}
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	e["conformance"] = raw
	out, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// dropVariants removes the variants o excludes (core-golden unless KeepGoldens; scenario-generated with
// DropGenerated), keeping every other field as a JSON value. It reports whether no variant is left.
func dropVariants(t testing.TB, data []byte, o Options) ([]byte, bool) {
	t.Helper()
	var e map[string]json.RawMessage
	if err := json.Unmarshal(data, &e); err != nil {
		t.Fatal(err)
	}
	if e["variants"] == nil {
		return data, false // api and strkey entries have no variants
	}
	var vs []json.RawMessage
	if err := json.Unmarshal(e["variants"], &vs); err != nil {
		t.Fatal(err)
	}
	kept := vs[:0]
	for _, v := range vs {
		var probe struct {
			Source struct {
				Kind     string `json:"kind"`
				Scenario string `json:"scenario"`
			} `json:"source"`
		}
		if err := json.Unmarshal(v, &probe); err != nil {
			t.Fatal(err)
		}
		golden := probe.Source.Kind == "core-golden" && !o.KeepGoldens
		generated := o.DropGenerated && probe.Source.Kind == "local-core" && strings.HasPrefix(probe.Source.Scenario, "scenarios/")
		if !golden && !generated {
			kept = append(kept, v)
		}
	}
	if len(kept) == len(vs) {
		return data, false
	}
	raw, err := json.Marshal(kept)
	if err != nil {
		t.Fatal(err)
	}
	e["variants"] = raw
	out, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return out, len(kept) == 0
}

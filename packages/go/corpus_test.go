package xdrcheckcorpus

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// repoCorpus is the repository's own corpus directory.
func repoCorpus(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", "..", "corpus"))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func openRepo(t *testing.T) *Corpus {
	t.Helper()
	c, err := Open(repoCorpus(t))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// rawIndex reads index.json independently of the loader, to compare against.
func rawIndex(t *testing.T) []map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoCorpus(t), "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	var idx struct{ Entries []map[string]any }
	if err := json.Unmarshal(raw, &idx); err != nil {
		t.Fatal(err)
	}
	return idx.Entries
}

func TestOpenRepositoryCorpus(t *testing.T) {
	c := openRepo(t)
	raw := rawIndex(t)
	if len(c.Entries) != len(raw) || len(raw) == 0 {
		t.Fatalf("%d entries, index.json has %d", len(c.Entries), len(raw))
	}
	if c.Version == "" || c.Version == "unknown" {
		t.Fatalf("version %q", c.Version)
	}
	for i, e := range c.Entries {
		if e.ID != raw[i]["id"] || e.Validity != raw[i]["validity"] || e.Kind != raw[i]["kind"] {
			t.Fatalf("entry %d: %s %s %s, index.json %v", i, e.ID, e.Validity, e.Kind, raw[i])
		}
		if c.Entry(e.ID) != e {
			t.Fatalf("Entry(%s) does not return the entry", e.ID)
		}
	}
}

// Every blob of every entry verifies, every sidecar decompresses to JSON whose sha256 matches, and the
// variant key follows the report rule.
func TestEveryBlobAndSidecarVerifies(t *testing.T) {
	c := openRepo(t)
	variants, sidecars := 0, 0
	for _, e := range c.Entries {
		protocols := map[int]bool{}
		for _, v := range e.Variants {
			protocols[v.Protocol] = true
		}
		for _, v := range e.Variants {
			variants++
			b, err := v.Blob()
			if err != nil {
				t.Fatal(err)
			}
			if int64(len(b)) != v.Bytes {
				t.Fatalf("%s %s: %d bytes", e.ID, v.Key, len(b))
			}
			want := v.Network
			if len(protocols) > 1 {
				want = v.Network + "@" + strconv.Itoa(v.Protocol)
			}
			if v.Key != want {
				t.Fatalf("%s: key %q, want %q", e.ID, v.Key, want)
			}
			j, err := v.ExpectedJSON()
			if err != nil {
				t.Fatal(err)
			}
			if (v.DecodedPath == nil) != (j == nil) {
				t.Fatalf("%s %s: decoded %v but JSON %v", e.ID, v.Key, v.DecodedPath, j != nil)
			}
			if j != nil {
				sidecars++
			}
		}
	}
	if variants == 0 || sidecars == 0 {
		t.Fatalf("%d variants, %d sidecars", variants, sidecars)
	}
}

func TestManifestFramingAndValidity(t *testing.T) {
	c := openRepo(t)
	refuse, decodable := 0, 0
	for _, e := range c.Entries {
		m, err := e.Manifest()
		if err != nil {
			t.Fatal(err)
		}
		if m["id"] != e.ID {
			t.Fatalf("manifest id %v for %s", m["id"], e.ID)
		}
		for _, v := range e.Variants {
			if v.MustRefuse() {
				refuse++
				if v.Validity == "valid" {
					t.Fatal("unreachable")
				}
			}
			if v.Decodable() {
				decodable++
				if f, _, _ := v.Framing(); f != "none" {
					t.Fatalf("%s: decodable with framing %s", e.ID, f)
				}
			}
		}
		if e.Validity == "malformed" && e.Kind == "xdr" {
			r, err := e.ExpectRejectReason()
			if err != nil || r == "" {
				t.Fatalf("%s: malformed xdr entry without expect.reject.reason (%v)", e.ID, err)
			}
		}
	}
	if refuse == 0 || decodable == 0 {
		t.Fatalf("%d variants to refuse, %d decodable", refuse, decodable)
	}
}

// fixture copies one ledger entry's files out of the repository corpus into a fresh corpus directory with its
// own index.json and manifest.sha256.
func fixture(t *testing.T) (dir string, e *Entry) {
	t.Helper()
	c := openRepo(t)
	for _, x := range c.Entries {
		if x.Kind == "ledger" && len(x.Variants) > 0 && x.Variants[0].DecodedPath != nil {
			e = x
			break
		}
	}
	if e == nil {
		t.Fatal("no ledger entry with a sidecar")
	}
	dir = t.TempDir()
	cp := func(rel string) []byte {
		b, err := os.ReadFile(filepath.Join(repoCorpus(t), rel))
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(dir, rel), b)
		return b
	}
	m := cp(e.ManifestPath)
	writeFile(t, filepath.Join(dir, "manifest.sha256"), []byte(sha256Hex(m)+"  "+e.ManifestPath+"\n"))
	for _, v := range e.Variants {
		cp(v.BlobPath)
		if v.DecodedPath != nil {
			cp(*v.DecodedPath)
		}
	}
	cp("corpus.json")
	row := rowOf(t, e.ID)
	idx, _ := json.Marshal(map[string]any{"schema": IndexSchema, "entries": []any{row}})
	writeFile(t, filepath.Join(dir, "index.json"), idx)
	return dir, e
}

func rowOf(t *testing.T, id string) map[string]any {
	for _, r := range rawIndex(t) {
		if r["id"] == id {
			return r
		}
	}
	t.Fatalf("no row %s", id)
	return nil
}

func writeFile(t *testing.T, p string, b []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestTamperedFilesAreRefused(t *testing.T) {
	dir, e := fixture(t)
	c, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	v := c.Entries[0].Variants[0]
	if _, err := v.Blob(); err != nil {
		t.Fatal(err)
	}
	if _, err := v.ExpectedJSON(); err != nil {
		t.Fatal(err)
	}

	// A blob with one byte changed.
	blob := filepath.Join(dir, v.BlobPath)
	b, _ := os.ReadFile(blob)
	b[len(b)-1] ^= 1
	writeFile(t, blob, b)
	if _, err := v.Blob(); err == nil || !strings.Contains(err.Error(), "the index says") {
		t.Fatalf("a tampered blob: %v", err)
	}

	// A sidecar replaced by another valid zstd stream.
	side := filepath.Join(dir, *v.DecodedPath)
	other := filepath.Join(repoCorpus(t), "decoded")
	var replacement []byte
	filepath.WalkDir(other, func(p string, d os.DirEntry, err error) error {
		if replacement == nil && err == nil && !d.IsDir() && !strings.HasSuffix(p, filepath.Base(side)) {
			replacement, _ = os.ReadFile(p)
		}
		return nil
	})
	writeFile(t, side, replacement)
	if _, err := v.ExpectedJSON(); err == nil || !strings.Contains(err.Error(), "decoded_sha256") {
		t.Fatalf("a replaced sidecar: %v", err)
	}

	// A manifest that no longer matches manifest.sha256.
	mp := filepath.Join(dir, e.ManifestPath)
	m, _ := os.ReadFile(mp)
	writeFile(t, mp, append(m, ' '))
	c2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c2.Entries[0].Manifest(); err == nil || !strings.Contains(err.Error(), "manifest.sha256") {
		t.Fatalf("a tampered manifest: %v", err)
	}
}

// A release archive: a gzip ustar file with one top-level directory holding corpus/ (with the index) and stress/;
// a stress row's files are read from stress/.
func TestReleaseArchive(t *testing.T) {
	dir, e := fixture(t)
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	top := "xdrcheck-30.0.0"
	add := func(name string, b []byte) {
		if err := tw.WriteHeader(&tar.Header{Name: top + "/" + name, Mode: 0o644, Size: int64(len(b)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		tw.Write(b)
	}
	add("PROVENANCE.json", []byte(`{"schema":"xcc.release/v1","version":"30.0.7"}`))
	// The same entry twice: once as a curated row under corpus/, once as a stress row under stress/ only.
	row := rowOf(t, e.ID)
	stressRow := rowOf(t, e.ID)
	stressRow["id"], stressRow["tier"] = e.ID+"-stress", "stress"
	idx, _ := json.Marshal(map[string]any{"schema": IndexSchema, "entries": []any{row, stressRow}})
	add("corpus/index.json", idx)
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Base(p) == "index.json" {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		b, _ := os.ReadFile(p)
		if !strings.HasPrefix(rel, "manifest") {
			add("stress/"+filepath.ToSlash(rel), b)
		}
		add("corpus/"+filepath.ToSlash(rel), b)
		return nil
	})
	tw.Close()
	gz.Close()
	archive := filepath.Join(t.TempDir(), top+".tar.gz")
	writeFile(t, archive, buf.Bytes())

	c, err := OpenSHA256(archive, sha256Hex(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if c.Version != "30.0.7" || len(c.Entries) != 2 {
		t.Fatalf("version %s, %d entries", c.Version, len(c.Entries))
	}
	for _, x := range c.Entries {
		for _, v := range x.Variants {
			if _, err := v.Blob(); err != nil {
				t.Fatalf("%s: %v", x.ID, err)
			}
			if _, err := v.ExpectedJSON(); err != nil {
				t.Fatalf("%s: %v", x.ID, err)
			}
		}
	}
	if _, err := c.Entries[0].Manifest(); err != nil {
		t.Fatal(err)
	}
	// The stress root has no manifests in this fixture: the stress row reads stress/, not corpus/.
	if _, err := c.Entries[1].Manifest(); err == nil || !strings.Contains(err.Error(), "stress/manifest") {
		t.Fatalf("stress manifest: %v", err)
	}
	if _, err := OpenSHA256(archive, strings.Repeat("0", 64)); err == nil {
		t.Fatal("a wrong archive sha256 was accepted")
	}
}

package dataset

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestParseLedgers(t *testing.T) {
	f := filepath.Join(t.TempDir(), "l.tsv")
	os.WriteFile(f, []byte("seq\ttx\n7\t3\n# c\n5\n"), 0o644)
	got, err := ParseLedgers("10-12, 3,11,@" + f)
	if err != nil {
		t.Fatal(err)
	}
	want := []uint32{3, 5, 7, 10, 11, 12}
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%v", got)
		}
	}
	for _, bad := range []string{"0", "5-3", "x", "1-2000000"} {
		if _, err := ParseLedgers(bad); err == nil {
			t.Errorf("%q: want an error", bad)
		}
	}
	refs, _ := ReadRefs(f)
	if len(refs) != 2 || refs[0].Tx != 3 || refs[1].Tx != -1 {
		t.Fatalf("%v", refs)
	}
	if r, err := ParseTx("60190078:83"); err != nil || r.String() != "60190078:83" {
		t.Fatal(r, err)
	}
}

func TestLakeKeyAndFetch(t *testing.T) {
	l := &Lake{Cache: t.TempDir(), Network: "pubnet"}
	if k := l.Key(60190078); k != "FC6A07FF--60160000-60223999/FC699281--60190078.xdr.zst" {
		t.Fatalf("key %s", k)
	}
	body := map[string][]byte{}
	var gets atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gets.Add(1)
		key := strings.TrimPrefix(r.URL.Path, "/")
		b, ok := body[key]
		if !ok {
			http.NotFound(w, r)
			return
		}
		s := md5.Sum(b)
		etag := hex.EncodeToString(s[:])
		if strings.Contains(key, "--11.") {
			etag = "0123456789abcdef0123456789abcdef" // corrupt: MD5 mismatch
		}
		w.Header().Set("ETag", `"`+etag+`"`)
		w.Write(b)
	}))
	defer srv.Close()
	for _, s := range []uint32{10, 11} {
		body[l.Key(s)] = []byte("ledger bytes " + string(rune('a'+s)))
	}
	res, err := l.Fetch(context.Background(), []uint32{10, 12}, FetchOptions{BaseURL: srv.URL, Parallel: 4})
	if err != nil {
		t.Fatal(err)
	}
	if res.Counts["ok"] != 1 || res.Counts["not-found"] != 1 {
		t.Fatalf("%v", res.Counts)
	}
	if l.Locate(10) == "" || l.Locate(12) != "" {
		t.Fatal("locate")
	}
	n := gets.Load()
	res, _ = l.Fetch(context.Background(), []uint32{10}, FetchOptions{BaseURL: srv.URL})
	if res.Counts["have"] != 1 || gets.Load() != n {
		t.Fatalf("resume: %v", res.Counts)
	}
	// a body whose MD5 differs from the ETag is retried and then reported, never written
	res, _ = l.Fetch(context.Background(), []uint32{11}, FetchOptions{BaseURL: srv.URL, Parallel: 1, Retries: 1})
	if res.Counts["md5-mismatch"] != 1 || l.Locate(11) != "" {
		t.Fatalf("md5: %v", res.Counts)
	}
}

func TestBuildManifestValidates(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "census"), 0o755)
	os.MkdirAll(filepath.Join(root, "arch/pilot/lists"), 0o755)
	os.WriteFile(filepath.Join(root, "census/facts.tsv"), []byte("protocol\tlast_ledger\n1\t100\n2\t250\n"), 0o644)
	os.WriteFile(filepath.Join(root, "arch/pilot/lists/S0.txt"), []byte("5\n7\n"), 0o644)
	out := t.TempDir()
	m, err := Build(BuildOptions{Version: "t.1", Network: "pubnet", Roots: map[string]string{"derived": root}, Out: out, Hash: true})
	if err != nil {
		t.Fatal(err)
	}
	if m.TipLedger != 250 || m.Sets["controls"].Count != 2 || m.Tables["tokens"].Missing == "" {
		t.Fatalf("%+v", m)
	}
	t.Setenv("XDRCHECK_DATASET_ROOT_DERIVED", root)
	m2, err := Load(out)
	if err != nil {
		t.Fatal(err)
	}
	refs, err := m2.SetRefs("controls")
	if err != nil || len(refs) != 2 {
		t.Fatal(refs, err)
	}
	for _, c := range m2.Verify(true) {
		if c.State != "ok" {
			t.Errorf("%+v", c)
		}
	}
}

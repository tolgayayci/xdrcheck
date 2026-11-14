package manifest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const corpusRoot = "../../../corpus"

func TestLoadVendoredCorpus(t *testing.T) {
	c, err := Load(corpusRoot, Options{})
	if err != nil {
		t.Fatal(err)
	}
	// Every manifest file is loaded, in ID order.
	var files []string
	if err := filepath.WalkDir(filepath.Join(corpusRoot, "manifest"), func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".json") {
			files = append(files, p)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if len(c.Entries) != len(files) {
		t.Fatalf("got %d entries, want %d", len(c.Entries), len(files))
	}
	for i := 1; i < len(c.Entries); i++ {
		if c.Entries[i-1].ID >= c.Entries[i].ID {
			t.Errorf("entries out of order: %s before %s", c.Entries[i-1].ID, c.Entries[i].ID)
		}
	}
	for _, id := range []string{
		"cap-0038/pool-issuers-order-by-bytes-not-strkey",
		"cap-0040/signed-payload-signer-added",
		"cap-0073/sac-trust-creates-trustline",
	} {
		if c.Entry(id) == nil {
			t.Errorf("entry %s missing", id)
		}
	}
	if len(c.Chains) == 0 {
		t.Fatal("no chain indexes loaded")
	}
	for i := 1; i < len(c.Chains); i++ {
		if c.Chains[i-1].ID >= c.Chains[i].ID {
			t.Errorf("chains out of order: %s before %s", c.Chains[i-1].ID, c.Chains[i].ID)
		}
	}

	e := c.Entry("cap-0073/sac-trust-creates-trustline")
	if e == nil {
		t.Fatal("trust entry missing")
	}
	var p28 *Variant
	for _, v := range e.Variants {
		if v.Network == "testnet" && v.Protocol == 28 {
			p28 = v
		}
	}
	if p28 == nil || p28.Source.LocalCore == nil || p28.Source.Kind != SourceLocalCore {
		t.Fatalf("testnet p28 variant or its local-core source missing: %+v", p28)
	}
	if got := e.VariantKey(p28); got != "testnet@28" {
		t.Errorf("variant key %q", got)
	}
	r := p28.Resolved
	if r == nil {
		t.Fatal("variant not resolved")
	}
	// Tokens resolve to this variant's derived values.
	sac := p28.Derived["contracts"].(map[string]any)["sac_usdc"]
	owner := p28.Derived["accounts"].(map[string]any)["owner"]
	if got := r.Transactions[0].Hash; got != p28.Derived["tx_hash"] || got == "" {
		t.Errorf("resolved ${derived.tx_hash} = %q", got)
	}
	if got := r.Transactions[0].FeeCharged; got != p28.Derived["fee_charged"] || got == "" {
		t.Errorf("resolved ${derived.fee_charged} = %q", got)
	}
	if got := r.StateChanges[0].Asset; got != sac || got == "" {
		t.Errorf("resolved ${derived.contracts.sac_usdc} = %q", got)
	}
	if got := r.StateChanges[0].Account.Address; got != owner || got == "" {
		t.Errorf("resolved ${derived.accounts.owner} = %q", got)
	}
	if got := r.Values[1].Equals; got != sac {
		t.Errorf("resolved ${derived.contracts.sac_usdc} inside values[].equals = %v", got)
	}
	if got := r.StateChanges[0].Detail["flags"]; got != json.Number("1") {
		t.Errorf("detail flags = %#v, want json.Number 1", got)
	}
	// The shared block keeps its tokens.
	if got := e.Expect.Transactions[0].Hash; got != "${derived.tx_hash}" {
		t.Errorf("unresolved block changed: %q", got)
	}

	ch, l, ok := c.ChainForBlob(p28.Blob.SHA256)
	if !ok || ch.Network != "testnet" || ch.Protocol != 28 || int64(l.Seq) != p28.LedgerSeq || l.HeaderHash != p28.Derived["ledger_hash"] {
		t.Errorf("chain for blob: %v %+v %v", ch, l, ok)
	}

	h := c.Entry("cap-0040/signed-payload-signer-added")
	src := h.Variants[0].Source.History
	if src == nil || src.BlobOffset == nil || *src.BlobOffset != 12 || src.ObjectMetadata["protocol-version"] != "28" {
		t.Errorf("history source: %+v", src)
	}
	if h.VariantKey(h.Variants[0]) != "testnet" {
		t.Errorf("single-variant key %q", h.VariantKey(h.Variants[0]))
	}
	kd := h.Conformance.KnownDivergences[0]
	if kd.Target != "stellar/wallet-backend" || kd.Qualifier != "halt" || kd.Level != "replay" {
		t.Errorf("known divergence: %+v", kd)
	}
}

// trustChainFiles are the chain index files (relative to corpus/chains) holding the Protocol 28
// variants of the CAP-0073 trust entry.
func trustChainFiles(t *testing.T) []string {
	t.Helper()
	e, err := LoadEntry(filepath.Join(corpusRoot, "manifest/cap-0073/sac-trust-creates-trustline.json"))
	if err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(corpusRoot, "chains/*/*.json"))
	var out []string
	for _, v := range e.Variants {
		if v.Protocol != 28 {
			continue
		}
		for _, f := range files {
			ch, err := LoadChainIndex(f)
			if err != nil {
				t.Fatal(err)
			}
			for _, l := range ch.Ledgers {
				if l.BlobSHA256 == v.Blob.SHA256 {
					rel, _ := filepath.Rel(filepath.Join(corpusRoot, "chains"), f)
					out = append(out, rel)
				}
			}
		}
	}
	if len(out) != 2 {
		t.Fatalf("Protocol 28 trust variants on %d chains: %v", len(out), out)
	}
	return out
}

func TestChainIndexes(t *testing.T) {
	for _, f := range trustChainFiles(t) {
		ch, err := LoadChainIndex(filepath.Join(corpusRoot, "chains", f))
		if err != nil {
			t.Fatal(err)
		}
		// Ledgers 2 to the last, one row each; Protocol 27 settings on the Protocol 28 chain.
		last := ch.Ledgers[len(ch.Ledgers)-1].Seq
		if ch.Ledgers[0].Seq != 2 || int(last) != len(ch.Ledgers)+1 || ch.Settings.SourceProtocol == nil || *ch.Settings.SourceProtocol != 27 {
			t.Errorf("%s: %d ledgers, first %d, settings %+v", f, len(ch.Ledgers), ch.Ledgers[0].Seq, ch.Settings)
		}
	}
}

func TestSchemaExamplesDecode(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join(corpusRoot, "schema/examples/manifest-entry/valid-*.json"))
	chains, _ := filepath.Glob(filepath.Join(corpusRoot, "schema/examples/chain-index/valid-*.json"))
	indexes, _ := filepath.Glob(filepath.Join(corpusRoot, "schema/examples/corpus-index/valid-*.json"))
	if len(files) == 0 || len(chains) == 0 || len(indexes) == 0 {
		t.Fatal("schema examples not found")
	}
	for _, f := range files {
		if _, err := LoadEntry(f); err != nil {
			t.Error(err)
		}
	}
	for _, f := range chains {
		if _, err := LoadChainIndex(f); err != nil {
			t.Error(err)
		}
	}
	for _, f := range indexes {
		data, _ := os.ReadFile(f)
		if _, err := ParseCorpusIndex(data); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
}

// copyCorpus makes a writable copy of the vendored manifests, blobs and chains.
func copyCorpus(t *testing.T) string {
	t.Helper()
	dst := t.TempDir()
	for _, sub := range []string{"manifest", "blobs", "chains", "decoded"} {
		err := filepath.Walk(filepath.Join(corpusRoot, sub), func(p string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return err
			}
			rel, _ := filepath.Rel(corpusRoot, p)
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			out := filepath.Join(dst, rel)
			if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
				return err
			}
			return os.WriteFile(out, data, 0o644)
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return dst
}

func rewrite(t *testing.T, file string, edit func(string) string) {
	t.Helper()
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	out := edit(string(data))
	if out == string(data) {
		t.Fatalf("edit of %s changed nothing", file)
	}
	if err := os.WriteFile(file, []byte(out), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRejectsDrift(t *testing.T) {
	trustChain := "chains/" + trustChainFiles(t)[0]
	cases := []struct {
		name, file, old, new, want string
	}{
		{"unknown top-level field", "manifest/cap-0040/signed-payload-signer-added.json",
			`"kind": "ledger",`, `"kind": "ledger", "colour": "blue",`, `unknown field "colour"`},
		{"unknown field in a history source", "manifest/cap-0040/signed-payload-signer-added.json",
			`"kind": "history",`, `"kind": "history", "core_tag": "v1",`, `unknown field "core_tag"`},
		{"unknown detail key", "manifest/cap-0073/sac-trust-creates-trustline.json",
			`"num_sub_entries_after": 1`, `"num_sub_entries_after": 1, "colour": 1`, `detail key "colour"`},
		{"unresolvable token", "manifest/cap-0073/sac-trust-creates-trustline.json",
			`"${derived.fee_charged}"`, `"${derived.fee_charged_typo}"`, "derived.fee_charged_typo: no value"},
		{"unknown chain field", trustChain,
			`"profile": "lake",`, `"profile": "lake", "colour": 1,`, `unknown field "colour"`},
		{"blob size", "manifest/cap-0040/signed-payload-signer-added.json",
			`"bytes": 58256,`, `"bytes": 58255,`, "58256 bytes, manifest says 58255"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := copyCorpus(t)
			rewrite(t, filepath.Join(root, tc.file), func(s string) string { return strings.Replace(s, tc.old, tc.new, 1) })
			_, err := Load(root, Options{})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want an error containing %q", err, tc.want)
			}
		})
	}
}

func TestRejectsTamperedBlob(t *testing.T) {
	root := copyCorpus(t)
	e, err := LoadEntry(filepath.Join(root, "manifest/cap-0073/sac-trust-creates-trustline.json"))
	if err != nil {
		t.Fatal(err)
	}
	blob := filepath.Join(root, e.Variants[0].Blob.Path)
	data, _ := os.ReadFile(blob)
	data[100] ^= 0xff
	if err := os.WriteFile(blob, data, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = Load(root, Options{})
	if err == nil || !strings.Contains(err.Error(), "sha256") {
		t.Fatalf("got %v", err)
	}
	if _, err := Load(root, Options{SkipBlobCheck: true}); err != nil {
		t.Fatalf("with SkipBlobCheck: %v", err)
	}
}

func TestResolveString(t *testing.T) {
	d := map[string]any{
		"tx_hashes": []any{"aa", "bb"},
		"contracts": map[string]any{"x": "CX"},
		"fee":       json.Number("100"),
		"obj":       map[string]any{},
	}
	ok := map[string]string{
		"${derived.tx_hashes.1}":          "bb",
		"pre-${derived.contracts.x}-post": "pre-CX-post",
		"${derived.fee}/${derived.fee}":   "100/100",
		"no tokens, ${other.thing}":       "no tokens, ${other.thing}",
	}
	for in, want := range ok {
		got, err := ResolveString(in, d)
		if err != nil || got != want {
			t.Errorf("%q: got %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"${derived.missing}", "${derived.tx_hashes.2}", "${derived.obj}", "${derived.}", "${derived.fee"} {
		if got, err := ResolveString(bad, d); err == nil {
			t.Errorf("%q: resolved to %q, want an error", bad, got)
		}
	}
}

// TestLoadOverlay merges an overlay corpus: its entries load with the public ones, a blob only the overlay holds
// is read from there, and an entry ID in both corpora is an error.
func TestLoadOverlay(t *testing.T) {
	ov := t.TempDir()
	blob := []byte{0, 0, 0, 0, 0, 0, 0, 7} // SCV_BOOL 7: in no public blob
	sum := sha256.Sum256(blob)
	sha := hex.EncodeToString(sum[:])
	rel := "blobs/" + sha[:2] + "/" + sha + ".xdr"
	write := func(p string, data []byte) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(filepath.Join(ov, p)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(ov, p), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(rel, blob)
	const id = "xdr-strict/fictional-overlay-entry"
	entry := func(id string) []byte {
		b, _ := json.Marshal(map[string]any{
			"schema": EntrySchema, "id": id, "title": "A fictional overlay entry", "kind": "xdr", "caps": []int{},
			"caps_note": "test", "protocol": map[string]any{"introduced": 20}, "synthetic": true, "negative": true,
			"why": "test",
			"variants": []any{map[string]any{
				"network": "none", "passphrase": "", "protocol": 30, "xdr_type": "ScVal", "requires": []string{},
				"blob":   map[string]any{"sha256": sha, "bytes": len(blob), "path": rel},
				"source": map[string]any{"kind": "synthetic", "recipe": "test", "reason": "test"},
			}},
			"expect": map[string]any{"reject": map[string]any{"reason": "bool_range"}},
		})
		return b
	}
	write("manifest/"+id+".json", entry(id))

	c, err := Load(corpusRoot, Options{Overlay: ov})
	if err != nil {
		t.Fatal(err)
	}
	e := c.Entry(id)
	if e == nil || c.Overlay != ov {
		t.Fatalf("overlay entry not loaded (overlay %q)", c.Overlay)
	}
	if got, want := c.BlobPath(e.Variants[0]), filepath.Join(ov, filepath.FromSlash(rel)); got != want {
		t.Errorf("blob path %s, want %s", got, want)
	}
	pub := c.Entry("cap-0040/signed-payload-signer-added")
	if p := c.BlobPath(pub.Variants[0]); !strings.HasPrefix(p, filepath.Clean(corpusRoot)) {
		t.Errorf("public blob read from %s", p)
	}

	// An overlay entry with a public ID is refused.
	write("manifest/cap-0040/signed-payload-signer-added.json", entry("cap-0040/signed-payload-signer-added"))
	if _, err := Load(corpusRoot, Options{Overlay: ov}); err == nil || !strings.Contains(err.Error(), "both") {
		t.Errorf("duplicate ID: %v", err)
	}
}

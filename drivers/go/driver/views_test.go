package driver

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// viewsDriver starts the built driver and skips unless it offers the views profile (SDK v0.8.0 and later).
func viewsDriver(t *testing.T, env ...string) *driverProc {
	t.Helper()
	d := startDriver(t, env...)
	profiles, _ := d.describe()["decode"].(map[string]any)["profiles"].([]any)
	if !slices.Contains(profiles, any(ViewsProfile)) {
		t.Skip("this SDK version offers no views profile")
	}
	return d
}

type ledgerBlob struct{ name, path, passphrase, xdrType string }

func ledgerBlobs(t *testing.T, root string) []ledgerBlob {
	var out []ledgerBlob
	for _, e := range loadEntries(t, root) {
		for _, v := range e.Variants {
			if v.Blob.Path == "" || (v.XDRType != "LedgerCloseMeta" && v.XDRType != "LedgerCloseMetaBatch") {
				continue
			}
			out = append(out, ledgerBlob{e.ID + "/" + e.variantKey(v.Network, v.Protocol), filepath.Join(root, "corpus", v.Blob.Path), v.Passphrase, v.XDRType})
		}
	}
	if len(out) == 0 {
		t.Fatal("the corpus has no ledger blobs")
	}
	return out
}

func viewsRequest(b ledgerBlob, level string) *request {
	return &request{Entry: "views/" + b.name, Level: level, Profile: ViewsProfile,
		Input: input{Kind: "xdr", XDRType: b.xdrType, Path: b.path, Passphrase: b.passphrase}}
}

// TestViewsAgreeWithFullDecode: on every curated ledger the view path of this SDK version reports the same
// derived keys as its full decode. A ledger that the full decode itself refuses or that a known divergence
// covers is left to the conformance run; here the two paths are only compared.
func TestViewsAgreeWithFullDecode(t *testing.T) {
	root := repoRoot(t)
	d := viewsDriver(t)
	for _, b := range ledgerBlobs(t, root) {
		for _, level := range []string{"L0", "L1"} {
			resp := d.run(viewsRequest(b, level))
			reason, _ := resp["reason"].(map[string]any)
			msg, _ := reason["message"].(string)
			if resp["outcome"] == "diverge" || strings.Contains(msg, "the view") {
				t.Errorf("%s %s: %v %v", b.name, level, resp["outcome"], reason)
			}
		}
	}
}

// TestViewsCatchPlantedDifference: with a difference planted on the view path (the first transaction hash the
// view extractor reports is flipped), every ledger with a transaction is a diverge naming the extractor.
func TestViewsCatchPlantedDifference(t *testing.T) {
	root := repoRoot(t)
	d := viewsDriver(t, "XDRCHECK_GO_VIEWS_PLANT=tx-hash")
	caught := 0
	for _, b := range ledgerBlobs(t, root) {
		resp := d.run(viewsRequest(b, "L1"))
		obj, _ := resp["actual"].(map[string]any)["object"].(map[string]any)
		if resp["outcome"] == "ok" && obj["transactions"] != nil && obj["transactions"].(interface{ String() string }).String() != "0" {
			t.Errorf("%s: the planted hash difference was not caught", b.name)
			continue
		}
		if resp["outcome"] == "diverge" {
			if r := resp["reason"].(map[string]any); r["entry_point"] != "ingest.ExtractLedgerTxParts" {
				t.Errorf("%s: diverge names %v", b.name, r["entry_point"])
			}
			caught++
		}
	}
	if caught == 0 {
		t.Fatal("no planted difference was caught")
	}
}

// TestViewsRefuseTrailingBytes: the view validator applies the same consumed-length rule as the strict decode.
func TestViewsRefuseTrailingBytes(t *testing.T) {
	root := repoRoot(t)
	d := viewsDriver(t)
	b := ledgerBlobs(t, root)[0]
	raw, err := os.ReadFile(b.path)
	if err != nil {
		t.Fatal(err)
	}
	hexed := hex.EncodeToString(append(raw, 0, 0, 0, 0))
	req := viewsRequest(b, "L0")
	req.Input.Path, req.Input.XDRHex = "", &hexed
	resp := d.run(req)
	if resp["outcome"] != "reject" || resp["reason"].(map[string]any)["code"] != "trailing_bytes" {
		t.Fatalf("four trailing bytes: %v %v", resp["outcome"], resp["reason"])
	}
}

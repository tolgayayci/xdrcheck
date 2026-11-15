package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/ingest/ledgerbackend"
	"github.com/stellar/go-stellar-sdk/support/datastore"

	"github.com/tolgayayci/xdrcheck/go/internal/lake"
	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
	"github.com/tolgayayci/xdrcheck/go/internal/objstore"
	"github.com/tolgayayci/xdrcheck/go/internal/pins"
	"github.com/tolgayayci/xdrcheck/go/internal/testcorpus"
)

const (
	corpusDir = "../../../corpus"
	pinsPath  = "../../../pins.toml"
	testnet   = "Test SDF Network ; September 2015"
)

// runServe starts `xdrcheck serve` and returns the served views once it reports ready.
func runServe(t *testing.T, args ...string) (views []served, stop func() int, stderr *bytes.Buffer) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	pr, pw := io.Pipe()
	stderr = &bytes.Buffer{}
	done := make(chan int, 1)
	go func() {
		code := serve(ctx, args, pw, stderr)
		pw.Close()
		done <- code
	}()
	sc := bufio.NewScanner(pr)
	for sc.Scan() {
		var probe map[string]any
		json.Unmarshal(sc.Bytes(), &probe)
		if probe["ready"] == true {
			break
		}
		var s served
		if err := json.Unmarshal(sc.Bytes(), &s); err != nil {
			t.Fatal(err)
		}
		views = append(views, s)
	}
	if len(views) == 0 {
		cancel()
		t.Fatalf("serve exited %d before ready: %s", <-done, stderr)
	}
	go io.Copy(io.Discard, pr)
	return views, func() int { cancel(); return <-done }, stderr
}

// readAll reads a unit's range through a go-stellar-sdk backend and returns the sha256 of every ledger.
func readAll(t *testing.T, b ledgerbackend.LedgerBackend, first, last uint32) []string {
	t.Helper()
	ctx := context.Background()
	if err := b.PrepareRange(ctx, ledgerbackend.BoundedRange(first, last)); err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	var out []string
	for s := first; s <= last; s++ {
		m, err := b.GetLedger(ctx, s)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := m.MarshalBinary()
		sum := sha256.Sum256(raw)
		out = append(out, hex.EncodeToString(sum[:]))
	}
	return out
}

func bsb(t *testing.T, ds datastore.DataStore) *ledgerbackend.BufferedStorageBackend {
	t.Helper()
	schema, err := datastore.LoadSchema(context.Background(), ds, datastore.DataStoreConfig{NetworkPassphrase: testnet})
	if err != nil {
		t.Fatal(err)
	}
	b, err := ledgerbackend.NewBufferedStorageBackend(ledgerbackend.BufferedStorageBackendConfig{BufferSize: 1, NumWorkers: 1, RetryWait: time.Millisecond}, ds, schema)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestServeThreeEntriesOverEachInput(t *testing.T) {
	corpusDir := testcorpus.Build(t, testcorpus.Original, testcorpus.Options{})
	c, err := manifest.Load(corpusDir, manifest.Options{})
	if err != nil {
		t.Fatal(err)
	}
	blobs := map[string]string{} // testnet blob sha256 -> entry
	for _, e := range c.Entries {
		for _, v := range e.Variants {
			if v.Network == "testnet" {
				blobs[v.Blob.SHA256] = e.ID
			}
		}
	}
	args := []string{"--corpus", corpusDir, "--pins", pinsPath, "--network", "testnet",
		"--sep54-dir", t.TempDir(), "--rpc", "127.0.0.1:0", "--delivery-log", filepath.Join(t.TempDir(), "delivery.ndjson")}
	withS3 := true
	if p, err := pins.Load(pinsPath); err != nil || objstore.Available(p.Images["seaweedfs"]) != nil {
		withS3 = false
		t.Log("object store not available here; --s3 not exercised")
	} else {
		args = append(args, "--s3", "127.0.0.1:0")
	}
	views, stop, stderr := runServe(t, args...)
	defer func() {
		if code := stop(); code != 0 {
			t.Errorf("serve exited %d: %s", code, stderr)
		}
	}()

	t.Setenv("AWS_ACCESS_KEY_ID", objstore.AccessKey)
	t.Setenv("AWS_SECRET_ACCESS_KEY", objstore.SecretKey)
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	seen := map[string]map[string]bool{} // view -> entries read back
	for _, v := range views {
		var b ledgerbackend.LedgerBackend
		switch v.View {
		case "sep54-dir":
			ds, err := datastore.NewDataStore(context.Background(), datastore.DataStoreConfig{Type: "Filesystem", Params: map[string]string{"destination_path": v.Dir}})
			if err != nil {
				t.Fatal(err)
			}
			b = bsb(t, ds)
		case "rpc":
			b = ledgerbackend.NewRPCLedgerBackend(ledgerbackend.RPCLedgerBackendOptions{RPCServerURL: v.URL, BufferSize: 1})
		case "s3":
			ds, err := datastore.NewDataStore(context.Background(), datastore.DataStoreConfig{Type: "S3", Params: map[string]string{
				"destination_bucket_path": v.Path, "region": objstore.Region, "endpoint_url": v.URL}})
			if err != nil {
				t.Fatal(err)
			}
			b = bsb(t, ds)
		default:
			t.Fatalf("view %q", v.View)
		}
		for _, sum := range readAll(t, b, v.First, v.Last) {
			entry, ok := blobs[sum]
			if !ok {
				t.Errorf("%s %s served a ledger that is not a testnet corpus blob (%s)", v.View, v.Unit, sum)
				continue
			}
			if seen[v.View] == nil {
				seen[v.View] = map[string]bool{}
			}
			seen[v.View][entry] = true
		}
	}
	want := []string{"cap-0038/pool-issuers-order-by-bytes-not-strkey", "cap-0040/signed-payload-signer-added", "cap-0073/sac-trust-creates-trustline"}
	inputs := []string{"sep54-dir", "rpc"}
	if withS3 {
		inputs = append(inputs, "s3")
	}
	for _, in := range inputs {
		var got []string
		for e := range seen[in] {
			got = append(got, e)
		}
		sort.Strings(got)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s: read back %v", in, got)
		}
	}

	// The history entry's object is the public lake's, byte for byte, at its original key.
	for _, v := range views {
		if v.View == "sep54-dir" && v.First == 4437357 {
			data, err := os.ReadFile(filepath.Join(v.Dir, "FFBC9DFF--4416000-4479999/FFBC4A92--4437357.xdr.zst"))
			if err != nil {
				t.Fatal(err)
			}
			if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != "24fc6077579e6058512e35401c728288898e6c4fd550b8f26e0a5079aae4001b" {
				t.Error("history object differs from the lake's")
			}
		}
	}
}

func TestServeStreamAndArguments(t *testing.T) {
	corpusDir := testcorpus.Build(t, testcorpus.Original, testcorpus.Options{})
	views, stop, stderr := runServe(t, "--corpus", corpusDir, "--network", "pubnet", "--unit", "stream", "--rpc", "127.0.0.1:0")
	if len(views) != 1 || !views[0].Transformed || views[0].Kind != "stream" || views[0].First != 1000 || views[0].Last != 1001 {
		t.Errorf("stream views %+v", views)
	}
	b := ledgerbackend.NewRPCLedgerBackend(ledgerbackend.RPCLedgerBackendOptions{RPCServerURL: views[0].URL, BufferSize: 2})
	if sums := readAll(t, b, 1000, 1001); len(sums) != 2 {
		t.Errorf("%v", sums)
	}
	if code := stop(); code != 0 {
		t.Errorf("exit %d: %s", code, stderr)
	}

	for _, bad := range [][]string{
		{"--corpus", corpusDir, "--rpc", "127.0.0.1:0"},                                                  // no network
		{"--corpus", corpusDir, "--network", "testnet"},                                                  // no output
		{"--corpus", corpusDir, "--network", "testnet", "--gcs", "127.0.0.1:0"},                          // not built
		{"--corpus", corpusDir, "--network", "testnet", "--rpc", ":0", "--entries", "x", "--chain", "y"}, // alternatives
		{"--corpus", corpusDir, "--network", "testnet", "--rpc", ":0", "--ledgers", "9..3"},              // bad range
	} {
		var errb bytes.Buffer
		if code := serve(context.Background(), bad, io.Discard, &errb); code != 2 {
			t.Errorf("%v: exit %d", bad, code)
		}
	}
}

func TestServeDeliveryLog(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "d.ndjson")
	views, stop, _ := runServe(t, "--corpus", corpusDir, "--network", "testnet", "--entries", "cap-0040/*", "--rpc", "127.0.0.1:0", "--delivery-log", logPath)
	b := ledgerbackend.NewRPCLedgerBackend(ledgerbackend.RPCLedgerBackendOptions{RPCServerURL: views[0].URL, BufferSize: 1})
	readAll(t, b, 4437357, 4437357)
	stop()
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	var served bool
	for _, l := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var d lake.Delivery
		json.Unmarshal([]byte(l), &d)
		if d.Method == "getLedgers" && len(d.Ledgers) == 1 && d.Ledgers[0] == 4437357 && d.Status == "ok" {
			served = true
		}
	}
	if !served {
		t.Errorf("delivery log: %s", data)
	}
}

package objstore

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stellar/go-stellar-sdk/ingest/ledgerbackend"
	"github.com/stellar/go-stellar-sdk/support/datastore"

	"github.com/tolgayayci/xdrcheck/go/internal/lake"
	"github.com/tolgayayci/xdrcheck/go/internal/pins"
)

const (
	repo     = "../../.."
	testnet  = "Test SDF Network ; September 2015"
	chainP28 = repo + "/evidence/wallet-backend-731/out/p28-testnet/run-1/meta.xdr"
)

func image(t *testing.T) string {
	t.Helper()
	p, err := pins.Load(repo + "/pins.toml")
	if err != nil {
		t.Fatal(err)
	}
	img := p.Images["seaweedfs"]
	if err := Available(img); err != nil {
		t.Skipf("object store not available: %v", err)
	}
	return img
}

func chainLayout(t *testing.T) (*lake.Layout, [][]byte) {
	t.Helper()
	f, err := os.Open(chainP28)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var raws [][]byte
	lake.ScanFrames(f, func(i int, fr lake.Frame, p []byte) error { raws = append(raws, bytes.Clone(p)); return nil })
	var ls []lake.Ledger
	for i, b := range raws {
		ls = append(ls, lake.Ledger{Seq: uint32(2 + i), Load: func() ([]byte, error) { return b, nil }})
	}
	l, err := lake.Write(t.TempDir(), lake.NewConfig(testnet), ls)
	if err != nil {
		t.Fatal(err)
	}
	return l, raws
}

func TestSeaweedFSLayoutAndLog(t *testing.T) {
	img := image(t)
	ctx := context.Background()
	log := lake.NewDeliveryLog(nil)
	start := time.Now()
	st, err := Launch(ctx, Options{Image: img, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("store mode %s (container %q, binary sha256 %s) ready in %s, proxy %s; notes %v",
		st.Mode, st.Container, st.BinarySHA, time.Since(start), st.Endpoint, st.Notes)
	closed := false
	defer func() {
		if !closed {
			st.Close()
		}
	}()

	l, raws := chainLayout(t)
	const prefix = "testnet/chain"
	if err := st.Upload(ctx, prefix, l); err != nil {
		t.Fatal(err)
	}
	if err := st.ReadBack(ctx, prefix, l); err != nil {
		t.Fatal(err)
	}
	if n := len(log.Records()); n != 0 {
		t.Fatalf("uploads and read-back must not be delivery records; %d logged", n)
	}

	// An S3 client lists and gets through the proxy.
	c := Client(st.Endpoint)
	list, err := c.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(st.Bucket), Prefix: aws.String(prefix + "/")})
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Contents) != 24 { // .config.json + 23 ledgers
		t.Fatalf("%d objects listed", len(list.Contents))
	}
	got, err := c.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(st.Bucket), Key: aws.String(prefix + "/" + l.Objects[13].Key)})
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(got.Body)
	got.Body.Close()
	if got.Metadata["start-ledger"] != "15" || got.Metadata["protocol-version"] != "28" {
		t.Errorf("metadata %v", got.Metadata)
	}
	raw, _ := lake.Decompress(data)
	if _, lcm, err := lake.UnwrapBatch(raw); err != nil || !bytes.Equal(lcm, raws[13]) {
		t.Errorf("ledger 15 differs: %v", err)
	}

	// go-stellar-sdk v0.9.0's S3 datastore and BufferedStorageBackend read the chain through the proxy.
	t.Setenv("AWS_ACCESS_KEY_ID", AccessKey)
	t.Setenv("AWS_SECRET_ACCESS_KEY", SecretKey)
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	ds, err := datastore.NewDataStore(ctx, datastore.DataStoreConfig{Type: "S3", Params: map[string]string{
		"destination_bucket_path": st.Bucket + "/" + prefix, "region": Region, "endpoint_url": st.Endpoint}})
	if err != nil {
		t.Fatal(err)
	}
	schema, err := datastore.LoadSchema(ctx, ds, datastore.DataStoreConfig{NetworkPassphrase: testnet})
	if err != nil {
		t.Fatal(err)
	}
	bsb, err := ledgerbackend.NewBufferedStorageBackend(ledgerbackend.BufferedStorageBackendConfig{BufferSize: 2, NumWorkers: 1, RetryLimit: 0, RetryWait: time.Millisecond}, ds, schema)
	if err != nil {
		t.Fatal(err)
	}
	if err := bsb.PrepareRange(ctx, ledgerbackend.BoundedRange(2, 24)); err != nil {
		t.Fatal(err)
	}
	for i := range raws {
		m, err := bsb.GetLedger(ctx, uint32(2+i))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := m.MarshalBinary()
		if !bytes.Equal(b, raws[i]) {
			t.Fatalf("ledger %d differs over S3", 2+i)
		}
	}
	bsb.Close()

	// The proxy logged every request: the list, the single GET, and the SDK's manifest read, listing and gets.
	recs := log.Records()
	var lists, configGets int
	gets := 0
	for _, r := range recs {
		switch {
		case strings.Contains(r.Query, "list-type=2"):
			lists++
		case r.Key == prefix+"/"+lake.ConfigFile && r.Method == "GET":
			configGets++
		case len(r.Ledgers) == 1 && r.Status == "200":
			gets++
		}
	}
	// One list and one GET by the test; the SDK lists to sniff the extension, reads the manifest, and GETs 23
	// objects.
	if lists < 2 || configGets < 1 || gets != 1+23 || len(recs) != lists+configGets+gets {
		t.Errorf("log: %d lists, %d config reads, %d ledger GETs in %d records: %+v", lists, configGets, gets, len(recs), recs)
	}
	for seq := uint32(2); seq <= 24; seq++ {
		if !log.Served(seq) {
			t.Errorf("ledger %d not logged as served", seq)
		}
	}
	t.Logf("%d requests logged", len(recs))

	closed = true
	pid := 0
	if st.child != nil {
		pid = st.child.Pid()
	}
	dataDir, container := st.dataDir, st.Container
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	// Only this store's container: other packages' tests may run their own stores at the same time.
	if container != "" {
		out, err := exec.Command("docker", "ps", "-a", "--filter", "name=^"+container+"$", "--format", "{{.Names}}").Output()
		if err != nil || strings.TrimSpace(string(out)) != "" {
			t.Errorf("container left behind: %q %v", out, err)
		}
	}
	if st.Mode == ModeBinary {
		if syscall.Kill(pid, 0) == nil {
			t.Errorf("weed process %d still running", pid)
		}
		if _, err := os.Stat(dataDir); err == nil {
			t.Errorf("data directory %s left behind", dataDir)
		}
	}
}

func TestExtractWeedIsCached(t *testing.T) {
	img := image(t)
	dir := t.TempDir()
	a, sumA, err := ExtractWeed(context.Background(), img, dir)
	if err != nil {
		t.Fatal(err)
	}
	b, sumB, err := ExtractWeed(context.Background(), img, dir)
	if err != nil || a != b || sumA != sumB || len(sumA) != 64 {
		t.Fatalf("%s %s / %s %s: %v", a, sumA, b, sumB, err)
	}
	if out, err := exec.Command(a, "version").Output(); err != nil || !strings.Contains(string(out), "4.46") {
		t.Errorf("weed version: %q %v", out, err)
	}
}

func TestRefusesUnpinnedImage(t *testing.T) {
	if _, err := Launch(context.Background(), Options{Image: "chrislusf/seaweedfs:4.46"}); err == nil {
		t.Error("an image without a digest was accepted")
	}
}

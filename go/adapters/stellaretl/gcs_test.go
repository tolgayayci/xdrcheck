package stellaretl

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stellar/go-stellar-sdk/support/datastore"
)

// The emulator serves a SEP-54 directory to go-stellar-sdk's GCS datastore — the reader stellar-etl uses — through
// STORAGE_EMULATOR_HOST, with no credentials.
func TestEmulatorServesGCSDatastore(t *testing.T) {
	lake := lakeLayout(t)
	e, err := startEmulator(lake, "pubnet", listenAddr(0))
	if err != nil {
		t.Fatal(err)
	}
	defer e.close()
	t.Setenv("STORAGE_EMULATOR_HOST", e.host)
	ctx := context.Background()
	ds, err := datastore.NewDataStore(ctx, datastore.DataStoreConfig{Type: "GCS",
		Params: map[string]string{"destination_bucket_path": datastoreArg + "/pubnet"},
		Schema: datastore.DataStoreSchema{LedgersPerFile: 1, FilesPerPartition: 64000}})
	if err != nil {
		t.Fatal(err)
	}
	defer ds.Close()
	const key = "FC279FFF--64512000-64575999/FC26EB3A--64558277.xdr.zst"
	r, _, err := ds.GetFile(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	r.Close()
	if err != nil {
		t.Fatal(err)
	}
	want, _ := os.ReadFile(filepath.Join(lake, key))
	if !bytes.Equal(got, want) {
		t.Fatalf("object differs: %d bytes, want %d", len(got), len(want))
	}
	if ok, err := ds.Exists(ctx, "FC279FFF--64512000-64575999/FC26EB39--64558278.xdr.zst"); err != nil || ok {
		t.Fatalf("absent object: exists %v, %v", ok, err)
	}
	if s := e.servedLedgers(); !slices.Equal(s, []string{"64558277"}) {
		t.Errorf("served ledgers %v (requests %+v)", s, e.requests())
	}
}

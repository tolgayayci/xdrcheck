package stellaretl

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tolgayayci/xdrcheck/go/internal/adapter"
	"github.com/tolgayayci/xdrcheck/go/internal/classify"
	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
	"github.com/tolgayayci/xdrcheck/go/internal/pins"
	"github.com/tolgayayci/xdrcheck/go/internal/replay/run"
	"github.com/tolgayayci/xdrcheck/go/internal/testcorpus"
)

// TestKnownDivergencesAtPin runs the real stellar-etl at the pinned commit over every corpus entry that declares a
// replay divergence for it (`xdrcheck replay --assert-known`) and requires each to come out exactly as declared.
//
// It needs a cache holding the clone and the binary (`<cache>/stellar-etl/repo.git`, `bin/stellar-etl-<commit>`),
// which the adapter's own prepare makes on a networked first run. Point XDRCHECK_STELLAR_ETL_CACHE at the cache root
// (the one `xdrcheck replay` uses is the user cache directory's xdrcheck/adapters); without it the test is skipped.
func TestKnownDivergencesAtPin(t *testing.T) {
	cacheRoot := os.Getenv("XDRCHECK_STELLAR_ETL_CACHE")
	if cacheRoot == "" {
		t.Skip("XDRCHECK_STELLAR_ETL_CACHE is not set: no stellar-etl clone and binary to run")
	}
	pn, err := pins.Load(filepath.Join(testcorpus.Vendored(), "..", "pins.toml"))
	if err != nil {
		t.Fatal(err)
	}
	commit := pn.Pipelines.StellarETL.Commit
	if _, err := os.Stat(filepath.Join(cacheRoot, "stellar-etl", "bin", "stellar-etl-"+commit)); err != nil {
		t.Fatalf("no binary for the pinned commit in the cache: %v", err)
	}
	root := testcorpus.Build(t, nil, testcorpus.Options{})
	c, err := manifest.Load(root, manifest.Options{})
	if err != nil {
		t.Fatal(err)
	}
	var declared []string
	for _, e := range c.Entries {
		if classify.HasReplayDivergence(e, TargetName) {
			declared = append(declared, e.ID)
		}
	}
	if len(declared) == 0 {
		t.Fatal("no corpus entry declares a replay divergence for " + TargetName)
	}
	res, err := run.Run(context.Background(), run.Options{
		Corpus: c, HarnessVersion: "test", TargetVersion: commit, AssertKnown: true, Input: "sep54-dir", KeepGoing: true,
		Adapter: adapter.Config{Argv: []string{os.Args[0], "--cache-dir", cacheRoot, "--offline"},
			Env: append(os.Environ(), "XDRCHECK_STELLARETL_MAIN=1"), Name: "stellaretl-real"},
		WorkDir: t.TempDir(), CacheDir: cacheRoot, Out: testWriter{t}, Log: testWriter{t},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("entries %s: %v", strings.Join(declared, ", "), res.ByResult)
	if res.Rows < len(declared) || res.Unexpected != 0 || res.Faults != 0 {
		t.Fatalf("rows %d (entries %d), unexpected %d, faults %d, notes %v", res.Rows, len(declared), res.Unexpected, res.Faults, res.Notes)
	}
}

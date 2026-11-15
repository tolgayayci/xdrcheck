package hunt

import (
	"os"
	"path/filepath"
	"testing"
)

// The command's earlier name still works: its environment variables and its per-user directories are read when
// only they exist, and the new name always wins.
func TestEnvAndDirsOfTheEarlierName(t *testing.T) {
	t.Setenv("XDRCHECK_DATASET", "")
	os.Unsetenv("XDRCHECK_DATASET")
	t.Setenv("XCC_DATASET", "/old/dataset")
	if got := Env("DATASET"); got != "/old/dataset" {
		t.Fatalf("Env(DATASET) with only XCC_DATASET set: got %q", got)
	}
	t.Setenv("XDRCHECK_DATASET", "/new/dataset")
	if got := Env("DATASET"); got != "/new/dataset" {
		t.Fatalf("Env(DATASET) with both set: got %q", got)
	}

	data := t.TempDir()
	t.Setenv("XDG_DATA_HOME", data)
	if got := DataDir(); got != filepath.Join(data, Tool) {
		t.Fatalf("DataDir with nothing there: got %s", got)
	}
	if err := os.Mkdir(filepath.Join(data, "xcc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := DataDir(); got != filepath.Join(data, "xcc") {
		t.Fatalf("DataDir with only the earlier directory: got %s", got)
	}
	if err := os.Mkdir(filepath.Join(data, Tool), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := DataDir(); got != filepath.Join(data, Tool) {
		t.Fatalf("DataDir with both directories: got %s", got)
	}

	if got := SchemaID("run"); got != "xcc.run/v1" {
		t.Fatalf("SchemaID(run) = %q; the data-side schema ids are frozen", got)
	}
}

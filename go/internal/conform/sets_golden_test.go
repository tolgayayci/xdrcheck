package conform

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The resolved columns of every set of the repository's drivers/sets.toml (with drivers/sets.d/), field by field,
// must equal testdata/sets-resolved.golden. The golden file was written from the single sets file before the
// columns moved into sets.d/, so a split or a loader change that alters any set's resolution fails here.
// XDRCHECK_UPDATE_SETS_GOLDEN=1 rewrites it, for a deliberate change of the columns or sets.
func TestSetResolutionGolden(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	s, err := LoadSets(filepath.Join(root, "drivers", "sets.toml"), root)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, name := range s.SetNames() {
		cols, err := s.Resolve(name)
		if err != nil {
			t.Fatal(err)
		}
		b.WriteString("set " + name + "\n")
		for _, c := range cols {
			// Every field the file sets, under its TOML name; Root, Base and the --sdk fields are not the file's.
			row := map[string]any{"id": c.ID, "sdk": c.SDK, "kind": c.Kind, "ecosystem": c.Ecosystem,
				"package": c.Package, "target": c.Target, "version": c.Version, "profile": c.Profile, "role": c.Role,
				"dir": c.Dir, "run": c.Run, "levels": c.Levels}
			if c.Floor != nil {
				row["floor"] = c.Floor
			}
			if c.Limits != nil {
				row["limits"] = c.Limits
			}
			j, err := json.Marshal(row)
			if err != nil {
				t.Fatal(err)
			}
			b.WriteString("  " + string(j) + "\n")
		}
	}
	golden := filepath.Join("testdata", "sets-resolved.golden")
	if os.Getenv("XDRCHECK_UPDATE_SETS_GOLDEN") == "1" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, []byte(b.String()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if b.String() != string(want) {
		t.Errorf("resolved sets differ from %s (XDRCHECK_UPDATE_SETS_GOLDEN=1 rewrites it after a deliberate change)", golden)
	}
}

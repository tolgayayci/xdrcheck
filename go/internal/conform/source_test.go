package conform

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --sdk: a column of a driver whose Makefiles read XDRCHECK_SDK_SOURCE builds from the checkout in a private copy of
// its language directory, with a cache of its own; run refuses a copy that was not built from that checkout.
func TestWithSource(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDRCHECK_CACHE", filepath.Join(root, "cache"))
	write := func(rel, body string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("drivers/x/rules.mk", "build:\n\techo $(XDRCHECK_SDK_SOURCE)\n")
	write("drivers/x/1.0/Makefile", "include ../rules.mk\n")
	write("drivers/x/1.0/bin/xdrcheck-driver", "stale build output, never copied\n")
	write("drivers/y/1.0/Makefile", "build:\n")
	checkout := filepath.Join(root, "checkout")
	write("checkout/go.mod", "module example\n")
	x := &Column{ID: "x@1.0", SDK: "x", Dir: "drivers/x/1.0"}
	x2 := &Column{ID: "x@1.0:p", SDK: "x", Dir: "drivers/x/1.0", Profile: "p"}
	y := &Column{ID: "y@1.0", SDK: "y", Dir: "drivers/y/1.0"}
	s := &Sets{Root: root, Columns: map[string]*Column{x.ID: x, x2.ID: x2, y.ID: y}}

	if _, err := s.WithSource([]*Column{x, y}, checkout); err == nil || !strings.Contains(err.Error(), "one SDK") {
		t.Fatalf("two SDKs: %v", err)
	}
	if _, err := s.WithSource([]*Column{y}, checkout); err == nil || !strings.Contains(err.Error(), "XDRCHECK_SDK_SOURCE") {
		t.Fatalf("a driver without support: %v", err)
	}
	if _, err := s.WithSource([]*Column{x}, filepath.Join(root, "missing")); err == nil {
		t.Fatal("a missing checkout was accepted")
	}
	cols, err := s.WithSource([]*Column{x, x2}, checkout)
	if err != nil {
		t.Fatal(err)
	}
	c := cols[0]
	if x.Source != "" || c.Source != checkout || c.SourceDir != cols[1].SourceDir || s.AbsDir(c) != c.SourceDir {
		t.Fatalf("source column %+v (the original must stay pinned: %+v)", c, x)
	}
	if strings.HasPrefix(c.SourceDir, root+"/drivers") || CacheDir(c) == CacheDir(x) || !strings.Contains(CacheDir(c), "@source-") {
		t.Fatalf("source dir %s, cache %s (pinned %s)", c.SourceDir, CacheDir(c), CacheDir(x))
	}
	if err := s.CheckSource(c); err == nil {
		t.Fatal("run accepted a column that was never built from the checkout")
	}
	if err := s.PrepareSource(c); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(c.SourceDir, "Makefile")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(c.SourceDir), "rules.mk")); err != nil {
		t.Fatal("the shared rules beside the version directory were not copied")
	}
	if _, err := os.Stat(filepath.Join(c.SourceDir, "bin")); !os.IsNotExist(err) {
		t.Fatalf("build output was copied: %v", err)
	}
	write(strings.TrimPrefix(filepath.Join(c.SourceDir, SourceFile), root+"/"), "/somewhere/else\n")
	if err := s.CheckSource(c); err == nil || !strings.Contains(err.Error(), "/somewhere/else") {
		t.Fatalf("a copy built from another checkout: %v", err)
	}
	if err := os.WriteFile(filepath.Join(c.SourceDir, SourceFile), []byte(checkout+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckSource(c); err != nil {
		t.Fatal(err)
	}
	// A fresh fetch starts the copy over: what the last build left is gone.
	if err := s.PrepareSource(c); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckSource(c); err == nil {
		t.Fatal("PrepareSource kept the previous build")
	}
}

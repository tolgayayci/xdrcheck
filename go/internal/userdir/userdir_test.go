package userdir

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUnder(t *testing.T) {
	base := t.TempDir()
	if got := Under(base); got != filepath.Join(base, Name) {
		t.Fatalf("nothing there: got %s", got)
	}
	if err := os.Mkdir(filepath.Join(base, legacy), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := Under(base); got != filepath.Join(base, legacy) {
		t.Fatalf("only the legacy directory: got %s", got)
	}
	if err := os.Mkdir(filepath.Join(base, Name), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := Under(base); got != filepath.Join(base, Name) {
		t.Fatalf("both: got %s", got)
	}
}

func TestLegacyEnv(t *testing.T) {
	t.Setenv("XCC_USERDIR_TEST_OLD_ONLY", "old")
	t.Setenv("XCC_USERDIR_TEST_BOTH", "old")
	t.Setenv("XDRCHECK_USERDIR_TEST_BOTH", "new")
	t.Setenv("XDRCHECK_USERDIR_TEST_OLD_ONLY", "")
	os.Unsetenv("XDRCHECK_USERDIR_TEST_OLD_ONLY")
	if got := Getenv("USERDIR_TEST_OLD_ONLY"); got != "old" {
		t.Fatalf("Getenv fallback: got %q", got)
	}
	if got := Getenv("USERDIR_TEST_BOTH"); got != "new" {
		t.Fatalf("Getenv: the new name must win, got %q", got)
	}
	set := LegacyEnv()
	if got := os.Getenv("XDRCHECK_USERDIR_TEST_OLD_ONLY"); got != "old" {
		t.Fatalf("LegacyEnv did not copy the old variable: got %q (set %v)", got, set)
	}
	if got := os.Getenv("XDRCHECK_USERDIR_TEST_BOTH"); got != "new" {
		t.Fatalf("LegacyEnv overwrote the new variable: got %q", got)
	}
	os.Unsetenv("XDRCHECK_USERDIR_TEST_OLD_ONLY")
}

func TestOverlayLegacyDirectory(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	want := filepath.Join(home, ".local", "share", Name, "overlay")
	if got := Overlay(); got != want {
		t.Fatalf("no directory: got %s, want %s", got, want)
	}
	old := filepath.Join(home, ".local", "share", legacy)
	if err := os.MkdirAll(filepath.Join(old, "overlay"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := Overlay(); got != filepath.Join(old, "overlay") {
		t.Fatalf("only the legacy directory: got %s", got)
	}
}

package pins

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Every tracked pin of the repository's pins file is found, with the value the strict reader sees.
func TestTrackedPinsRepository(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(file), "..", "..", "..", "pins.toml")
	text, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tracked, err := TrackedPins(string(text))
	if err != nil {
		t.Fatal(err)
	}
	p, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"js.stellar_sdk":       p.JS.StellarSDK,
		"python.stellar_sdk":   p.Python.StellarSDK,
		"go.go_stellar_sdk":    p.Go.GoStellarSDK,
		"rust.stellar_xdr":     p.Rust.StellarXDR,
		"rust.soroban_sdk":     p.Rust.SorobanSDK,
		"stellar_core.version": p.StellarCore.Version,
		"services.stellar_rpc": p.Services["stellar_rpc"],
	}
	got := map[string]string{}
	for _, tr := range tracked {
		got[tr.Key] = tr.Current
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: tracked %q, pins.toml %q", k, got[k], v)
		}
	}
}

func TestTrackedPinsErrors(t *testing.T) {
	for _, bad := range []string{
		"[js]\n# renovate: datasource=npm\nstellar_sdk = \"1.0.0\"\n",
		"[js]\n# renovate: datasource=npm depName=x\n[python]\n",
		"[js]\n# renovate: datasource=npm depName=x\nlist = [1]\n",
		"[js]\n# renovate: datasource=npm depName=x colour=red\nv = \"1\"\n",
		"[js]\n# renovate: datasource=npm depName=x extractVersion=^v(.*)$\nv = \"1\"\n",
		"# renovate: datasource=npm depName=x",
	} {
		if _, err := TrackedPins(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestNewestStable(t *testing.T) {
	tags := []string{"v9.2.0rc6", "v29.0.0", "v30.0.0", "v30.0.1", "v30.1.0-rc.1", "v30.0.0-internal", "galexie-v30.0.2"}
	if v, _ := NewestStable(tags, "", "v30.0.0"); v != "v30.0.1" {
		t.Errorf("plain tags: %s", v)
	}
	if v, _ := NewestStable(tags, "", "30.0.0"); v != "30.0.1" {
		t.Errorf("keeps the pin's form: %s", v)
	}
	if v, _ := NewestStable(tags, `^galexie-(?<version>v\d+\.\d+\.\d+)$`, "v30.0.0"); v != "v30.0.2" {
		t.Errorf("extractVersion: %s", v)
	}
	if v, _ := NewestStable([]string{"v28.0", "v30.0", "v23.0"}, "", "v30.0"); v != "v30.0" {
		t.Errorf("two-part tags: %s", v)
	}
	if _, err := NewestStable([]string{"v1.0.0-rc.1"}, "", "1.0.0"); err == nil || !strings.Contains(err.Error(), "no stable tag") {
		t.Errorf("no stable tag: %v", err)
	}
	for _, c := range []struct {
		cur, latest string
		behind      bool
	}{
		{"17.4.0", "17.5.0", true}, {"v0.8.0", "v0.9.0", true}, {"17.4.0", "17.4.0", false},
		{"30.0.0-rc.1", "30.0.0", true}, {"2.8.34", "2.8.9", false}, {"v30.0", "v30.0", false},
	} {
		if Behind(c.cur, c.latest) != c.behind {
			t.Errorf("Behind(%s, %s) = %v", c.cur, c.latest, !c.behind)
		}
	}
	if escapeModule("github.com/BurntSushi/toml") != "github.com/!burnt!sushi/toml" {
		t.Errorf("module escaping")
	}
}

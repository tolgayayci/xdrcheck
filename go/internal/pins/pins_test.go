package pins

import (
	"os"
	"strings"
	"testing"
)

const pinsFile = "../../../pins.toml"

func TestLoadRepositoryPins(t *testing.T) {
	p, err := Load(pinsFile)
	if err != nil {
		t.Fatal(err)
	}
	checks := map[string]string{
		"go.toolchain":            p.Go.Toolchain,
		"rust.stellar_xdr":        p.Rust.StellarXDR,
		"stellar_core.version":    p.StellarCore.Version,
		"stellar_core.commit":     p.StellarCore.Commit,
		"stellar_xdr_definitions": p.StellarXDRDefinitions.Tag,
		"wallet_backend.current":  p.Pipelines.WalletBackend.Current,
		"public_lake.testnet":     p.PublicLake.Testnet,
		"images.seaweedfs":        p.Images["seaweedfs"],
		"services.stellar_rpc":    p.Services["stellar_rpc"],
	}
	for k, v := range checks {
		if v == "" {
			t.Errorf("%s is empty", k)
		}
	}
	if p.Protocol.MaxSupported < 30 {
		t.Errorf("protocol.max_supported = %d", p.Protocol.MaxSupported)
	}
	if len(p.StellarCore.RuntimeDebs) == 0 || len(p.StellarCore.GoldenTiers) == 0 {
		t.Error("stellar_core runtime_debs or golden_tiers empty")
	}
	if a, ok := p.Pipelines.WalletBackend.AcceptancePair("731"); !ok || len(a.Prefix) != 40 || len(a.Fixed) != 40 {
		t.Errorf("acceptance pair 731: %+v %v", a, ok)
	}
	if cols := p.Conformance.Columns["js"]; len(cols) == 0 || cols[0] != p.JS.StellarSDK {
		t.Errorf("js columns %v, first should be the pinned SDK %s", cols, p.JS.StellarSDK)
	}
	if len(p.FileSHA256) != 64 {
		t.Errorf("file sha256 %q", p.FileSHA256)
	}
}

func TestRejectsUnknownKeyAndMissingSection(t *testing.T) {
	data, err := os.ReadFile(pinsFile)
	if err != nil {
		t.Fatal(err)
	}
	src := string(data)
	unknown := strings.Replace(src, "[go]\n", "[go]\nmystery = \"1.0\"\n", 1)
	if _, err := Parse([]byte(unknown)); err == nil || !strings.Contains(err.Error(), "go.mystery") {
		t.Errorf("unknown key: %v", err)
	}
	i := strings.Index(src, "[docs]")
	j := strings.Index(src, "[conformance.columns]")
	if i < 0 || j < i {
		t.Fatal("pins.toml layout changed; update the test")
	}
	if _, err := Parse([]byte(src[:i] + src[j:])); err == nil || !strings.Contains(err.Error(), "docs") {
		t.Errorf("missing section: %v", err)
	}
}

// Superseded -updates builds leave the plain Ubuntu pool, so every runtime library is fetched from a
// snapshot.ubuntu.com URL first, with the plain pool as the fallback.
func TestRuntimeDebsUseSnapshotURLs(t *testing.T) {
	p, err := Load(pinsFile)
	if err != nil {
		t.Fatal(err)
	}
	const snapshot = "https://snapshot.ubuntu.com/ubuntu/"
	debs := p.StellarCore.RuntimeDebs
	if !strings.HasPrefix(debs["llvm_base_url"].SHA256, snapshot) {
		t.Errorf("llvm_base_url %q is not a snapshot URL", debs["llvm_base_url"].SHA256)
	}
	if debs["llvm_fallback_base_url"].SHA256 == "" {
		t.Error("llvm_fallback_base_url is missing")
	}
	for name, d := range debs {
		if !strings.HasSuffix(name, ".deb") || d.URL == "" {
			continue
		}
		if !strings.HasPrefix(d.URL, snapshot) || !strings.HasSuffix(d.URL, "/"+name) {
			t.Errorf("%s: url %q is not a snapshot URL of the file", name, d.URL)
		}
		if !strings.HasSuffix(d.FallbackURL, "/"+name) {
			t.Errorf("%s: fallback_url %q", name, d.FallbackURL)
		}
	}
	var d RuntimeDeb
	if err := d.UnmarshalTOML(map[string]any{"url": "u", "fallback_url": "f", "sha256": "s"}); err != nil || d.FallbackURL != "f" {
		t.Errorf("fallback_url: %+v %v", d, err)
	}
}

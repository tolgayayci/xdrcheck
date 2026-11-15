package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/tolgayayci/xdrcheck/go/internal/pins"
)

// pinnedBuild is build information that agrees with the pins file.
func pinnedBuild(p *pins.Pins) func() (*debug.BuildInfo, bool) {
	return func() (*debug.BuildInfo, bool) {
		return &debug.BuildInfo{GoVersion: "go" + p.Go.Toolchain, Deps: []*debug.Module{
			{Path: goSDK, Version: p.Go.GoStellarSDK}, {Path: "github.com/BurntSushi/toml", Version: p.Go.TOML}}}, true
	}
}

func runPinsChecker(t *testing.T, root string, setup func(c *pinsChecker)) (int, string) {
	t.Helper()
	p, err := pins.Load(filepath.Join(root, "pins.toml"))
	if err != nil {
		t.Fatal(err)
	}
	text, _ := os.ReadFile(filepath.Join(root, "pins.toml"))
	var out bytes.Buffer
	// The schedule is read against a date before every event, so these tests do not change with the clock;
	// the dated checks have their own test (TestPinsScheduleDates) and `xdrcheck pins check` reads the real date.
	c := &pinsChecker{root: root, p: p, pinsText: string(text), out: &out, buildInfo: pinnedBuild(p), cacheDir: t.TempDir(),
		today: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)}
	if setup != nil {
		setup(c)
	}
	c.run()
	return c.drifts, out.String()
}

// The repository agrees with its pins file.
func TestPinsCheckRepository(t *testing.T) {
	drifts, out := runPinsChecker(t, repoAbs, nil)
	if drifts != 0 {
		t.Errorf("%d drift(s) in the repository:\n%s", drifts, out)
	}
	var stdout, stderr bytes.Buffer
	t.Chdir(repoAbs)
	if code := pinsMain([]string{"check", "--pins", "nope.toml"}, &stdout, &stderr); code != 2 {
		t.Errorf("missing pins file: exit %d", code)
	}
	if code := pinsMain([]string{"verify"}, &stdout, &stderr); code != 2 {
		t.Errorf("unknown subcommand: exit %d", code)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	os.MkdirAll(filepath.Dir(path), 0o755)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func sha(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// Each kind of drift is reported: toolchain files, lock files, a version named in a script, an image without a
// digest, the binary's toolchain, and fetched caches that differ from the pins.
func TestPinsCheckDrift(t *testing.T) {
	root := t.TempDir()
	text, _ := os.ReadFile(filepath.Join(repoAbs, "pins.toml"))
	pinsText := strings.Replace(string(text), `seaweedfs = "chrislusf/seaweedfs:4.46@sha256:`, `seaweedfs = "chrislusf/seaweedfs:4.46"
old_seaweedfs = "chrislusf/seaweedfs:4.46@sha256:`, 1)
	writeFile(t, filepath.Join(root, "pins.toml"), pinsText)
	p, err := pins.Parse([]byte(pinsText))
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "mise.toml"), "[tools]\ngo = \""+p.Go.Toolchain+"\"\nnode = \"20.0.1\"\npython = \""+p.Python.Version+"\"\njava = \""+p.Java.JDK+"\"\n")
	writeFile(t, filepath.Join(root, "rust-toolchain.toml"), "[toolchain]\nchannel = \"1.80.0\"\n")
	writeFile(t, filepath.Join(root, "go", "go.mod"), "module x\n\ngo "+p.Go.Toolchain+"\n\nrequire (\n\tgithub.com/BurntSushi/toml "+p.Go.TOML+"\n\tgithub.com/stellar/go-stellar-sdk v0.6.0\n)\n")
	writeFile(t, filepath.Join(root, "drivers", "js", "17.4.0", "package-lock.json"), `{"packages":{"node_modules/@stellar/stellar-sdk":{"version":"17.3.0"}}}`)
	writeFile(t, filepath.Join(root, "drivers", "rust", "30.0.0", "Cargo.lock"),
		"version = 4\n\n[[package]]\nname = \"stellar-xdr\"\nversion = \"28.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n"+
			"[[package]]\nname = \"xdrcheck-driver-rust\"\nversion = \"0.1.0\"\ndependencies = [\n \"stellar-xdr\",\n]\n")
	writeFile(t, filepath.Join(root, "scripts", "fetch.d", "tool.sh"), "#!/usr/bin/env bash\ncurl -O https://example.invalid/tool-9.8.7.tar.gz\nping 1.1.1.1\n")

	cache := t.TempDir()
	core := filepath.Join(cache, "stellar-core", p.StellarCore.Version)
	writeFile(t, filepath.Join(core, "pkg", "usr", "bin", "stellar-core"), "not the pinned binary")
	writeFile(t, filepath.Join(core, "dl", filepath.Base(p.StellarCore.DebURL)), "not the pinned package")

	drifts, out := runPinsChecker(t, root, func(c *pinsChecker) {
		c.cacheDir = cache
		c.buildInfo = func() (*debug.BuildInfo, bool) {
			return &debug.BuildInfo{GoVersion: "go1.25.0", Deps: []*debug.Module{{Path: goSDK, Version: "v0.7.0"}}}, true
		}
	})
	for _, want := range []string{
		"FAIL mise.toml tools.node: pins.toml says " + p.JS.Node + ", found 20.0.1",
		"FAIL rust-toolchain.toml channel",
		"FAIL go/go.mod requires github.com/stellar/go-stellar-sdk v0.6.0",
		"FAIL drivers/js/17.4.0/package-lock.json @stellar/stellar-sdk: pins.toml says 17.4.0, found 17.3.0",
		"FAIL drivers/rust/30.0.0/Cargo.lock: xdrcheck-driver-rust depends on stellar-xdr 28.0.0",
		"FAIL scripts/fetch.d/tool.sh:2 names version 9.8.7",
		"FAIL pins.toml images.seaweedfs",
		"FAIL Go toolchain this xdrcheck was built with: pins.toml says go" + p.Go.Toolchain + ", found go1.25.0",
		"FAIL module github.com/stellar/go-stellar-sdk in this xdrcheck",
		"FAIL cached binary stellar-core/" + p.StellarCore.Version + "/pkg/usr/bin/stellar-core sha256",
		"FAIL cached download stellar-core/" + p.StellarCore.Version + "/dl/" + filepath.Base(p.StellarCore.DebURL),
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q", want)
		}
	}
	if strings.Contains(out, "1.1.1") || strings.Contains(out, "llvm_base_url") {
		t.Errorf("an address or a non-package key was taken for a version:\n%s", out)
	}
	if drifts < 11 {
		t.Errorf("%d drifts:\n%s", drifts, out)
	}

	// A cache that matches its pin is not a drift.
	writeFile(t, filepath.Join(core, "pkg", "usr", "bin", "stellar-core"), "pinned")
	_, out = runPinsChecker(t, root, func(c *pinsChecker) {
		c.cacheDir = cache
		c.p.StellarCore.BinarySHA256 = sha("pinned")
	})
	if strings.Contains(out, "cached binary") {
		t.Errorf("matching binary reported:\n%s", out)
	}
}

// A conformance driver's cache filled from another lock file is a drift.
func TestPinsCheckDriverCaches(t *testing.T) {
	cache := t.TempDir()
	lock, err := os.ReadFile(filepath.Join(repoAbs, "drivers", "js", "17.4.0", "package-lock.json"))
	if err != nil {
		t.Skip("no JavaScript driver directory")
	}
	writeFile(t, filepath.Join(cache, "conform", "drivers-js-17.4.0", "fetched"), sha(string(lock))+"\n")
	writeFile(t, filepath.Join(cache, "conform", "drivers-js-17.3.0", "fetched"), sha("another lock")+"\n")
	writeFile(t, filepath.Join(cache, "conform", "drivers-go-v0.8.0", "fetched"), "go-stellar-sdk v0.7.3\n")
	_, out := runPinsChecker(t, repoAbs, func(c *pinsChecker) { c.cacheDir = cache })
	if strings.Contains(out, "drivers/js/17.4.0") {
		t.Errorf("a matching cache is reported:\n%s", out)
	}
	for _, want := range []string{"FAIL cache of drivers/js/17.3.0", "FAIL cache of drivers/go/v0.8.0 (fetched SDK): pins.toml says go-stellar-sdk v0.8.0, found go-stellar-sdk v0.7.3"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

// Versions compiled into the kit's code follow pins.toml: a constant that differs, a site that is gone or no
// longer matches, and a marker on a stale or unknown pin are each a drift.
func TestPinsCheckCodeConstants(t *testing.T) {
	root := t.TempDir()
	text, _ := os.ReadFile(filepath.Join(repoAbs, "pins.toml"))
	writeFile(t, filepath.Join(root, "pins.toml"), string(text))
	p, err := pins.Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	next := p.Protocol.MaxSupported + 1
	for _, k := range codeConstants {
		src, err := os.ReadFile(filepath.Join(repoAbs, k.file))
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(root, k.file), string(src))
	}
	writeFile(t, filepath.Join(root, "crates/xdrcheck-xdr/src/ledger.rs"), fmt.Sprintf("pub const DEFAULT_MAX_PROTOCOL: u32 = %d;\n", next))
	writeFile(t, filepath.Join(root, "drivers/rust/src/reach.rs"), fmt.Sprintf("pub const KNOWN_PROTOCOL: u32 = %d; // pin:protocol.max_supported\n", next))
	writeFile(t, filepath.Join(root, "crates/xdrcheck-corpus/src/cmd/verify/report.rs"), "let oracle = \"1.2.3\";\n")
	os.Remove(filepath.Join(root, "drivers/stub/main.go"))
	writeFile(t, filepath.Join(root, "go/internal/x/x.go"), "const a = 7 // pin:protocol.max_supported\nconst b = 1 // pin:rust.mystery\n")
	drifts, out := runPinsChecker(t, root, nil)
	for _, want := range []string{
		fmt.Sprintf("FAIL crates/xdrcheck-xdr/src/ledger.rs protocol.max_supported: pins.toml says %d, found %d", p.Protocol.MaxSupported, next),
		fmt.Sprintf("FAIL drivers/rust/src/reach.rs protocol.max_supported: pins.toml says %d, found %d", p.Protocol.MaxSupported, next),
		fmt.Sprintf("FAIL drivers/rust/src/reach.rs:1 pin:protocol.max_supported: pins.toml says %d, found %d", p.Protocol.MaxSupported, next),
		"FAIL crates/xdrcheck-corpus/src/cmd/verify/report.rs: no constant matching",
		"FAIL drivers/stub/main.go: open",
		fmt.Sprintf("FAIL go/internal/x/x.go:1 pin:protocol.max_supported: pins.toml says %d, found 7", p.Protocol.MaxSupported),
		"FAIL go/internal/x/x.go:2: marker pin:rust.mystery names no pin the check knows",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "FAIL drivers/go/driver/decode.go") || strings.Contains(out, "FAIL corpus/corpus.json") {
		t.Errorf("an unchanged site was reported:\n%s", out)
	}
	if drifts < 7 {
		t.Errorf("%d drifts:\n%s", drifts, out)
	}
}

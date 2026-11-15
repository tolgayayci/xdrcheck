package main

// xdrcheck pins check [--pins FILE]: every version the kit builds or runs
// against agrees with pins.toml, the single source of versions.
//
// What it compares with the pins file:
//   - the toolchain files: mise.toml [tools], rust-toolchain.toml (root and contracts/), the go directive of
//     every go.mod of the kit;
//   - the lock files: go.mod requirements (go/, lint/, drivers/), the workspace members' resolved crates in
//     Cargo.lock (root, contracts/, drivers/rust/<version>/), the SDK each drivers/js/<version>/package-lock.json
//     resolves, and drivers/sets.toml's columns;
//   - digests: every image is referenced by sha256 digest, every download carries a sha256;
//   - versions named elsewhere: every version-like string (x.y.z) in the workflows, the scripts and the
//     Makefiles appears in pins.toml;
//   - versions compiled into the kit's own code: the protocol ceiling of the gates, the generator and every
//     conformance driver, and the oracle version the reports name (codeConstants);
//   - what is in use: the Go toolchain and modules this xdrcheck binary was built with, and, where they exist, the
//     fetched caches — the stellar-core package and binary, and each conformance driver directory's cache stamp.
//     A cache that has not been fetched is reported, not failed (the static check runs without downloads).
//
//   - dates: every pins.toml [[schedule]] event (a mainnet vote, a testnet reset) against today; with
//     --network, the networks' live state as well (pins_watch.go).
//
// The published evidence/ transcripts keep the versions their probes used and are not checked. Exit codes: 0
// everything agrees (warnings allowed); 1 a drift; 2 the pins file does not read.
//
// xdrcheck pins latest [--pins FILE] [--json FILE]: the newest published version of every pin that follows an
// upstream release, against the pin (pins_latest.go).

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/tolgayayci/xdrcheck/go/internal/conform"
	"github.com/tolgayayci/xdrcheck/go/internal/pins"
	"github.com/tolgayayci/xdrcheck/go/internal/userdir"
)

func init() {
	register("pins", "check that every version used matches pins.toml", func(args []string) int {
		return pinsMain(args, os.Stdout, os.Stderr)
	})
}

func pinsMain(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "latest" {
		return pinsLatestMain(args[1:], stdout, stderr, nil)
	}
	if len(args) == 0 || args[0] != "check" {
		fmt.Fprintln(stderr, "usage: xdrcheck pins check [--pins FILE] [--today YYYY-MM-DD] [--network]\n       xdrcheck pins latest [--pins FILE] [--json FILE] [--list]")
		return 2
	}
	fs := flag.NewFlagSet("xdrcheck pins check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	pinsFile := fs.String("pins", "", "pins file (default pins.toml at the repository root)")
	todayFlag := fs.String("today", "", "read the pins.toml [[schedule]] events against this date (YYYY-MM-DD, UTC) instead of the clock")
	network := fs.Bool("network", false, "also read the networks' state (Horizon roots of mainnet and testnet, the status page's scheduled maintenances) and compare it with the pins; read-only GETs of public endpoints")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "xdrcheck pins check: unexpected arguments %v\n", fs.Args())
		return 2
	}
	var today time.Time
	if *todayFlag != "" {
		t, err := time.ParseInLocation(pins.DateLayout, *todayFlag, time.UTC)
		if err != nil {
			fmt.Fprintf(stderr, "xdrcheck pins check: --today %q is not YYYY-MM-DD\n", *todayFlag)
			return 2
		}
		today = t
	}
	root, path, code := resolvePinsFile(*pinsFile, stderr, "xdrcheck pins check")
	if code != 0 {
		return code
	}
	p, err := pins.Load(path)
	if err != nil {
		fmt.Fprintf(stderr, "xdrcheck pins check: %v\n", err)
		return 2
	}
	text, _ := os.ReadFile(path)
	c := &pinsChecker{root: root, p: p, pinsText: string(text), out: stdout, today: today, withNetwork: *network}
	c.run()
	fmt.Fprintf(stdout, "pins check: %d checks, %d drift(s), %d warning(s)\n", c.checks, c.drifts, c.warnings)
	if c.drifts > 0 {
		return 1
	}
	return 0
}

// resolvePinsFile resolves --pins: the file and the root the checked paths are relative to (its directory, or the
// repository root by default). code is non-zero when neither resolves.
func resolvePinsFile(flagValue string, stderr io.Writer, cmd string) (root, path string, code int) {
	path = flagValue
	if path == "" {
		r, err := repoRoot()
		if err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", cmd, err)
			return "", "", 2
		}
		return r, filepath.Join(r, "pins.toml"), 0
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", cmd, err)
		return "", "", 2
	}
	return filepath.Dir(abs), path, 0
}

type pinsChecker struct {
	root     string
	p        *pins.Pins
	pinsText string
	out      io.Writer
	checks   int
	drifts   int
	warnings int
	// buildInfo replaces debug.ReadBuildInfo in tests.
	buildInfo func() (*debug.BuildInfo, bool)
	// cacheDir replaces $XDRCHECK_CACHE / ~/.cache/xdrcheck in tests.
	cacheDir string
	// today is the date the [[schedule]] events are read against (zero: the clock).
	today time.Time
	// withNetwork adds the network-state checks; sources replaces their endpoints in tests.
	withNetwork bool
	sources     *watchSources
}

// expect records one comparison.
func (c *pinsChecker) expect(what, want, have string) {
	c.checks++
	if want != have {
		c.drifts++
		if have == "" {
			have = "(missing)"
		}
		fmt.Fprintf(c.out, "FAIL %s: pins.toml says %s, found %s\n", what, want, have)
	}
}

func (c *pinsChecker) failf(format string, a ...any) {
	c.checks++
	c.drifts++
	fmt.Fprintf(c.out, "FAIL "+format+"\n", a...)
}

func (c *pinsChecker) infof(format string, a ...any) { fmt.Fprintf(c.out, "info "+format+"\n", a...) }

func (c *pinsChecker) rel(p string) string {
	if r, err := filepath.Rel(c.root, p); err == nil {
		return filepath.ToSlash(r)
	}
	return p
}

func (c *pinsChecker) run() {
	c.toolchainFiles()
	c.goModules()
	c.cargoLocks()
	c.jsLocks()
	c.columnSets()
	c.digests()
	c.versionStrings()
	c.codeConstants()
	c.binary()
	c.caches()
	c.schedule()
	if c.withNetwork {
		c.network()
	}
}

// ---- toolchain files ----

func (c *pinsChecker) toolchainFiles() {
	var mise struct {
		Tools map[string]string `toml:"tools"`
	}
	if _, err := toml.DecodeFile(filepath.Join(c.root, "mise.toml"), &mise); err == nil {
		c.expect("mise.toml tools.go", c.p.Go.Toolchain, mise.Tools["go"])
		c.expect("mise.toml tools.node", c.p.JS.Node, mise.Tools["node"])
		c.expect("mise.toml tools.python", c.p.Python.Version, mise.Tools["python"])
		c.expect("mise.toml tools.java", c.p.Java.JDK, mise.Tools["java"])
	} else if !errors.Is(err, fs.ErrNotExist) {
		c.failf("mise.toml: %v", err)
	}
	for _, f := range []string{"rust-toolchain.toml", "contracts/rust-toolchain.toml"} {
		var rt struct {
			Toolchain map[string]any `toml:"toolchain"`
		}
		_, err := toml.DecodeFile(filepath.Join(c.root, f), &rt)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			c.failf("%s: %v", f, err)
			continue
		}
		ch, _ := rt.Toolchain["channel"].(string)
		c.expect(f+" channel", c.p.Rust.Toolchain, ch)
	}
}

// ---- go.mod ----

type goMod struct {
	goVersion string
	requires  map[string]string
}

func readGoMod(path string) (*goMod, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	m := &goMod{requires: map[string]string{}}
	in := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.Index(line, "//"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		fields := strings.Fields(line)
		switch {
		case len(fields) == 0:
		case in && fields[0] == ")":
			in = false
		case in && len(fields) >= 2:
			m.requires[fields[0]] = fields[1]
		case fields[0] == "go" && len(fields) == 2:
			m.goVersion = fields[1]
		case fields[0] == "require" && len(fields) == 2 && fields[1] == "(":
			in = true
		case fields[0] == "require" && len(fields) >= 3:
			m.requires[fields[1]] = fields[2]
		}
	}
	return m, sc.Err()
}

const goSDK = "github.com/stellar/go-stellar-sdk"

func (c *pinsChecker) goModules() {
	allowedSDK := append([]string{c.p.Go.GoStellarSDK}, c.p.Conformance.Columns["go"]...)
	var mods []string
	for _, d := range []string{"go", "lint", "drivers"} {
		filepath.WalkDir(filepath.Join(c.root, d), func(p string, e fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if e.IsDir() && (e.Name() == "node_modules" || e.Name() == "bin" || e.Name() == "target") {
				return filepath.SkipDir
			}
			if e.Name() == "go.mod" {
				mods = append(mods, p)
			}
			return nil
		})
	}
	for _, p := range mods {
		m, err := readGoMod(p)
		if err != nil {
			c.failf("%s: %v", c.rel(p), err)
			continue
		}
		r := c.rel(p)
		c.expect(r+" go directive", c.p.Go.Toolchain, m.goVersion)
		if v, ok := m.requires[goSDK]; ok && !slices.Contains(allowedSDK, v) {
			c.failf("%s requires %s %s, which is neither [go] go_stellar_sdk nor a [conformance.columns] go version", r, goSDK, v)
		}
		switch {
		case r == "go/go.mod":
			c.expect(r+" "+goSDK, c.p.Go.GoStellarSDK, m.requires[goSDK])
			c.expect(r+" github.com/BurntSushi/toml", c.p.Go.TOML, m.requires["github.com/BurntSushi/toml"])
		case r == "lint/go.mod":
			c.expect(r+" "+goSDK, c.p.Go.GoStellarSDK, m.requires[goSDK])
			c.expect(r+" golang.org/x/tools", c.p.Go.XTools, m.requires["golang.org/x/tools"])
		case goVersionDirRe.MatchString(r):
			// drivers/go/<version>/go.mod resolves exactly the SDK its directory names (drivers/go/driver and
			// drivers/go/views are shared packages, not versions).
			dirVersion := filepath.Base(filepath.Dir(p))
			c.expect(r+" "+goSDK, dirVersion, m.requires[goSDK])
			if !slices.Contains(c.p.Conformance.Columns["go"], dirVersion) {
				c.failf("drivers/go/%s is not a [conformance.columns] go version", dirVersion)
			}
		}
	}
}

// goVersionDirRe matches the go.mod of a drivers/go/<version> directory.
var goVersionDirRe = regexp.MustCompile(`^drivers/go/v[0-9][^/]*/go\.mod$`)

// ---- Cargo.lock ----

type cargoPackage struct {
	name, version string
	member        bool // a workspace member (no source)
	deps          []string
}

func readCargoLock(path string) ([]cargoPackage, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lock struct {
		Package []struct {
			Name         string   `toml:"name"`
			Version      string   `toml:"version"`
			Source       string   `toml:"source"`
			Dependencies []string `toml:"dependencies"`
		} `toml:"package"`
	}
	if _, err := toml.Decode(string(data), &lock); err != nil {
		return nil, err
	}
	out := make([]cargoPackage, len(lock.Package))
	for i, p := range lock.Package {
		out[i] = cargoPackage{name: p.Name, version: p.Version, member: p.Source == "", deps: p.Dependencies}
	}
	return out, nil
}

// semverCore drops build metadata (0.9.34+deprecated is 0.9.34).
func semverCore(v string) string {
	if i := strings.IndexByte(v, '+'); i >= 0 {
		return v[:i]
	}
	return v
}

// checkCargoLock checks that every workspace member's dependency on a pinned crate resolves to an allowed
// version, and that each pinned crate is present at its pinned version.
func (c *pinsChecker) checkCargoLock(path string, pinned map[string][]string) {
	pkgs, err := readCargoLock(path)
	r := c.rel(path)
	if err != nil {
		c.failf("%s: %v", r, err)
		return
	}
	versions := map[string][]string{}
	for _, p := range pkgs {
		versions[p.name] = append(versions[p.name], semverCore(p.version))
	}
	names := make([]string, 0, len(pinned))
	for n := range pinned {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, want := range pinned[name] {
			c.checks++
			if !slices.Contains(versions[name], want) {
				c.drifts++
				fmt.Fprintf(c.out, "FAIL %s: %s %s (pins.toml) is not in the lock file (has %v)\n", r, name, want, versions[name])
			}
		}
	}
	for _, p := range pkgs {
		if !p.member {
			continue
		}
		for _, d := range p.deps {
			f := strings.Fields(d)
			allowed, ok := pinned[f[0]]
			if !ok {
				continue
			}
			v := ""
			if len(f) >= 2 {
				v = semverCore(f[1])
			} else if len(versions[f[0]]) == 1 {
				v = versions[f[0]][0]
			}
			c.checks++
			if !slices.Contains(allowed, v) {
				c.drifts++
				fmt.Fprintf(c.out, "FAIL %s: %s depends on %s %s, pins.toml allows %v\n", r, p.name, f[0], v, allowed)
			}
		}
	}
}

func (c *pinsChecker) cargoLocks() {
	rp := c.p.Rust
	root := map[string][]string{
		"stellar-xdr":      {rp.StellarXDR},
		"stellar-strkey":   {rp.StellarStrkey},
		"soroban-env-host": {rp.SorobanEnvHost, rp.SorobanEnvHostP29},
		"jsonschema":       {rp.Jsonschema},
		"serde_yaml":       {rp.SerdeYAML},
		"ed25519-dalek":    {rp.Ed25519Dalek},
		"libc":             {rp.Libc},
	}
	if _, err := os.Stat(filepath.Join(c.root, "Cargo.lock")); err == nil {
		c.checkCargoLock(filepath.Join(c.root, "Cargo.lock"), root)
	}
	if _, err := os.Stat(filepath.Join(c.root, "contracts", "Cargo.lock")); err == nil {
		c.checkCargoLock(filepath.Join(c.root, "contracts", "Cargo.lock"), map[string][]string{"soroban-sdk": {rp.SorobanSDK}})
	}
	locks, _ := filepath.Glob(filepath.Join(c.root, "drivers", "rust", "*", "Cargo.lock"))
	for _, l := range locks {
		v := filepath.Base(filepath.Dir(l))
		if !slices.Contains(c.p.Conformance.Columns["rust"], v) {
			c.failf("drivers/rust/%s is not a [conformance.columns] rust version", v)
		}
		c.checkCargoLock(l, map[string][]string{"stellar-xdr": {v}})
	}
}

// ---- package-lock.json ----

func (c *pinsChecker) jsLocks() {
	locks, _ := filepath.Glob(filepath.Join(c.root, "drivers", "js", "*", "package-lock.json"))
	for _, l := range locks {
		v := filepath.Base(filepath.Dir(l))
		r := c.rel(l)
		if !slices.Contains(c.p.Conformance.Columns["js"], v) {
			c.failf("drivers/js/%s is not a [conformance.columns] js version", v)
		}
		data, err := os.ReadFile(l)
		if err != nil {
			c.failf("%s: %v", r, err)
			continue
		}
		var lock struct {
			Packages map[string]struct {
				Version string `json:"version"`
			} `json:"packages"`
		}
		if err := json.Unmarshal(data, &lock); err != nil {
			c.failf("%s: %v", r, err)
			continue
		}
		c.expect(r+" @stellar/stellar-sdk", v, lock.Packages["node_modules/@stellar/stellar-sdk"].Version)
	}
}

// ---- drivers/sets.toml ----

func (c *pinsChecker) columnSets() {
	path := filepath.Join(c.root, "drivers", "sets.toml")
	if _, err := os.Stat(path); err != nil {
		return
	}
	c.checks++
	s, err := conform.LoadSets(path, c.root)
	if err == nil {
		err = s.CheckPins(c.p)
	}
	if err != nil {
		c.drifts++
		fmt.Fprintf(c.out, "FAIL drivers/sets.toml: %v\n", err)
	}
}

// ---- digests and download hashes ----

var (
	imageDigest = regexp.MustCompile(`^[^@\s]+@sha256:[0-9a-f]{64}$`)
	sha256Hex   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func (c *pinsChecker) digests() {
	images := map[string]string{"stellar_core.image": c.p.StellarCore.Image, "stellar_core.test_image": c.p.StellarCore.TestImage}
	for k, v := range c.p.Images {
		images["images."+k] = v
	}
	keys := make([]string, 0, len(images))
	for k := range images {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		c.checks++
		if !imageDigest.MatchString(images[k]) {
			c.drifts++
			fmt.Fprintf(c.out, "FAIL pins.toml %s = %q is not an image reference pinned by sha256 digest\n", k, images[k])
		}
	}
	hashes := map[string]string{"stellar_core.deb_sha256": c.p.StellarCore.DebSHA256, "stellar_core.binary_sha256": c.p.StellarCore.BinarySHA256}
	for name, d := range runtimeDebs(c.p) {
		hashes["stellar_core.runtime_debs."+name] = d.SHA256
	}
	keys = keys[:0]
	for k := range hashes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		c.checks++
		if !sha256Hex.MatchString(hashes[k]) {
			c.drifts++
			fmt.Fprintf(c.out, "FAIL pins.toml %s = %q is not a sha256\n", k, hashes[k])
		}
	}
}

// ---- versions named outside pins.toml ----

var versionLike = regexp.MustCompile(`v?([0-9]+\.[0-9]+\.[0-9]+)`)

// versionStrings checks the workflows, the scripts and the Makefiles: every x.y.z that is not part of a word or
// a longer dotted number (an address such as 1.1.1.1) must appear in pins.toml.
func (c *pinsChecker) versionStrings() {
	var files []string
	add := func(pattern string) {
		m, _ := filepath.Glob(filepath.Join(c.root, pattern))
		files = append(files, m...)
	}
	add(".github/workflows/*.yml")
	add(".github/workflows/*.yaml")
	add(".github/actions/*/action.yml")
	add("Makefile")
	add("drivers/*/Makefile")
	add("drivers/*/*/Makefile")
	add("drivers/*/*.mk")
	filepath.WalkDir(filepath.Join(c.root, "scripts"), func(p string, e fs.DirEntry, err error) error {
		if err == nil && !e.IsDir() && strings.HasSuffix(p, ".sh") {
			files = append(files, p)
		}
		return nil
	})
	sort.Strings(files)
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		r := c.rel(f)
		for n, line := range strings.Split(string(data), "\n") {
			if strings.Contains(line, "uses:") {
				// Actions are pinned by commit with their version in a trailing comment (checked by the workflow
				// check); the comment's version is not a pins.toml value.
				if i := strings.Index(line, "#"); i >= 0 {
					line = line[:i]
				}
			}
			for _, m := range versionLike.FindAllStringSubmatchIndex(line, -1) {
				if partOfLongerToken(line, m[0], m[1]) {
					continue
				}
				v := line[m[2]:m[3]]
				c.checks++
				if !strings.Contains(c.pinsText, v) {
					c.drifts++
					fmt.Fprintf(c.out, "FAIL %s:%d names version %s, which is not in pins.toml\n", r, n+1, line[m[0]:m[1]])
				}
			}
		}
	}
}

// ---- versions compiled into the kit's own code ----

// codeConstants are the pinned values the kit's code carries as literals: the oracle crate version it reports,
// the highest protocol its gates, generator and drivers accept. Each site is a file and a pattern whose one
// group must equal the pin; a file that is gone or no longer matches is a drift too, so a renamed constant
// cannot drop out of the check. The drivers' constants also carry a `pin:<key>` marker (see codeMarkers).
//
// Generating these from pins.toml at build time was the alternative. It was not taken: the drivers are five
// languages with no shared build step, the crates are also built from the release archive and by cargo alone,
// and a raised protocol constant is not enough by itself: each site needs new probes, settings or decoding
// before the new value is true. A check that names every site makes the pin move fail until each is updated.
var codeConstants = []struct{ file, pattern, pin string }{
	{"crates/xdrcheck-xdr/src/ledger.rs", `pub const DEFAULT_MAX_PROTOCOL: u32 = (\d+);`, "protocol.max_supported"},
	{"corpus/corpus.json", `"max_protocol": (\d+)`, "protocol.max_supported"},
	{"crates/xdrcheck-corpus/src/cmd/verify/report.rs", `let oracle_version = "([^"]+)";`, "rust.stellar_xdr"},
	{"crates/xdrcheck-gen/src/output/sidecar.rs", `pin\("/pins/oracle/version", "([^"]+)"\)`, "rust.stellar_xdr"},
	{"crates/xdrcheck-gen/src/soroban/sim.rs", `SIMULATION_PROTOCOLS: std::ops::RangeInclusive<u32> = \d+..=(\d+);`, "protocol.max_supported"},
	{"crates/xdrcheck-gen/src/upgrade.rs", `\(21\.\.=(\d+)\)\.contains\(&protocol\)`, "protocol.max_supported"},
	{"go/adapters/baseline/indexer/run.go", `DefaultGates = Gates\{MaxProtocol: (\d+),`, "protocol.max_supported"},
	{"drivers/core/main.go", markerPattern, "protocol.max_supported"},
	{"drivers/go/driver/decode.go", markerPattern, "protocol.max_supported"},
	{"drivers/js/src/reach.mjs", markerPattern, "protocol.max_supported"},
	{"drivers/js16/src/reach.mjs", markerPattern, "protocol.max_supported"},
	{"drivers/python/src/xdrcheck_driver/reach.py", markerPattern, "protocol.max_supported"},
	{"drivers/rust/src/reach.rs", markerPattern, "protocol.max_supported"},
	{"drivers/stub/main.go", markerPattern, "protocol.max_supported"},
}

// markerPattern finds a protocol constant marked `pin:protocol.max_supported`.
const markerPattern = `(?m)=\s*(\d+);?\s*(?://|#)\s*pin:protocol\.max_supported\s*$`

// markerRE is a `pin:<key>` marker in a comment; the first number or version on the code before the comment is
// the marked value.
var (
	markerRE  = regexp.MustCompile(`(//|#)\s*pin:([a-z_]+\.[a-z_]+)\b`)
	literalRE = regexp.MustCompile(`\b\d+(?:\.\d+\.\d+)?\b`)
)

// pinValue is the pins.toml value of a dotted key a constant may encode.
func (c *pinsChecker) pinValue(key string) (string, bool) {
	switch key {
	case "protocol.max_supported":
		return fmt.Sprint(c.p.Protocol.MaxSupported), true
	case "rust.stellar_xdr":
		return c.p.Rust.StellarXDR, true
	case "stellar_core.version":
		return c.p.StellarCore.Version, true
	}
	return "", false
}

func (c *pinsChecker) codeConstants() {
	for _, k := range codeConstants {
		want, _ := c.pinValue(k.pin)
		data, err := os.ReadFile(filepath.Join(c.root, k.file))
		if err != nil {
			c.failf("%s: %v (it carries pins.toml %s)", k.file, err, k.pin)
			continue
		}
		m := regexp.MustCompile(k.pattern).FindSubmatch(data)
		if m == nil {
			c.failf("%s: no constant matching %s (it carries pins.toml %s); update the site list in go/cmd/xdrcheck/pins.go", k.file, k.pattern, k.pin)
			continue
		}
		c.expect(k.file+" "+k.pin, want, string(m[1]))
	}
	c.codeMarkers()
}

// codeMarkers checks every `pin:<key>` marker in the kit's source, so a constant marked after the site list
// was written is checked too.
func (c *pinsChecker) codeMarkers() {
	skip := map[string]bool{".git": true, "node_modules": true, "target": true, "bin": true, "classes": true,
		"test-classes": true, "lib": true, "testdata": true, ".venv": true, "evidence": true, "references": true}
	exts := map[string]bool{".go": true, ".rs": true, ".mjs": true, ".js": true, ".py": true, ".java": true}
	for _, dir := range []string{"crates", "drivers", "go", "lint"} {
		filepath.WalkDir(filepath.Join(c.root, dir), func(p string, e fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if e.IsDir() {
				if skip[e.Name()] {
					return filepath.SkipDir
				}
				return nil
			}
			if !exts[filepath.Ext(p)] || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			data, err := os.ReadFile(p)
			if err != nil || !strings.Contains(string(data), "pin:") {
				return nil
			}
			for n, line := range strings.Split(string(data), "\n") {
				m := markerRE.FindStringSubmatchIndex(line)
				if m == nil {
					continue
				}
				key := line[m[4]:m[5]]
				where := fmt.Sprintf("%s:%d", c.rel(p), n+1)
				want, ok := c.pinValue(key)
				if !ok {
					c.failf("%s: marker pin:%s names no pin the check knows", where, key)
					continue
				}
				c.expect(where+" pin:"+key, want, literalRE.FindString(line[:m[0]]))
			}
			return nil
		})
	}
}

func isWord(b byte) bool {
	return b == '_' || isDigit(b) || b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z'
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

// partOfLongerToken reports whether line[start:end] continues a word or a longer dotted number (1.1.1.1). A
// file suffix after the version (tool-1.2.3.tar.gz) does not make it part of a longer token.
func partOfLongerToken(line string, start, end int) bool {
	if start > 0 {
		b := line[start-1]
		if isWord(b) || b == '.' && start > 1 && isDigit(line[start-2]) {
			return true
		}
	}
	if end < len(line) {
		b := line[end]
		if isWord(b) || b == '.' && end+1 < len(line) && isDigit(line[end+1]) {
			return true
		}
	}
	return false
}

// ---- in use: this binary and the fetched caches ----

func (c *pinsChecker) binary() {
	read := c.buildInfo
	if read == nil {
		read = debug.ReadBuildInfo
	}
	bi, ok := read()
	if !ok {
		c.infof("no build information in this binary; its toolchain is not checked")
		return
	}
	c.expect("Go toolchain this xdrcheck was built with", "go"+c.p.Go.Toolchain, bi.GoVersion)
	for _, d := range bi.Deps {
		v := d.Version
		if d.Replace != nil {
			v = d.Replace.Version
		}
		switch d.Path {
		case goSDK:
			c.expect("module "+goSDK+" in this xdrcheck", c.p.Go.GoStellarSDK, v)
		case "github.com/BurntSushi/toml":
			c.expect("module github.com/BurntSushi/toml in this xdrcheck", c.p.Go.TOML, v)
		}
	}
}

// runtimeDebs are the [stellar_core.runtime_debs] entries that are packages: the table also holds
// llvm_base_url, which the fetch script reads from there.
func runtimeDebs(p *pins.Pins) map[string]pins.RuntimeDeb {
	out := map[string]pins.RuntimeDeb{}
	for name, d := range p.StellarCore.RuntimeDebs {
		if strings.HasSuffix(name, ".deb") {
			out[name] = d
		}
	}
	return out
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (c *pinsChecker) cacheBase() string {
	if c.cacheDir != "" {
		return c.cacheDir
	}
	if b := os.Getenv("XDRCHECK_CACHE"); b != "" {
		return b
	}
	if d, ok := userdir.HomeCache(); ok {
		return d
	}
	return ""
}

func (c *pinsChecker) caches() {
	base := c.cacheBase()
	if base == "" {
		c.infof("no cache directory; caches are not checked")
		return
	}
	sc := c.p.StellarCore
	core := filepath.Join(base, "stellar-core", sc.Version)
	if _, err := os.Stat(core); err != nil {
		c.infof("stellar-core %s has not been fetched; its cache is not checked", sc.Version)
	} else {
		want := map[string]string{filepath.Base(sc.DebURL): sc.DebSHA256}
		for name, d := range runtimeDebs(c.p) {
			want[name] = d.SHA256
		}
		names := make([]string, 0, len(want))
		for n := range want {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			got, err := fileSHA256(filepath.Join(core, "dl", n))
			if errors.Is(err, fs.ErrNotExist) {
				c.infof("stellar-core cache: %s not downloaded", n)
				continue
			}
			c.expect("cached download stellar-core/"+sc.Version+"/dl/"+n+" sha256", want[n], got)
		}
		bin := filepath.Join(core, "pkg", "usr", "bin", "stellar-core")
		if got, err := fileSHA256(bin); err == nil {
			c.expect("cached binary stellar-core/"+sc.Version+"/pkg/usr/bin/stellar-core sha256", sc.BinarySHA256, got)
		} else {
			c.infof("stellar-core cache: the binary is not extracted")
		}
	}
	c.driverCaches(base)
}

// driverCaches compares each conformance driver directory's cache stamp with the lock it was filled from: a
// JavaScript cache records the sha256 of its package-lock.json, a Go cache the SDK version it fetched.
func (c *pinsChecker) driverCaches(base string) {
	path := filepath.Join(c.root, "drivers", "sets.toml")
	s, err := conform.LoadSets(path, c.root)
	if err != nil {
		return // reported by columnSets
	}
	seen := map[string]bool{}
	ids := make([]string, 0, len(s.Columns))
	for id := range s.Columns {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	unfetched := 0
	for _, id := range ids {
		col := s.Columns[id]
		if seen[col.Dir] {
			continue
		}
		seen[col.Dir] = true
		dir := filepath.Join(base, "conform", strings.ReplaceAll(filepath.ToSlash(filepath.Clean(col.Dir)), "/", "-"))
		stamp, err := os.ReadFile(filepath.Join(dir, "fetched"))
		if err != nil {
			unfetched++
			continue
		}
		got := strings.TrimSpace(string(stamp))
		switch col.SDK {
		case "js":
			want, err := fileSHA256(filepath.Join(c.root, col.Dir, "package-lock.json"))
			if err == nil {
				c.expect("cache of "+col.Dir+" (filled from package-lock.json sha256)", want, got)
			}
		case "go":
			c.expect("cache of "+col.Dir+" (fetched SDK)", "go-stellar-sdk "+col.Version, got)
		}
	}
	if unfetched > 0 {
		c.infof("%d conformance driver director(ies) have not been fetched; their caches are not checked", unfetched)
	}
}

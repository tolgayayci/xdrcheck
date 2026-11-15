package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tolgayayci/xdrcheck/go/internal/pins"
)

// watchPins is a pins file with two schedule events: a mainnet vote on 2026-11-23 and a testnet reset on
// 2026-12-16, each with the pin it moves.
const watchPins = `
[protocol]
max_supported = 30
network_mainnet = 29
network_testnet = 30

[[schedule]]
event = "Mainnet vote"
date = "2026-11-23"
source = "status page"
pin = "protocol.network_mainnet"
until = "29"
action = "set protocol.network_mainnet"

[[schedule]]
event = "Testnet reset"
date = "2026-12-16"
source = "docs"
pin = "public_lake.testnet"
until = "testnet/2025-12-18"
action = "move public_lake.testnet"

[stellar_core]
[stellar_xdr_definitions]
[rust]
[go]
[js]
[python]
[java]
[images]
[services]
[pipelines]
[docs]
[conformance]
[public_lake]
testnet = "testnet/2025-12-18"
`

func watchChecker(t *testing.T, text, today string) (*pinsChecker, *bytes.Buffer) {
	t.Helper()
	p, err := pins.Parse([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	day, err := time.Parse(pins.DateLayout, today)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	return &pinsChecker{root: t.TempDir(), p: p, out: &out, today: day}, &out
}

// The schedule turns from info to a warning 14 days ahead and to a failure, with the action, once the day has
// passed and the pin has not moved; a moved pin is only reported.
func TestPinsScheduleDates(t *testing.T) {
	for _, tc := range []struct {
		today         string
		drifts, warns int
		want, wantNot string
	}{
		{"2026-11-01", 0, 0, "info schedule: Mainnet vote in 22 day(s)", "FAIL"},
		{"2026-11-14", 0, 1, "warn schedule: Mainnet vote in 9 day(s), on 2026-11-23; afterwards: set protocol.network_mainnet", "FAIL"},
		{"2026-11-23", 0, 1, "warn schedule: Mainnet vote is today", "FAIL"},
		{"2026-11-24", 1, 0, "FAIL schedule: Mainnet vote was on 2026-11-23 (1 day(s) ago) and protocol.network_mainnet still is 29: set protocol.network_mainnet (source: status page)", ""},
		{"2026-12-17", 2, 0, "FAIL schedule: Testnet reset was on 2026-12-16 (1 day(s) ago) and public_lake.testnet still is testnet/2025-12-18: move public_lake.testnet", ""},
	} {
		c, out := watchChecker(t, watchPins, tc.today)
		c.schedule()
		if c.drifts != tc.drifts || c.warnings != tc.warns || !strings.Contains(out.String(), tc.want) ||
			(tc.wantNot != "" && strings.Contains(out.String(), tc.wantNot)) {
			t.Errorf("%s: %d drift(s), %d warning(s), want %d and %d with %q:\n%s", tc.today, c.drifts, c.warnings, tc.drifts, tc.warns, tc.want, out)
		}
	}
	moved := strings.Replace(watchPins, "network_mainnet = 29", "network_mainnet = 30", 1)
	c, out := watchChecker(t, moved, "2026-11-30")
	c.schedule()
	if c.drifts != 0 || !strings.Contains(out.String(), "protocol.network_mainnet is 30, no longer 29; remove the event") {
		t.Errorf("moved pin: %d drift(s):\n%s", c.drifts, out)
	}
	// A malformed event is refused when the pins file is read.
	for _, bad := range []string{`date = "2026-11-23"`, `pin = "protocol.network_mainnet"`} {
		repl := map[string]string{`date = "2026-11-23"`: `date = "23 Nov"`, `pin = "protocol.network_mainnet"`: `pin = "go.toml"`}[bad]
		if _, err := pins.Parse([]byte(strings.Replace(watchPins, bad, repl, 1))); err == nil {
			t.Errorf("%s accepted", repl)
		}
	}
}

// fakeNetworks serves Horizon roots and a status page with the given state.
func fakeNetworks(t *testing.T, mainnet, testnet [2]int, testnetLatest int64, maintenances string) *watchSources {
	t.Helper()
	root := func(cur, sup int, pass string, latest int64) string {
		return fmt.Sprintf(`{"current_protocol_version": %d, "core_supported_protocol_version": %d, "core_latest_ledger": %d, "core_version": "stellar-core test", "network_passphrase": %q}`, cur, sup, latest, pass)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/mainnet/", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, root(mainnet[0], mainnet[1], networkPassphrases["mainnet"], 60000000))
	})
	mux.HandleFunc("/testnet/", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, root(testnet[0], testnet[1], networkPassphrases["testnet"], testnetLatest))
	})
	mux.HandleFunc("/status.json", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"scheduled_maintenances": [%s]}`, maintenances)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &watchSources{
		horizon: map[string]string{"mainnet": srv.URL + "/mainnet/", "testnet": srv.URL + "/testnet/"},
		status:  srv.URL + "/status.json",
		client:  srv.Client(),
	}
}

// vendorTestnet writes a capture record of the pinned testnet epoch at ledger seq under root.
func vendorTestnet(t *testing.T, root string, seq int) {
	t.Helper()
	dir := filepath.Join(root, "corpus", "objects", "testnet", fmt.Sprint(seq))
	os.MkdirAll(dir, 0o755)
	rec := fmt.Sprintf(`{"store": "s3://bucket/v1.1/stellar/ledgers/testnet/2025-12-18", "ledger_seq": %d}`, seq)
	if err := os.WriteFile(filepath.Join(dir, "capture.json"), []byte(rec), 0o644); err != nil {
		t.Fatal(err)
	}
}

const voteMaintenance = `{"name": "Stellar Public Network Protocol Upgrade Vote", "scheduled_for": "2026-11-23T17:00:00.000Z", "shortlink": "https://example.invalid/vote"}`

// The network check: matching state passes; a stale network pin warns; a network above max_supported fails;
// a reset testnet fails; a status-page event missing from the schedule warns; a source that cannot be read
// fails.
func TestPinsNetworkState(t *testing.T) {
	run := func(src *watchSources, today string) (*pinsChecker, string) {
		c, out := watchChecker(t, watchPins, today)
		vendorTestnet(t, c.root, 5000000)
		c.sources = src
		c.network()
		return c, out.String()
	}
	c, out := run(fakeNetworks(t, [2]int{29, 30}, [2]int{30, 30}, 5700000, voteMaintenance), "2026-11-14")
	if c.drifts != 0 || c.warnings != 0 || !strings.Contains(out, "validators are ready for protocol 30") ||
		!strings.Contains(out, "no reset since") || !strings.Contains(out, "is a [[schedule]] event") {
		t.Errorf("agreeing state: %d drift(s), %d warning(s):\n%s", c.drifts, c.warnings, out)
	}

	c, out = run(fakeNetworks(t, [2]int{30, 30}, [2]int{30, 30}, 5700000, voteMaintenance), "2026-11-24")
	if c.drifts != 0 || !strings.Contains(out, "warn network mainnet runs protocol 30, pins.toml protocol.network_mainnet is 29") {
		t.Errorf("stale mainnet pin: %d drift(s):\n%s", c.drifts, out)
	}

	c, out = run(fakeNetworks(t, [2]int{31, 31}, [2]int{31, 32}, 120, `{"name": "Testnet Reset", "scheduled_for": "2027-03-17T17:00:00Z", "shortlink": "x"}`), "2026-12-14")
	for _, want := range []string{
		"FAIL network mainnet runs protocol 31, above protocol.max_supported 30",
		"FAIL network testnet runs protocol 31",
		"warn network testnet: validators run a core that supports protocol 32",
		"FAIL network testnet: latest ledger 120 is below ledger 5000000 vendored from epoch testnet/2025-12-18: testnet has been reset",
		`warn status page announces "Testnet Reset" on 2027-03-17T17:00:00Z (x), which is not a pins.toml [[schedule]] event`,
		"warn schedule: Testnet reset on 2026-12-16 is 2 day(s) away and not on the status page",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("network ahead of the pins: missing %q in:\n%s", want, out)
		}
	}
	if c.drifts != 3 {
		t.Errorf("network ahead of the pins: %d drift(s), want 3", c.drifts)
	}

	dead := fakeNetworks(t, [2]int{29, 30}, [2]int{30, 30}, 5700000, voteMaintenance)
	dead.status += ".missing"
	dead.horizon["testnet"] = "http://127.0.0.1:1/"
	c, out = run(dead, "2026-11-14")
	if c.drifts != 2 || !strings.Contains(out, "FAIL network testnet: Horizon root not read") || !strings.Contains(out, "FAIL network: status page not read") {
		t.Errorf("unreadable sources: %d drift(s):\n%s", c.drifts, out)
	}
}

// The repository's own schedule parses and every event names a pin.
func TestPinsScheduleRepository(t *testing.T) {
	p, err := pins.Load(filepath.Join(repoAbs, "pins.toml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range p.Schedule {
		if _, ok := p.Value(e.Pin); !ok {
			t.Errorf("%s: pin %s", e.Event, e.Pin)
		}
	}
}

// pins latest against fake registries: a pin behind the newest version is BEHIND and exits 1; an unreadable
// registry exits 2; the JSON rows carry both versions.
func TestPinsLatest(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/npm/@stellar/stellar-sdk/latest", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, `{"version": "17.5.0"}`) })
	mux.HandleFunc("/pypi/pypi/stellar-sdk/json", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, `{"info": {"version": "17.0.1"}}`) })
	mux.HandleFunc("/go/github.com/stellar/go-stellar-sdk/@latest", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, `{"Version": "v0.9.0"}`) })
	mux.HandleFunc("/crates/api/v1/crates/soroban-sdk", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"crate": {"max_stable_version": "30.0.0", "max_version": "31.0.0-rc.1"}}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	reg := &pins.Registries{NPM: srv.URL + "/npm", PyPI: srv.URL + "/pypi", GoProxy: srv.URL + "/go", Crates: srv.URL + "/crates",
		Client: srv.Client(), Tags: func(_ context.Context, repo string) ([]string, error) {
			return []string{"v29.0.0", "v30.0.0", "v30.0.1rc1", "v30.1.0-rc.1", "v9.2.0rc6"}, nil
		}}
	text := `[stellar_core]
# renovate: datasource=github-tags depName=stellar/stellar-core extractVersion=^v(?<version>\d+\.\d+\.\d+)$
version = "30.0.0"
[rust]
# renovate: datasource=crate depName=soroban-sdk
soroban_sdk = "30.0.0-rc.1"   # a release candidate is behind its release
[go]
# renovate: datasource=go depName=github.com/stellar/go-stellar-sdk
go_stellar_sdk = "v0.9.0"
[js]
# renovate: datasource=npm depName=@stellar/stellar-sdk
stellar_sdk = "17.4.0"
[python]
# renovate: datasource=pypi depName=stellar-sdk
stellar_sdk = "17.0.1"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "pins.toml")
	os.WriteFile(path, []byte(text), 0o644)
	var stdout, stderr bytes.Buffer
	code := pinsLatestMain([]string{"--pins", path, "--json", filepath.Join(dir, "latest.json")}, &stdout, &stderr, reg)
	out := stdout.String()
	for _, want := range []string{
		"current stellar_core.version",
		"BEHIND  rust.soroban_sdk                     30.0.0-rc.1      -> 30.0.0",
		"current go.go_stellar_sdk",
		"BEHIND  js.stellar_sdk                       17.4.0           -> 17.5.0",
		"pins latest: 5 tracked pins, 2 behind, 0 lookup(s) failed",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s%s", want, out, stderr.String())
		}
	}
	if code != 1 {
		t.Errorf("exit %d, want 1", code)
	}
	data, _ := os.ReadFile(filepath.Join(dir, "latest.json"))
	if !strings.Contains(string(data), `"latest": "17.5.0"`) || !strings.Contains(string(data), `"key": "js.stellar_sdk"`) {
		t.Errorf("json rows:\n%s", data)
	}
	reg.NPM = srv.URL + "/gone"
	stdout.Reset()
	if code := pinsLatestMain([]string{"--pins", path}, &stdout, &stderr, reg); code != 2 || !strings.Contains(stdout.String(), "ERROR   js.stellar_sdk") {
		t.Errorf("unreadable registry: exit %d:\n%s", code, stdout.String())
	}
}

// Package pins reads pins.toml, the single source of every external version the kit builds against or tests
// , into typed structs.
//
// Decoding is strict: a key the structs do not know is an error, and every top-level section must be present,
// so a pins file and the code that reads it cannot drift apart silently.
package pins

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// Pins is the whole pins file.
type Pins struct {
	CI                    CI                    `toml:"ci"`
	Protocol              Protocol              `toml:"protocol"`
	StellarCore           StellarCore           `toml:"stellar_core"`
	StellarXDRDefinitions StellarXDRDefinitions `toml:"stellar_xdr_definitions"`
	Rust                  Rust                  `toml:"rust"`
	Go                    Go                    `toml:"go"`
	JS                    JS                    `toml:"js"`
	Python                Python                `toml:"python"`
	Java                  Java                  `toml:"java"`
	Images                map[string]string     `toml:"images"`   // name -> image reference with digest
	Services              map[string]string     `toml:"services"` // name -> version
	Pipelines             Pipelines             `toml:"pipelines"`
	Docs                  Docs                  `toml:"docs"`
	Conformance           Conformance           `toml:"conformance"`
	PublicLake            PublicLake            `toml:"public_lake"`
	// Schedule lists the dated network changes the pins depend on ([[schedule]]); may be empty.
	Schedule []Event `toml:"schedule"`

	// FileSHA256 is the sha256 of the file's bytes (report header pins.file_sha256). Path is where it was read.
	FileSHA256 string `toml:"-"`
	Path       string `toml:"-"`
}

// Protocol is the protocol gate and the networks' protocols on the pin date.
type Protocol struct {
	MaxSupported   int `toml:"max_supported"`
	NetworkMainnet int `toml:"network_mainnet"`
	NetworkTestnet int `toml:"network_testnet"`
}

// StellarCore is the pinned stellar-core release.
type StellarCore struct {
	Version      string                `toml:"version"`
	Commit       string                `toml:"commit"`
	DebURL       string                `toml:"deb_url"`
	DebSHA256    string                `toml:"deb_sha256"`
	BinarySHA256 string                `toml:"binary_sha256"`
	Image        string                `toml:"image"`
	TestImage    string                `toml:"test_image"`
	GoldenTiers  []string              `toml:"golden_tiers"`
	RuntimeDebs  map[string]RuntimeDeb `toml:"runtime_debs"` // file name -> sha256, or {url, sha256}
	LLVMBaseURL  string                `toml:"llvm_base_url"`
}

// RuntimeDeb is one runtime library package: either a bare sha256 (fetched from llvm_base_url, else
// llvm_fallback_base_url) or a table with its own url and an optional fallback_url.
type RuntimeDeb struct {
	URL         string
	FallbackURL string
	SHA256      string
}

// UnmarshalTOML accepts both forms.
func (d *RuntimeDeb) UnmarshalTOML(v any) error {
	switch t := v.(type) {
	case string:
		d.SHA256 = t
		return nil
	case map[string]any:
		for k, val := range t {
			s, ok := val.(string)
			if !ok {
				return fmt.Errorf("runtime_debs: %s must be a string", k)
			}
			switch k {
			case "url":
				d.URL = s
			case "fallback_url":
				d.FallbackURL = s
			case "sha256":
				d.SHA256 = s
			default:
				return fmt.Errorf("runtime_debs: unknown key %q", k)
			}
		}
		if d.SHA256 == "" {
			return fmt.Errorf("runtime_debs: sha256 missing")
		}
		return nil
	}
	return fmt.Errorf("runtime_debs: unexpected value %T", v)
}

// CI holds the versions of tools only CI installs.
type CI struct {
	Mise       string `toml:"mise"`
	Actionlint string `toml:"actionlint"`
}

// StellarXDRDefinitions is the pinned XDR definitions tag.
type StellarXDRDefinitions struct {
	Tag    string `toml:"tag"`
	Commit string `toml:"commit"`
}

// Rust holds the Rust toolchain and crate pins.
type Rust struct {
	Toolchain      string `toml:"toolchain"`
	StellarXDR     string `toml:"stellar_xdr"`
	StellarStrkey  string `toml:"stellar_strkey"`
	SorobanEnvHost string `toml:"soroban_env_host"`
	// SorobanEnvHostP29 is the host the generator simulates Protocol 29 ledgers with.
	SorobanEnvHostP29 string `toml:"soroban_env_host_p29"`
	SorobanSDK        string `toml:"soroban_sdk"`
	Jsonschema        string `toml:"jsonschema"`
	SerdeYAML         string `toml:"serde_yaml"`
	Ed25519Dalek      string `toml:"ed25519_dalek"`
	Libc              string `toml:"libc"`
}

// Go holds the Go toolchain and module pins.
type Go struct {
	Toolchain    string `toml:"toolchain"`
	GoStellarSDK string `toml:"go_stellar_sdk"`
	XTools       string `toml:"x_tools"`
	GolangciLint string `toml:"golangci_lint"`
	TOML         string `toml:"toml"`
	// FakeGCSServer is the GCS emulator the stellar-etl adapter serves its input through.
	FakeGCSServer string `toml:"fake_gcs_server"`
}

// JS holds the Node and JS SDK pins.
type JS struct {
	Node       string `toml:"node"`
	StellarSDK string `toml:"stellar_sdk"`
}

// Python holds the Python and Python SDK pins.
type Python struct {
	Version    string `toml:"version"`
	StellarSDK string `toml:"stellar_sdk"`
}

// Java holds the JDK pin.
type Java struct {
	JDK string `toml:"jdk"`
}

// Pipelines are the indexing pipelines under test.
type Pipelines struct {
	WalletBackend WalletBackend `toml:"wallet_backend"`
	StellarETL    StellarETL    `toml:"stellar_etl"`
}

// WalletBackend pins wallet-backend: the current commit and the pre-fix/fixed pairs of the acceptance checks.
type WalletBackend struct {
	Repo                               string       `toml:"repo"`
	Current                            string       `toml:"current"`
	GoToolchain                        string       `toml:"go_toolchain"`
	MaxDecodableProtocolBeforeA9bac8d2 int          `toml:"max_decodable_protocol_before_a9bac8d2"`
	Acceptance                         []BugCommits `toml:"acceptance"`
}

// BugCommits is one acceptance pair: the commit before the fix and the fixing commit.
type BugCommits struct {
	Bug    string `toml:"bug"`
	Prefix string `toml:"prefix"`
	Fixed  string `toml:"fixed"`
}

// StellarETL pins stellar-etl.
type StellarETL struct {
	Repo        string `toml:"repo"`
	Tag         string `toml:"tag"`
	Commit      string `toml:"commit"`
	GoToolchain string `toml:"go_toolchain"`
}

// Docs pins the documentation repository.
type Docs struct {
	Repo   string `toml:"repo"`
	Commit string `toml:"commit"`
}

// Conformance lists the SDK versions allowed as conformance columns, by language.
type Conformance struct {
	Columns map[string][]string `toml:"columns"`
}

// PublicLake is the public SEP-54 data lake.
type PublicLake struct {
	Bucket  string `toml:"bucket"`
	Pubnet  string `toml:"pubnet"`
	Testnet string `toml:"testnet"`
}

// Event is one dated network change a pin depends on: a mainnet protocol vote or a testnet reset. On and
// after Date (UTC), Pin must no longer hold Until; Action says what to do when it still does.
type Event struct {
	Event  string `toml:"event"`  // what happens, for example "Mainnet vote on Protocol 30"
	Date   string `toml:"date"`   // YYYY-MM-DD (UTC) of the event
	Source string `toml:"source"` // where the date was read
	Pin    string `toml:"pin"`    // the dotted pins.toml key the event invalidates, for example protocol.network_mainnet
	Until  string `toml:"until"`  // the value Pin holds until the event
	Action string `toml:"action"` // what to do once the event has happened
}

// DateLayout is the layout of Event.Date.
const DateLayout = "2006-01-02"

// Day is the event's date at 00:00 UTC.
func (e Event) Day() (time.Time, error) {
	return time.ParseInLocation(DateLayout, e.Date, time.UTC)
}

// Value returns the scalar at a dotted key that a schedule event may name, as text.
func (p *Pins) Value(key string) (string, bool) {
	switch key {
	case "protocol.max_supported":
		return strconv.Itoa(p.Protocol.MaxSupported), true
	case "protocol.network_mainnet":
		return strconv.Itoa(p.Protocol.NetworkMainnet), true
	case "protocol.network_testnet":
		return strconv.Itoa(p.Protocol.NetworkTestnet), true
	case "public_lake.testnet":
		return p.PublicLake.Testnet, true
	case "public_lake.pubnet":
		return p.PublicLake.Pubnet, true
	case "stellar_core.version":
		return p.StellarCore.Version, true
	}
	return "", false
}

func (p *Pins) checkSchedule() error {
	for i, e := range p.Schedule {
		if e.Event == "" || e.Date == "" || e.Source == "" || e.Pin == "" || e.Until == "" || e.Action == "" {
			return fmt.Errorf("schedule[%d] %q: event, date, source, pin, until and action are all required", i, e.Event)
		}
		if _, err := e.Day(); err != nil {
			return fmt.Errorf("schedule[%d] %q: date %q is not YYYY-MM-DD", i, e.Event, e.Date)
		}
		if _, ok := p.Value(e.Pin); !ok {
			return fmt.Errorf("schedule[%d] %q: pin %q is not a key a schedule event can name", i, e.Event, e.Pin)
		}
	}
	return nil
}

var sections = []string{
	"protocol", "stellar_core", "stellar_xdr_definitions", "rust", "go", "js", "python", "java", "images",
	"services", "pipelines", "docs", "conformance", "public_lake",
}

// Load reads and parses the pins file at path.
func Load(path string) (*Pins, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	p.Path = path
	return p, nil
}

// Parse decodes pins.toml content strictly.
func Parse(data []byte) (*Pins, error) {
	var p Pins
	md, err := toml.Decode(string(data), &p)
	if err != nil {
		return nil, err
	}
	if und := md.Undecoded(); len(und) > 0 {
		keys := make([]string, len(und))
		for i, k := range und {
			keys[i] = k.String()
		}
		sort.Strings(keys)
		return nil, fmt.Errorf("unknown keys: %s", strings.Join(keys, ", "))
	}
	var missing []string
	for _, s := range sections {
		if !md.IsDefined(s) {
			missing = append(missing, s)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("missing sections: %s", strings.Join(missing, ", "))
	}
	if err := p.checkSchedule(); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	p.FileSHA256 = hex.EncodeToString(sum[:])
	return &p, nil
}

// AcceptancePair returns the wallet-backend acceptance pair for a bug number, or false.
func (w *WalletBackend) AcceptancePair(bug string) (BugCommits, bool) {
	for _, a := range w.Acceptance {
		if a.Bug == bug {
			return a, true
		}
	}
	return BugCommits{}, false
}

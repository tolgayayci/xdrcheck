package framework

// Configuration: `.xdrlint.yml`, shipped profiles, the overlay, and the
// external suppression files they name.
//
// Keys are flat and lower-case because golangci-lint passes plugin settings
// through Viper (lint/docs/README.md, section Configuration). A configuration is built from
// layers, later layers overriding earlier ones:
//
//	profile (-profile NAME|PATH)  →  project config (-config FILE, or
//	.xdrlint.yml found from the working directory up to the module root)  →
//	overlay (-overlay DIR, file DIR/xdrlint.yml)
//
// Merging: scalars are replaced by a later non-empty value; lists are
// appended (duplicates dropped), except `rules`, which a later layer
// replaces; maps are merged key by key. Each layer may name one
// `suppressions` file; all of them apply. A relative path inside a layer is
// resolved against the directory of that layer's file (for a shipped
// profile: inside the embedded profiles directory).

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/tolgayayci/xdrcheck/lint/profiles"
)

// Config holds every configuration key, merged over all layers.
type Config struct {
	Rules                []string            `yaml:"rules"`
	Severity             map[string]Severity `yaml:"severity"`
	XDRPackageAliases    []string            `yaml:"xdrpackagealiases"`
	ParticipantNameRegex string              `yaml:"participantnameregex"`
	SinksParticipant     []string            `yaml:"sinksparticipant"`
	SinksAccountKey      []string            `yaml:"sinksaccountkey"`
	SinksText            []string            `yaml:"sinkstext"`
	SanitizersAddress    []string            `yaml:"sanitizersaddress"`
	SanitizersText       []string            `yaml:"sanitizerstext"`
	BudgetMethods        []string            `yaml:"budgetmethods"`
	OverflowPolicy       string              `yaml:"overflowpolicy"`
	OverflowFlags        []string            `yaml:"overflowflags"`
	HaltingFuncs         []string            `yaml:"haltingfuncs"`
	IngestEntryPoints    []string            `yaml:"ingestentrypoints"`
	Floors               map[string]int      `yaml:"floors"`
	SinksMovement        []string            `yaml:"sinksmovement"`
	SanitizersEvent      []string            `yaml:"sanitizersevent"`
	Suppressions         string              `yaml:"suppressions"`

	// Report metadata (`-report`): which target the run is about. Defaults:
	// the main module path, the commit checked out in the module root, and
	// kind "pipeline" (a third-party reader, so every report needs a finding).
	TargetName    string `yaml:"targetname"`
	TargetVersion string `yaml:"targetversion"`
	TargetKind    string `yaml:"targetkind"`

	// Filled in by Load, not by a file.
	Profile          string             `yaml:"-"` // profile name or path given with -profile
	Layers           []string           `yaml:"-"` // display names of the files merged, in order
	SuppressionFiles []*SuppressionFile `yaml:"-"`
	Overlay          bool               `yaml:"-"`
}

// Default overflow policies (XDR206).
const (
	PolicyHaltLedger  = "halt-ledger"
	PolicySkipAndFlag = "skip-and-flag"
)

// DefaultParticipantNameRegex is used when participantnameregex is unset.
const DefaultParticipantNameRegex = `(?i)participant`

// ParticipantName returns the compiled participant-name pattern.
func (c *Config) ParticipantName() *regexp.Regexp {
	if c == nil || c.ParticipantNameRegex == "" {
		return regexp.MustCompile(DefaultParticipantNameRegex)
	}
	return regexp.MustCompile(c.ParticipantNameRegex) // validated by Validate
}

// Enabled reports whether rule r runs under this configuration.
func (c *Config) Enabled(r Rule) bool {
	if c == nil || c.Rules == nil {
		return !r.OptIn
	}
	return slices.Contains(c.Rules, r.ID)
}

// SeverityOf returns the severity a report of rule r gets: the configured
// override if any, else want (the rule's default or what the rule asked for).
func (c *Config) SeverityOf(r Rule, want Severity) Severity {
	if c != nil {
		if s, ok := c.Severity[r.ID]; ok {
			return s
		}
	}
	if want.Valid() {
		return want
	}
	return r.Severity
}

var targetKinds = []string{"sdk", "pipeline", "core", "oracle", "selftest", "fixture"}

// Validate checks values that a YAML decode cannot: rule IDs, severities,
// enumerations and the regular expression. A rule ID must be one the
// registry provides: an ID the v1 rule set reserves but this build does not
// implement is an error too, because enabling it would silently check
// nothing. (Inline directives and suppression entries may still name a
// reserved ID; XDR000 reports those that suppress nothing.)
func (c *Config) Validate(reg *Registry) error {
	return c.validate(func(id string) bool { return reg.Rule(id) != nil })
}

func (c *Config) validate(known func(string) bool) error {
	var errs []error
	unknown := func(id string) string {
		if isReserved(id) {
			return fmt.Sprintf("rule %q is reserved but not provided by this build", id)
		}
		return fmt.Sprintf("unknown rule %q", id)
	}
	for _, id := range c.Rules {
		if !known(id) {
			errs = append(errs, fmt.Errorf("rules: %s", unknown(id)))
		}
	}
	for id, s := range c.Severity {
		if !known(id) {
			errs = append(errs, fmt.Errorf("severity: %s", unknown(id)))
		}
		if !s.Valid() {
			errs = append(errs, fmt.Errorf("severity: %s: %q is not error, warning or info", id, s))
		}
	}
	switch c.OverflowPolicy {
	case "", PolicyHaltLedger, PolicySkipAndFlag:
	default:
		errs = append(errs, fmt.Errorf("overflowpolicy: %q is not %s or %s", c.OverflowPolicy, PolicyHaltLedger, PolicySkipAndFlag))
	}
	if c.ParticipantNameRegex != "" {
		if _, err := regexp.Compile(c.ParticipantNameRegex); err != nil {
			errs = append(errs, fmt.Errorf("participantnameregex: %v", err))
		}
	}
	if c.TargetKind != "" && !slices.Contains(targetKinds, c.TargetKind) {
		errs = append(errs, fmt.Errorf("targetkind: %q is not one of %s", c.TargetKind, strings.Join(targetKinds, ", ")))
	}
	return errors.Join(errs...)
}

func (c *Config) merge(o *Config) {
	if o.Rules != nil {
		c.Rules = slices.Clone(o.Rules)
	}
	for k, v := range o.Severity {
		if c.Severity == nil {
			c.Severity = map[string]Severity{}
		}
		c.Severity[k] = v
	}
	for k, v := range o.Floors {
		if c.Floors == nil {
			c.Floors = map[string]int{}
		}
		c.Floors[k] = v
	}
	appendList := func(dst *[]string, src []string) {
		for _, s := range src {
			if !slices.Contains(*dst, s) {
				*dst = append(*dst, s)
			}
		}
	}
	appendList(&c.XDRPackageAliases, o.XDRPackageAliases)
	appendList(&c.SinksParticipant, o.SinksParticipant)
	appendList(&c.SinksAccountKey, o.SinksAccountKey)
	appendList(&c.SinksText, o.SinksText)
	appendList(&c.SanitizersAddress, o.SanitizersAddress)
	appendList(&c.SanitizersText, o.SanitizersText)
	appendList(&c.BudgetMethods, o.BudgetMethods)
	appendList(&c.OverflowFlags, o.OverflowFlags)
	appendList(&c.HaltingFuncs, o.HaltingFuncs)
	appendList(&c.IngestEntryPoints, o.IngestEntryPoints)
	appendList(&c.SinksMovement, o.SinksMovement)
	appendList(&c.SanitizersEvent, o.SanitizersEvent)
	scalar := func(dst *string, src string) {
		if src != "" {
			*dst = src
		}
	}
	scalar(&c.ParticipantNameRegex, o.ParticipantNameRegex)
	scalar(&c.OverflowPolicy, o.OverflowPolicy)
	scalar(&c.TargetName, o.TargetName)
	scalar(&c.TargetVersion, o.TargetVersion)
	scalar(&c.TargetKind, o.TargetKind)
}

// source is where a layer's file lives: on disk, or in the embedded profiles.
type source struct {
	fsys    fs.FS  // nil = the operating system's file system
	name    string // path inside fsys, or an OS path
	display string // what reports show
}

func (s source) read() ([]byte, error) {
	if s.fsys == nil {
		return os.ReadFile(s.name)
	}
	return fs.ReadFile(s.fsys, s.name)
}

// resolve returns the source for rel, relative to s's directory.
func (s source) resolve(rel string) source {
	if s.fsys == nil {
		p := rel
		if !filepath.IsAbs(p) {
			p = filepath.Join(filepath.Dir(s.name), rel)
		}
		return source{name: p, display: displayPath(p)}
	}
	p := path.Join(path.Dir(s.name), rel)
	return source{fsys: s.fsys, name: p, display: path.Join("profiles", p)}
}

// displayPath shows p relative to the working directory when it is inside it.
func displayPath(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	if wd, err := os.Getwd(); err == nil {
		if rel, err := filepath.Rel(wd, abs); err == nil && !strings.HasPrefix(rel, "..") {
			return filepath.ToSlash(rel)
		}
	}
	return abs
}

// decodeStrict decodes one YAML document, rejecting unknown keys. An empty
// document decodes to the zero value.
func decodeStrict(data []byte, v any) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func (c *Config) addLayer(src source) error {
	data, err := src.read()
	if err != nil {
		return err
	}
	var layer Config
	if err := decodeStrict(data, &layer); err != nil {
		return fmt.Errorf("%s: %v", src.display, err)
	}
	c.merge(&layer)
	c.Layers = append(c.Layers, src.display)
	if layer.Suppressions != "" {
		sf, err := loadSuppressionFile(src.resolve(layer.Suppressions))
		if err != nil {
			return err
		}
		c.SuppressionFiles = append(c.SuppressionFiles, sf)
	}
	return nil
}

// ProfileNames lists the shipped profiles.
func ProfileNames() []string {
	var names []string
	entries, _ := fs.ReadDir(profiles.FS, ".")
	for _, e := range entries {
		if n, ok := strings.CutSuffix(e.Name(), ".yml"); ok && !e.IsDir() && !strings.Contains(n, ".suppressions") {
			names = append(names, n)
		}
	}
	return names
}

// profileSource finds a profile by shipped name, or by path when the value
// names a file (contains a path separator or ends in .yml / .yaml).
func profileSource(nameOrPath string) (source, error) {
	if strings.ContainsRune(nameOrPath, '/') || strings.HasSuffix(nameOrPath, ".yml") || strings.HasSuffix(nameOrPath, ".yaml") {
		return source{name: nameOrPath, display: displayPath(nameOrPath)}, nil
	}
	name := nameOrPath + ".yml"
	if _, err := fs.Stat(profiles.FS, name); err != nil {
		return source{}, fmt.Errorf("no shipped profile %q (shipped: %s)", nameOrPath, strings.Join(ProfileNames(), ", "))
	}
	return source{fsys: profiles.FS, name: name, display: "profiles/" + name}, nil
}

// LoadOptions says which layers to load.
type LoadOptions struct {
	Profile      string // -profile NAME|PATH
	ConfigFile   string // -config FILE; when empty, .xdrlint.yml is searched for from DiscoverFrom
	DiscoverFrom string // directory to start the .xdrlint.yml search in ("" = no search)
	OverlayDir   string // -overlay DIR
}

// ConfigFileNames are the names searched for by discovery.
var ConfigFileNames = []string{".xdrlint.yml", ".xdrlint.yaml"}

// Load builds a configuration from the layers named by opts.
func Load(opts LoadOptions) (*Config, error) {
	c := &Config{Profile: opts.Profile}
	if opts.Profile != "" {
		src, err := profileSource(opts.Profile)
		if err != nil {
			return nil, err
		}
		if err := c.addLayer(src); err != nil {
			return nil, fmt.Errorf("profile: %w", err)
		}
	}
	cfgFile := opts.ConfigFile
	if cfgFile == "" && opts.DiscoverFrom != "" {
		cfgFile = discover(opts.DiscoverFrom)
	}
	if cfgFile != "" {
		if err := c.addLayer(source{name: cfgFile, display: displayPath(cfgFile)}); err != nil {
			return nil, fmt.Errorf("config: %w", err)
		}
	}
	if opts.OverlayDir != "" {
		c.Overlay = true
		p := filepath.Join(opts.OverlayDir, "xdrlint.yml")
		if _, err := os.Stat(p); err == nil {
			if err := c.addLayer(source{name: p, display: displayPath(p)}); err != nil {
				return nil, fmt.Errorf("overlay: %w", err)
			}
		} else if !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("overlay: %w", err)
		}
	}
	return c, nil
}

// discover looks for a configuration file in dir and its parents, stopping
// after the first directory that holds a go.mod.
func discover(dir string) string {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return ""
	}
	for {
		for _, n := range ConfigFileNames {
			p := filepath.Join(dir, n)
			if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
				return p
			}
		}
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return ""
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// Environment variables read when the analyzers run without the standalone
// driver (go vet -vettool, where the command line belongs to go vet).
const (
	EnvConfig  = "XDRLINT_CONFIG"
	EnvProfile = "XDRLINT_PROFILE"
	EnvOverlay = "XDRLINT_OVERLAY"
)

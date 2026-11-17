// Package plugin is xdrlint as a golangci-lint module plugin.
//
// Build a golangci-lint binary that contains it with `golangci-lint custom`
// and a .custom-gcl.yml naming this module and package (the golangci-lint
// version must use the same golang.org/x/tools as this module):
//
//	version: v2.15.0
//	plugins:
//	  - module: github.com/tolgayayci/xdrcheck/lint
//	    import: github.com/tolgayayci/xdrcheck/lint/plugin
//	    version: <tag>          # or `path: <local checkout of lint/>`
//
// then enable it in .golangci.yml:
//
//	linters:
//	  enable: [xdrlint]
//	  settings:
//	    custom:
//	      xdrlint:
//	        type: module
//	        settings:
//	          profile: wallet-backend     # a shipped profile or a profile file
//	          # config: .xdrlint.yml       # a project configuration file
//	          # any configuration key inline, for example:
//	          # overflowpolicy: halt-ledger
//
// With no settings, each package uses the .xdrlint.yml found from its
// directory up to its module root, as under `go vet -vettool`. Inline keys
// are the keys of .xdrlint.yml and form one layer over the profile; they
// cannot be combined with `config`. Reports suppressed by `//xdrlint:ignore`
// or a suppression file are not printed; `//nolint:xdrlint` is handled by
// golangci-lint itself.
package plugin

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/golangci/plugin-module-register/register"
	"golang.org/x/tools/go/analysis"
	"gopkg.in/yaml.v3"

	"github.com/tolgayayci/xdrcheck/lint/internal/framework"
	// The rule packages register their analyzers.
	_ "github.com/tolgayayci/xdrcheck/lint/rules/xdr1xx"
	_ "github.com/tolgayayci/xdrcheck/lint/rules/xdr2xx"
	_ "github.com/tolgayayci/xdrcheck/lint/rules/xdr3xx"
	_ "github.com/tolgayayci/xdrcheck/lint/rules/xdr4xx"
)

// Name is the linter name in golangci-lint's configuration.
const Name = "xdrlint"

func init() { register.Plugin(Name, New) }

// Plugin is the golangci-lint linter plugin.
type Plugin struct{}

// New builds the plugin from the settings under
// linters.settings.custom.xdrlint.settings.
func New(settings any) (register.LinterPlugin, error) {
	cfg, err := configFrom(settings)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	if cfg != nil {
		framework.SetConfig(cfg)
	}
	return &Plugin{}, nil
}

// BuildAnalyzers returns every xdrlint analyzer, XDR000 included.
func (*Plugin) BuildAnalyzers() ([]*analysis.Analyzer, error) {
	return framework.Analyzers(), nil
}

// GetLoadMode: the rules need type information and SSA.
func (*Plugin) GetLoadMode() string { return register.LoadModeTypesInfo }

// configFrom turns the plugin settings into a configuration; nil means none
// was given and each package discovers its own.
func configFrom(settings any) (*framework.Config, error) {
	m, ok := settings.(map[string]any)
	if settings != nil && !ok {
		return nil, fmt.Errorf("settings must be a mapping, got %T", settings)
	}
	if len(m) == 0 {
		return nil, nil
	}
	opts := framework.LoadOptions{}
	inline := map[string]any{}
	for k, v := range m {
		switch k {
		case "profile", "config", "overlay":
			s, ok := v.(string)
			if !ok {
				return nil, fmt.Errorf("settings: %s must be a string", k)
			}
			switch k {
			case "profile":
				opts.Profile = s
			case "config":
				opts.ConfigFile = s
			case "overlay":
				opts.OverlayDir = s
			}
		default:
			inline[k] = v
		}
	}
	if len(inline) > 0 {
		if opts.ConfigFile != "" {
			return nil, fmt.Errorf("settings: give configuration keys inline or in `config`, not both")
		}
		// The inline keys become a configuration file, decoded with the same
		// strict decoder as .xdrlint.yml (an unknown key is an error). A
		// relative suppression file is relative to the working directory
		// (golangci-lint's), not to that temporary file.
		if s, ok := inline["suppressions"].(string); ok && s != "" && !filepath.IsAbs(s) {
			abs, err := filepath.Abs(s)
			if err != nil {
				return nil, err
			}
			inline["suppressions"] = abs
		}
		data, err := yaml.Marshal(inline)
		if err != nil {
			return nil, err
		}
		dir, err := os.MkdirTemp("", "xdrlint-plugin-")
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(dir)
		opts.ConfigFile = filepath.Join(dir, "settings.yml")
		if err := os.WriteFile(opts.ConfigFile, data, 0o600); err != nil {
			return nil, err
		}
	}
	cfg, err := framework.Load(opts)
	if err != nil {
		return nil, err
	}
	if err := cfg.Validate(framework.Default); err != nil {
		return nil, err
	}
	return cfg, nil
}

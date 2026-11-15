// Package hunt holds what the data-side commands share: the tool's name, the schema ids derived from it, the
// environment variables they read, and the per-user directories they cache into.
//
// The commands are `data`, `query`, `find`, the target form of `replay`, `repro`, `xcheck` and `runs`
// (docs/hunt.md). Every name below is derived from Tool, so renaming the command is a one-line change.
package hunt

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/tolgayayci/xdrcheck/go/internal/userdir"
)

// Tool is the command's name. Schema ids, environment variables and cache directories are derived from it.
const Tool = "xdrcheck"

// Version is the version of the data-side commands, written into every run manifest and bundle.
const Version = "0.1.0"

// schemaPrefix is the namespace of the data-side schema ids. The ids are frozen formats written into run
// directories and bundles, so they keep the namespace they were published under when the command was renamed.
const schemaPrefix = "xcc"

// SchemaID returns the id of one of the data-side schemas, for example SchemaID("run") = "xcc.run/v1".
func SchemaID(name string) string { return schemaPrefix + "." + name + "/v1" }

// Env returns the value of the environment variable <TOOL>_<name>, for example Env("DATASET") reads XDRCHECK_DATASET;
// when only the variable of the command's earlier name is set (XCC_DATASET), that one is read.
func Env(name string) string {
	if v, ok := os.LookupEnv(EnvName(name)); ok {
		return v
	}
	return userdir.Getenv(name)
}

// EnvName returns the full name of an environment variable.
func EnvName(name string) string { return strings.ToUpper(Tool) + "_" + name }

// CacheDir returns the per-user cache directory (built target programs, fetched tools):
// $<TOOL>_CACHE, else $XDG_CACHE_HOME/<tool>, else ~/.cache/<tool> (each the directory of the earlier name when
// only that one exists, see package userdir).
func CacheDir() string {
	if d := Env("CACHE"); d != "" {
		return d
	}
	if d := os.Getenv("XDG_CACHE_HOME"); d != "" {
		return userdir.Under(d)
	}
	home, _ := os.UserHomeDir()
	return userdir.Under(filepath.Join(home, ".cache"))
}

// DataDir returns the per-user data directory (the default dataset): $XDG_DATA_HOME/<tool>, else
// ~/.local/share/<tool> (each the directory of the earlier name when only that one exists).
func DataDir() string {
	if d := os.Getenv("XDG_DATA_HOME"); d != "" {
		return userdir.Under(d)
	}
	home, _ := os.UserHomeDir()
	return userdir.Under(filepath.Join(home, ".local", "share"))
}

// Unavailable is the error of a part whose tool is not installed. Its message always starts with
// "not available:" so that a caller, a summary or a reader can never take it for a result.
type Unavailable struct {
	What string // the tool or input that is missing
	Hint string // how to get it, optional
}

func (u *Unavailable) Error() string {
	s := "not available: " + u.What + " missing"
	if u.Hint != "" {
		s += " (" + u.Hint + ")"
	}
	return s
}

// Missing returns an Unavailable error.
func Missing(what, hint string) error { return &Unavailable{What: what, Hint: hint} }

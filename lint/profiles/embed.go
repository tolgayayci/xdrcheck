// Package profiles embeds the shipped xdrlint profiles, so that
// `xdrlint -profile NAME` works from an installed binary.
//
// A profile is a configuration file with the keys of .xdrlint.yml. A
// relative path inside a profile (for example `suppressions:`) is resolved
// inside this directory.
package profiles

import "embed"

// FS holds the *.yml files of this directory. A profile's suppression files
// live next to it; a subdirectory of them must be added to the pattern below.
//
//go:embed *.yml
var FS embed.FS

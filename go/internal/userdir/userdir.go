// Package userdir resolves the kit's per-user directories: the cache, the cache under the platform's user cache
// directory, and the private overlay. Each is <base>/xdrcheck. The kit had another name before, and directories
// made under that name are still read: when <base>/xdrcheck does not exist and the old one does, the old one is
// used, so existing caches and overlays keep working. Nothing is moved. Environment variables of the old name
// are read the same way (LegacyEnv, Getenv).
package userdir

import (
	"os"
	"path/filepath"
	"strings"
)

// Name is the directory name the kit creates.
const Name = "xdrcheck"

// legacy is the directory name earlier versions of the kit created; it is only read.
const legacy = "xcc"

// Under returns base/xdrcheck, or base/<legacy name> when only that one exists as a directory.
func Under(base string) string {
	cur := filepath.Join(base, Name)
	if _, err := os.Stat(cur); err == nil {
		return cur
	}
	if fi, err := os.Stat(filepath.Join(base, legacy)); err == nil && fi.IsDir() {
		return filepath.Join(base, legacy)
	}
	return cur
}

// HomeCache is ~/.cache/xdrcheck (or the legacy directory there). ok is false when there is no home directory.
func HomeCache() (dir string, ok bool) {
	h, err := os.UserHomeDir()
	if err != nil {
		return "", false
	}
	return Under(filepath.Join(h, ".cache")), true
}

// UserCache is <os.UserCacheDir()>/xdrcheck (or the legacy directory there).
func UserCache() (string, error) {
	d, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return Under(d), nil
}

// Overlay is ~/.local/share/xdrcheck/overlay (or the legacy directory's overlay).
func Overlay() string {
	h, _ := os.UserHomeDir()
	return filepath.Join(Under(filepath.Join(h, ".local", "share")), "overlay")
}

// EnvPrefix is the prefix of the kit's environment variables; legacyEnvPrefix is the one earlier versions read.
const (
	EnvPrefix       = "XDRCHECK_"
	legacyEnvPrefix = "XCC_"
)

// Getenv returns $XDRCHECK_<name>, else the variable of the earlier name ($XCC_<name>) when only that one is set.
func Getenv(name string) string {
	if v, ok := os.LookupEnv(EnvPrefix + name); ok {
		return v
	}
	return os.Getenv(legacyEnvPrefix + name)
}

// LegacyEnv copies every variable of the earlier name (XCC_<NAME>) to XDRCHECK_<NAME> when XDRCHECK_<NAME> is
// not set, so the process and every program it starts read settings exported under the old name. A variable
// set under the new name always wins. It returns the names it set. Commands call it first thing in main.
func LegacyEnv() []string {
	var set []string
	for _, kv := range os.Environ() {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || !strings.HasPrefix(k, legacyEnvPrefix) || len(k) == len(legacyEnvPrefix) {
			continue
		}
		name := EnvPrefix + strings.TrimPrefix(k, legacyEnvPrefix)
		if _, exists := os.LookupEnv(name); exists {
			continue
		}
		if os.Setenv(name, v) == nil {
			set = append(set, name)
		}
	}
	return set
}

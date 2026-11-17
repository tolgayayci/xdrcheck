package main

import (
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
)

// expandTestdata expands a relative directory pattern such as
// "./testdata/..." whose fixed part names a testdata directory. The go
// command never matches testdata trees with "...", even when the pattern
// names one explicitly, so the linter's own fixtures could not be linted as
// "./testdata/..."; this walks such a tree and lists each directory holding
// Go files. Every other pattern is passed through unchanged. (`go vet` does
// its own matching: there, name a directory below testdata, for example
// ./testdata/xdr0xx/....)
func expandTestdata(patterns []string) []string {
	var out []string
	for _, p := range patterns {
		dir, ok := strings.CutSuffix(p, "/...")
		relative := strings.HasPrefix(p, "./") || strings.HasPrefix(p, "../")
		if !ok || !relative || !slices.Contains(strings.Split(filepath.ToSlash(dir), "/"), "testdata") {
			out = append(out, p)
			continue
		}
		n := len(out)
		_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || !d.IsDir() {
				return nil
			}
			if name := d.Name(); path != dir && (strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")) {
				return filepath.SkipDir
			}
			if matches, _ := filepath.Glob(filepath.Join(path, "*.go")); len(matches) > 0 {
				out = append(out, "./"+filepath.ToSlash(filepath.Clean(path)))
			}
			return nil
		})
		if len(out) == n {
			out = append(out, p) // let the go command say that it matches nothing
		}
	}
	return out
}

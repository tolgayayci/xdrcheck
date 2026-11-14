package conform

// Building a column from an SDK checkout instead of its pinned package (`xdrcheck conform fetch|build|run --sdk PATH`):
// an SDK maintainer runs the corpus against an unreleased branch before tagging it.
//
// The committed driver directory is never touched. `fetch --sdk` copies the column's language directory (the
// parent of its driver directory, so relative paths between version directories and the shared driver source
// still hold) to a private place under the conformance cache, keyed by the checkout's path, and runs the copy's
// `make fetch` with XDRCHECK_SDK_SOURCE set to the checkout; `build` and `run` use that copy. The driver's Makefile does
// the language-specific part (a go.mod replace, a cargo path dependency, a wheel of the checkout) and leaves
// bin/xdrcheck-sdk-source naming the checkout it built from; `run` refuses a copy built from anything else. The copy
// has its own package cache, so the pinned build is never disturbed. describe may then report any version (the
// checkout's own); known divergences are still judged against the column's pinned version, so a bug the checkout
// fixes shows as unexpected-conform.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// SourceFile is the file a driver build from a checkout leaves in its directory, holding the checkout's path.
const SourceFile = "bin/xdrcheck-sdk-source"

// SourceVariable is the environment variable that tells a driver Makefile to build from a checkout.
const SourceVariable = "XDRCHECK_SDK_SOURCE"

// WithSource returns copies of the columns that build from the SDK checkout at path. Every column must be of one
// SDK, and its driver directory's Makefiles must support SourceVariable.
func (s *Sets) WithSource(cols []*Column, path string) ([]*Column, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if st, err := os.Stat(abs); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("--sdk %s: not a directory", path)
	}
	out := make([]*Column, 0, len(cols))
	for _, c := range cols {
		if c.SDK != cols[0].SDK {
			return nil, fmt.Errorf("--sdk builds one SDK from a checkout, but the selection has columns of %s and %s; select one SDK's columns (--column %s)", cols[0].SDK, c.SDK, cols[0].SDK)
		}
		lang := filepath.Dir(s.AbsDir(c))
		if !supportsSource(lang) {
			return nil, fmt.Errorf("--sdk: the driver of %s (%s) cannot build from a checkout (its Makefiles do not read %s)", c.ID, filepath.Dir(c.Dir), SourceVariable)
		}
		cc := *c
		cc.Source = abs
		cc.SourceDir = filepath.Join(sourceRoot(abs, c.Dir), filepath.Base(filepath.FromSlash(c.Dir)))
		out = append(out, &cc)
	}
	return out, nil
}

// supportsSource reports whether a language directory's Makefiles read SourceVariable.
func supportsSource(lang string) bool {
	found := false
	filepath.WalkDir(lang, func(p string, d fs.DirEntry, err error) error {
		if err != nil || found {
			return nil
		}
		if d.IsDir() && (d.Name() == "bin" || d.Name() == "node_modules" || d.Name() == "target") {
			return filepath.SkipDir
		}
		if n := d.Name(); n == "Makefile" || strings.HasSuffix(n, ".mk") {
			if b, err := os.ReadFile(p); err == nil && strings.Contains(string(b), SourceVariable) {
				found = true
			}
		}
		return nil
	})
	return found
}

// sourceKey names one checkout and one language directory.
func sourceKey(checkout, dir string) string {
	h := sha256.Sum256([]byte(checkout + "\x00" + filepath.ToSlash(filepath.Dir(dir))))
	return hex.EncodeToString(h[:6])
}

// sourceRoot is the private copy of a column's language directory for a checkout.
func sourceRoot(checkout, dir string) string {
	return filepath.Join(cacheBase(), "conform", "source-"+sourceKey(checkout, dir), filepath.Base(filepath.Dir(filepath.FromSlash(dir))))
}

// PrepareSource makes the private copy of a source column's language directory afresh from the committed one.
func (s *Sets) PrepareSource(c *Column) error {
	if c.Source == "" {
		return nil
	}
	pinned := *c
	pinned.Source, pinned.SourceDir = "", ""
	from := filepath.Dir(s.AbsDir(&pinned))
	to := filepath.Dir(c.SourceDir)
	if err := os.RemoveAll(to); err != nil {
		return err
	}
	return copyTree(from, to)
}

// CheckSource checks that a source column's driver was built from its checkout.
func (s *Sets) CheckSource(c *Column) error {
	if c.Source == "" {
		return nil
	}
	b, err := os.ReadFile(filepath.Join(c.SourceDir, filepath.FromSlash(SourceFile)))
	if err != nil {
		return fmt.Errorf("column %s has not been built from %s: run xdrcheck conform fetch and build with --sdk %s first", c.ID, c.Source, c.Source)
	}
	if got := strings.TrimSpace(string(b)); got != c.Source {
		return fmt.Errorf("column %s: its driver copy was built from %s, not %s; run xdrcheck conform fetch and build with --sdk again", c.ID, got, c.Source)
	}
	return nil
}

// copyTree copies a directory tree, leaving out build output (bin/, target/, node_modules/).
func copyTree(from, to string) error {
	return filepath.WalkDir(from, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(from, p)
		if err != nil {
			return err
		}
		dst := filepath.Join(to, rel)
		if d.IsDir() {
			if n := d.Name(); rel != "." && (n == "bin" || n == "target" || n == "node_modules") {
				return filepath.SkipDir
			}
			return os.MkdirAll(dst, 0o755)
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		src, err := os.Open(p)
		if err != nil {
			return err
		}
		defer src.Close()
		out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode().Perm()|0o200)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, src); err != nil {
			out.Close()
			return err
		}
		return out.Close()
	})
}

package main

// xdrcheck report redact: a copy of an xcc.report/v1 file that is safe to share.

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/tolgayayci/xdrcheck/go/internal/report"
)

func reportRedact(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("xdrcheck report redact", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "", "output file (default standard output)")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return 2
	}
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "xdrcheck report redact: "+format+"\n", a...)
		return 2
	}
	if len(pos) != 1 {
		return fail("want exactly one report")
	}
	rd, note, err := newRedactor()
	if err != nil {
		return fail("%v", err)
	}
	if note != "" {
		fmt.Fprintln(stderr, "xdrcheck report redact: "+note)
	}
	var buf bytes.Buffer
	w, err := report.NewWriter(&buf, report.Header{})
	if err != nil {
		return fail("%v", err)
	}
	h, _, err := report.ReadFile(pos[0], func(r *report.Row) error { return w.Write(rd.row(*r)) })
	if err != nil {
		return fail("%v", err)
	}
	w.SetHeader(rd.header(*h))
	if err := w.Close(); err != nil {
		return fail("%v", err)
	}
	if *out == "" {
		stdout.Write(buf.Bytes())
	} else if err := os.WriteFile(*out, buf.Bytes(), 0o644); err != nil {
		return fail("%v", err)
	}
	fmt.Fprintf(stderr, "xdrcheck report redact: %d strings changed; evidence, notes, messages and details dropped\n", rd.changed)
	return 0
}

// publicScanScript is the repository's public-tree scan; its patterns are what a redacted report must not
// contain.
const publicScanScript = "scripts/py/check_public.py"

// redactor removes everything machine-local or private from the strings a redacted report keeps.
type redactor struct {
	banned  []*regexp.Regexp
	allow   []*regexp.Regexp
	terms   *privateTerms // the scan's hashed list of private names
	locals  []string      // this machine's home, working and temporary directories
	changed int
}

// localRoots matches absolute paths under the usual machine-local roots.
var localRoots = regexp.MustCompile(`(/home|/Users|/root|/tmp|/var/folders|/private/var|/run/user|/mnt|/media)/[^\s"'<>|;,()]*`)

// newRedactor loads the banned patterns and the hashed list of private names from the repository's public-tree
// scan when it can be found from the working directory; without them only machine-local paths are removed, and
// the note says so.
func newRedactor() (*redactor, string, error) {
	rd := &redactor{}
	for _, f := range []func() (string, error){os.UserHomeDir, os.Getwd} {
		if d, err := f(); err == nil && len(d) > 1 {
			rd.locals = append(rd.locals, d)
		}
	}
	if t := os.TempDir(); len(t) > 1 {
		rd.locals = append(rd.locals, t)
	}
	sort.Slice(rd.locals, func(i, j int) bool { return len(rd.locals[i]) > len(rd.locals[j]) })
	root, err := repoRoot()
	if err != nil {
		return rd, "no repository found: only machine-local paths are redacted, not the public-tree scan's patterns", nil
	}
	banned, allow, err := loadPublicPatterns(filepath.Join(root, publicScanScript))
	if errors.Is(err, os.ErrNotExist) {
		return rd, publicScanScript + " not found: only machine-local paths are redacted", nil
	}
	if err != nil {
		return nil, "", err
	}
	rd.banned, rd.allow = banned, allow
	terms, err := loadPrivateTerms(filepath.Join(root, privateTermsFile))
	if errors.Is(err, os.ErrNotExist) {
		return rd, privateTermsFile + " not found: private names are not redacted", nil
	}
	if err != nil {
		return nil, "", err
	}
	rd.terms = terms
	return rd, "", nil
}

var pyCompile = regexp.MustCompile(`re\.compile\(r"((?:[^"\\]|\\.)*)"\)`)

// loadPublicPatterns reads every re.compile(r"...") pattern of the public-tree scan. The pattern assigned to
// HANDLE_OK is the scan's one allowed occurrence; the others are banned. Lookbehind assertions, which RE2
// lacks, are dropped, so a translated pattern matches at least everything the original does.
func loadPublicPatterns(path string) (banned, allow []*regexp.Regexp, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		for _, m := range pyCompile.FindAllStringSubmatch(line, -1) {
			re, err := regexp.Compile(dropLookbehind(m[1]))
			if err != nil {
				return nil, nil, fmt.Errorf("%s: pattern %q: %w", path, m[1], err)
			}
			if strings.HasPrefix(strings.TrimSpace(line), "HANDLE_OK") {
				allow = append(allow, re)
			} else {
				banned = append(banned, re)
			}
		}
	}
	if len(banned) == 0 {
		return nil, nil, fmt.Errorf("%s: no patterns found", path)
	}
	return banned, allow, nil
}

// dropLookbehind removes (?<=…) and (?<!…) groups from a Python pattern.
func dropLookbehind(p string) string {
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		if strings.HasPrefix(p[i:], "(?<=") || strings.HasPrefix(p[i:], "(?<!") {
			depth, class := 0, false
			j := i
			for ; j < len(p); j++ {
				switch c := p[j]; {
				case c == '\\':
					j++
				case class:
					if c == ']' {
						class = false
					}
				case c == '[':
					class = true
				case c == '(':
					depth++
				case c == ')':
					depth--
				}
				if depth == 0 {
					break
				}
			}
			i = j
			continue
		}
		b.WriteByte(p[i])
		if p[i] == '\\' && i+1 < len(p) {
			i++
			b.WriteByte(p[i])
		}
	}
	return b.String()
}

// scrub returns s with machine-local paths replaced by <local-path> and every banned match by [redacted].
func (rd *redactor) scrub(s string) string {
	orig := s
	for _, l := range rd.locals {
		s = strings.ReplaceAll(s, l, "<local-path>")
	}
	s = replaceUnlessWord(localRoots, s, "<local-path>")
	for _, re := range rd.banned {
		s = rd.replaceBanned(re, s)
	}
	if rd.terms != nil {
		s = rd.terms.redact(s)
	}
	if s != orig {
		rd.changed++
	}
	return s
}

// replaceUnlessWord replaces matches of re that do not continue a word or path (the preceding byte is not a
// letter, digit, '.', '-' or '_').
func replaceUnlessWord(re *regexp.Regexp, s, with string) string {
	var b strings.Builder
	last := 0
	for _, m := range re.FindAllStringIndex(s, -1) {
		if m[0] > 0 {
			c := s[m[0]-1]
			if c == '.' || c == '-' || c == '_' || c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' {
				continue
			}
		}
		b.WriteString(s[last:m[0]])
		b.WriteString(with)
		last = m[1]
	}
	b.WriteString(s[last:])
	return b.String()
}

func (rd *redactor) replaceBanned(re *regexp.Regexp, s string) string {
	var spans [][]int
	for _, a := range rd.allow {
		spans = append(spans, a.FindAllStringIndex(s, -1)...)
	}
	var b strings.Builder
	last := 0
	for _, m := range re.FindAllStringIndex(s, -1) {
		allowed := false
		for _, sp := range spans {
			if m[0] >= sp[0] && m[1] <= sp[1] {
				allowed = true
			}
		}
		if allowed || m[0] == m[1] {
			continue
		}
		b.WriteString(s[last:m[0]])
		b.WriteString("[redacted]")
		last = m[1]
	}
	b.WriteString(s[last:])
	return b.String()
}

func (rd *redactor) scrubMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[rd.scrub(k)] = rd.scrub(v)
	}
	return out
}

// row keeps classes, qualifiers, outcomes, verdicts and entry IDs, drops evidence, notes, linter messages,
// suppression reasons and corpus details, and scrubs every string it keeps.
func (rd *redactor) row(r report.Row) report.Row {
	r.Evidence, r.Notes = nil, nil
	r.RowID, r.Entry, r.Variant = rd.scrub(r.RowID), rd.scrub(r.Entry), rd.scrub(r.Variant)
	r.Target.Name, r.Target.Version = rd.scrub(r.Target.Name), rd.scrub(r.Target.Version)
	r.Target.Column, r.Target.Profile = rd.scrub(r.Target.Column), rd.scrub(r.Target.Profile)
	if r.Expected != nil {
		e := *r.Expected
		e.Result = rd.scrub(e.Result)
		r.Expected = &e
	}
	if r.KnownDivergence != nil {
		k := *r.KnownDivergence
		if ref := rd.scrub(k.Reference); ref != k.Reference {
			r.KnownDivergence = nil // a reference that is not public is dropped whole: it must stay a URI
		} else {
			k.FixedIn = rd.scrub(k.FixedIn)
			r.KnownDivergence = &k
		}
	}
	if r.Replay != nil {
		x := *r.Replay
		r.Replay = &x
	}
	if r.Conform != nil {
		x := *r.Conform
		x.Reason = rd.scrub(x.Reason)
		r.Conform = &x
	}
	if r.Lint != nil {
		x := *r.Lint
		x.Message, x.SuppressionReason = "", ""
		x.Location.File, x.Location.Function = rd.scrub(x.Location.File), rd.scrub(x.Location.Function)
		r.Lint = &x
	}
	if r.Corpus != nil {
		x := *r.Corpus
		x.Detail = ""
		r.Corpus = &x
	}
	return r
}

func (rd *redactor) header(h report.Header) report.Header {
	h.Tool.Version = rd.scrub(h.Tool.Version)
	h.Corpus.Version, h.Corpus.Schema = rd.scrub(h.Corpus.Version), rd.scrub(h.Corpus.Schema)
	h.Pins.Values = rd.scrubMap(h.Pins.Values)
	h.Mode.Suite, h.Mode.Offline = rd.scrub(h.Mode.Suite), rd.scrub(h.Mode.Offline)
	if h.Run != nil {
		run := *h.Run
		run.Host, run.ID = "", ""
		run.Toolchains = rd.scrubMap(run.Toolchains)
		h.Run = &run
	}
	return h
}

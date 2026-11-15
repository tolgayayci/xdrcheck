package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// privateTermsFile is the public-tree scan's hashed list of private names (scripts/py/check_public.py reads it
// with the same tokenizer): a "salt <s>" line, then the hex SHA-256 of "<s>:<lowercased name>" per line.
const privateTermsFile = "scripts/py/private-terms.sha256"

// privateTerms matches the names of a hashed list without knowing them.
type privateTerms struct {
	salt   string
	hashes map[string]bool
}

var (
	termToken     = regexp.MustCompile(`[A-Za-z0-9._-]+`)
	termSeparator = regexp.MustCompile(`[._-]`)
	termCamel     = regexp.MustCompile(`[A-Z]+[a-z0-9]*|[a-z0-9]+`)
	hexDigest     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

const termMaxParts = 4

func loadPrivateTerms(path string) (*privateTerms, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pt := &privateTerms{hashes: map[string]bool{}}
	for _, l := range strings.Split(string(data), "\n") {
		l = strings.TrimSpace(l)
		switch {
		case l == "" || strings.HasPrefix(l, "#"):
		case strings.HasPrefix(l, "salt "):
			pt.salt = strings.TrimPrefix(l, "salt ")
		case hexDigest.MatchString(l):
			pt.hashes[l] = true
		default:
			return nil, fmt.Errorf("%s: unreadable line %q", path, l)
		}
	}
	if pt.salt == "" || len(pt.hashes) == 0 {
		return nil, fmt.Errorf("%s: no salt or no hashes", path)
	}
	return pt, nil
}

func (pt *privateTerms) hit(s string) bool {
	sum := sha256.Sum256([]byte(pt.salt + ":" + strings.ToLower(s)))
	return pt.hashes[hex.EncodeToString(sum[:])]
}

// candidates mirrors check_public.py: the token, runs of up to four of its separated parts (as written and
// joined by "-"), and its camel-case words. Go's RE2 has no lookahead, so camel words are split a little
// differently ("HTTPServer" gives "HTTPServer" here), which only ever adds candidates.
func termCandidates(tok string) []string {
	out := []string{tok}
	words := termSeparator.Split(tok, -1)
	seps := termSeparator.FindAllString(tok, -1)
	for i, w := range words {
		if w != "" {
			out = append(out, w)
		}
		acc, norm := w, w
		for j := i + 1; j < len(words) && j < i+termMaxParts; j++ {
			acc += seps[j-1] + words[j]
			norm += "-" + words[j]
			out = append(out, acc, norm)
		}
		out = append(out, termCamel.FindAllString(w, -1)...)
	}
	return out
}

// redact replaces every private name in s with [redacted].
func (pt *privateTerms) redact(s string) string {
	toks := termToken.FindAllStringIndex(s, -1)
	cut := make([]bool, len(toks))
	for i, m := range toks {
		for _, c := range termCandidates(s[m[0]:m[1]]) {
			if pt.hit(c) {
				cut[i] = true
				break
			}
		}
		if i > 0 {
			x, y := strings.ToLower(s[toks[i-1][0]:toks[i-1][1]]), strings.ToLower(s[m[0]:m[1]])
			if pt.hit(x+" "+y) || pt.hit(x+"-"+y) {
				cut[i-1], cut[i] = true, true
			}
		}
	}
	var b strings.Builder
	last := 0
	for i, m := range toks {
		if !cut[i] {
			continue
		}
		b.WriteString(s[last:m[0]])
		b.WriteString("[redacted]")
		last = m[1]
	}
	b.WriteString(s[last:])
	return b.String()
}

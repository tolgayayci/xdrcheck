package xdrdef

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Enum ceilings of the conformance drivers. Each driver's `reach` module holds, between a BEGIN and an END
// marker line, the highest member value of a few sentinel enums in the pinned definitions; a driver whose SDK
// declares a member above one reports no protocol (its XDR is newer than the driver can bound). The values are
// data, read here from the XDR definitions and written into every driver's own language, so an upgrade
// changes one input instead of five hand-edited tables.
//
// Within a block, every `Name: N`, `"Name": N`, `("Name", N)` or `{"Name", N, …}` entry is one ceiling; Name
// is the enum's name as the SDK spells it, matched to the definition ignoring case. The BEGIN line ends with
// the definitions' label in parentheses, which the generator rewrites too.

// CeilingBegin and CeilingEnd mark a generated block (after the language's comment leader).
const (
	CeilingBegin = "BEGIN generated: xdrcheck xdr ceilings"
	CeilingEnd   = "END generated: xdrcheck xdr ceilings"
)

var (
	ceilingEntry = regexp.MustCompile(`"?\b([A-Z][A-Za-z0-9]*)"?(\s*[:,]\s*)(\d+)\b`)
	beginLabel   = regexp.MustCompile(`\(([^()]*)\)\s*$`)
)

// skipDirs are directories under drivers/ that hold fetched or built files, never driver sources.
var skipDirs = map[string]bool{"node_modules": true, "target": true, "vendor": true, ".venv": true, "bin": true,
	"dist": true, "__pycache__": true, ".git": true}

// FindCeilingFiles lists the files under dir that hold a ceiling block, sorted.
func FindCeilingFiles(dir string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(dir, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if e.IsDir() {
			if skipDirs[e.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if info, err := e.Info(); err != nil || info.Size() > 1<<20 {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if strings.Contains(string(b), CeilingBegin) {
			out = append(out, p)
		}
		return nil
	})
	sort.Strings(out)
	return out, err
}

// CeilingDrift is one value that differs from the definitions.
type CeilingDrift struct {
	File, Enum string
	Have, Want string
}

func (d CeilingDrift) String() string {
	return fmt.Sprintf("%s: %s is %s, the definitions say %s", d.File, d.Enum, d.Have, d.Want)
}

// UpdateCeilings rewrites the ceiling blocks of one file's text from the definitions; label names them on the
// BEGIN line. It returns the new text and every value that changed.
func UpdateCeilings(file, text string, s *Set, label string) (string, []CeilingDrift, error) {
	lines := strings.SplitAfter(text, "\n")
	var drift []CeilingDrift
	in, blocks, entries := false, 0, 0
	for i, l := range lines {
		switch {
		case strings.Contains(l, CeilingBegin):
			if in {
				return "", nil, fmt.Errorf("%s:%d: nested %q", file, i+1, CeilingBegin)
			}
			in = true
			blocks++
			nl := strings.TrimRight(l, "\r\n")
			want := nl
			if m := beginLabel.FindStringSubmatchIndex(nl); m != nil {
				want = nl[:m[2]] + label + nl[m[3]:]
				if nl[m[2]:m[3]] != label {
					drift = append(drift, CeilingDrift{file, "(label)", nl[m[2]:m[3]], label})
				}
			} else {
				return "", nil, fmt.Errorf("%s:%d: the BEGIN line must end with the definitions' label in parentheses", file, i+1)
			}
			lines[i] = want + l[len(nl):]
		case strings.Contains(l, CeilingEnd):
			if !in {
				return "", nil, fmt.Errorf("%s:%d: %q without BEGIN", file, i+1, CeilingEnd)
			}
			in = false
		case in:
			var err error
			lines[i] = ceilingEntry.ReplaceAllStringFunc(l, func(m string) string {
				sm := ceilingEntry.FindStringSubmatch(m)
				name, have := sm[1], sm[3]
				entries++
				e := s.FindEnumFold(name)
				if e == nil {
					err = fmt.Errorf("%s:%d: %s is no enum of the definitions", file, i+1, name)
					return m
				}
				max, _ := s.EnumMax(e.Name)
				want := strconv.FormatInt(max, 10)
				if want != have {
					drift = append(drift, CeilingDrift{file, name, have, want})
				}
				return m[:len(m)-len(have)] + want
			})
			if err != nil {
				return "", nil, err
			}
		}
	}
	if in {
		return "", nil, fmt.Errorf("%s: %q is not closed", file, CeilingBegin)
	}
	if blocks == 0 || entries == 0 {
		return "", nil, fmt.Errorf("%s: no ceiling block with entries", file)
	}
	return strings.Join(lines, ""), drift, nil
}

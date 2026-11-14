package xdrdef

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// token is one lexical token of a .x file with the preprocessor conditions in force where it appears.
type token struct {
	text string
	line int
	cond Cond
}

// lex splits a .x file into tokens. Comments, `%` pass-through lines and `#include`/`#pragma` lines are
// dropped; `#ifdef`, `#ifndef`, `#else` and `#endif` are tracked as a condition stack whose state is recorded
// on every token.
func lex(file, src string) ([]token, error) {
	var toks []token
	var stack []string // innermost last
	inComment := false
	for n, line := range strings.Split(src, "\n") {
		ln := n + 1
		if !inComment {
			t := strings.TrimSpace(line)
			if strings.HasPrefix(t, "%") {
				continue
			}
			if strings.HasPrefix(t, "#") {
				f := strings.Fields(strings.TrimPrefix(t, "#"))
				if len(f) == 0 {
					continue
				}
				switch f[0] {
				case "ifdef", "ifndef":
					if len(f) < 2 {
						return nil, fmt.Errorf("%s:%d: #%s without a name", file, ln, f[0])
					}
					c := f[1]
					if f[0] == "ifndef" {
						c = "!" + c
					}
					stack = append(stack, c)
				case "else":
					if len(stack) == 0 {
						return nil, fmt.Errorf("%s:%d: #else without #ifdef", file, ln)
					}
					top := stack[len(stack)-1]
					if strings.HasPrefix(top, "!") {
						stack[len(stack)-1] = top[1:]
					} else {
						stack[len(stack)-1] = "!" + top
					}
				case "endif":
					if len(stack) == 0 {
						return nil, fmt.Errorf("%s:%d: #endif without #ifdef", file, ln)
					}
					stack = stack[:len(stack)-1]
				case "if", "elif":
					return nil, fmt.Errorf("%s:%d: #%s is not supported (only #ifdef, #ifndef, #else, #endif)", file, ln, f[0])
				}
				continue
			}
		}
		cond := append(Cond(nil), stack...)
		sort.Strings(cond)
		i := 0
		for i < len(line) {
			if inComment {
				j := strings.Index(line[i:], "*/")
				if j < 0 {
					i = len(line)
					continue
				}
				i += j + 2
				inComment = false
				continue
			}
			c := line[i]
			switch {
			case c == ' ' || c == '\t' || c == '\r':
				i++
			case strings.HasPrefix(line[i:], "//"):
				i = len(line)
			case strings.HasPrefix(line[i:], "/*"):
				inComment = true
				i += 2
			case isIdentStart(c) || (c >= '0' && c <= '9'):
				j := i
				for j < len(line) && (isIdentStart(line[j]) || (line[j] >= '0' && line[j] <= '9')) {
					j++
				}
				toks = append(toks, token{line[i:j], ln, cond})
				i = j
			case strings.ContainsRune("{}()[]<>;:,=*-", rune(c)):
				toks = append(toks, token{string(c), ln, cond})
				i++
			default:
				return nil, fmt.Errorf("%s:%d: unexpected character %q", file, ln, c)
			}
		}
	}
	if len(stack) != 0 {
		return nil, fmt.Errorf("%s: #ifdef %s is not closed", file, stack[len(stack)-1])
	}
	return toks, nil
}

func isIdentStart(c byte) bool { return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

// parser is a recursive-descent parser over one file's tokens.
type parser struct {
	file string
	toks []token
	pos  int
	defs []*Def
}

func (p *parser) peek() string {
	if p.pos < len(p.toks) {
		return p.toks[p.pos].text
	}
	return ""
}

func (p *parser) tok() token {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return token{line: -1}
}

func (p *parser) next() string {
	t := p.peek()
	p.pos++
	return t
}

func (p *parser) errf(format string, a ...any) error {
	ln := 0
	if p.pos < len(p.toks) {
		ln = p.toks[p.pos].line
	} else if len(p.toks) > 0 {
		ln = p.toks[len(p.toks)-1].line
	}
	return fmt.Errorf("%s:%d: %s", p.file, ln, fmt.Sprintf(format, a...))
}

func (p *parser) expect(s string) error {
	if got := p.next(); got != s {
		p.pos--
		return p.errf("expected %q, found %q", s, got)
	}
	return nil
}

func (p *parser) ident() (string, error) {
	t := p.next()
	if t == "" || !isIdentStart(t[0]) {
		p.pos--
		return "", p.errf("expected a name, found %q", t)
	}
	return t, nil
}

// ParseFile parses one .x file's text.
func ParseFile(file, src string) ([]*Def, error) {
	toks, err := lex(file, src)
	if err != nil {
		return nil, err
	}
	p := &parser{file: file, toks: toks}
	if err := p.body(false); err != nil {
		return nil, err
	}
	return p.defs, nil
}

// body parses definitions until the end of input, or until `}` inside a namespace.
func (p *parser) body(inNamespace bool) error {
	for p.pos < len(p.toks) {
		switch p.peek() {
		case "}":
			if inNamespace {
				p.next()
				if p.peek() == ";" {
					p.next()
				}
				return nil
			}
			return p.errf("unexpected }")
		case "namespace":
			p.next()
			if _, err := p.ident(); err != nil {
				return err
			}
			if err := p.expect("{"); err != nil {
				return err
			}
			if err := p.body(true); err != nil {
				return err
			}
		case ";":
			p.next()
		default:
			if err := p.definition(); err != nil {
				return err
			}
		}
	}
	if inNamespace {
		return p.errf("namespace is not closed")
	}
	return nil
}

func (p *parser) definition() error {
	start := p.tok()
	switch kw := p.next(); kw {
	case "const":
		name, err := p.ident()
		if err != nil {
			return err
		}
		if err := p.expect("="); err != nil {
			return err
		}
		v, err := p.value()
		if err != nil {
			return err
		}
		p.defs = append(p.defs, &Def{Kind: "const", Name: name, File: p.file, Cond: start.cond, Value: normNumber(v)})
		return p.expect(";")
	case "typedef":
		f, err := p.declaration("")
		if err != nil {
			return err
		}
		if f == nil {
			return p.errf("typedef void")
		}
		p.defs = append(p.defs, &Def{Kind: "typedef", Name: f.Name, File: p.file, Cond: start.cond, Type: f.Type})
		return p.expect(";")
	case "enum":
		name, err := p.ident()
		if err != nil {
			return err
		}
		d := &Def{Kind: "enum", Name: name, File: p.file, Cond: start.cond}
		if d.Members, err = p.enumBody(); err != nil {
			return err
		}
		p.defs = append(p.defs, d)
		return p.expect(";")
	case "struct":
		name, err := p.ident()
		if err != nil {
			return err
		}
		d := &Def{Kind: "struct", Name: name, File: p.file, Cond: start.cond}
		if d.Fields, err = p.structBody(name); err != nil {
			return err
		}
		p.defs = append(p.defs, d)
		return p.expect(";")
	case "union":
		name, err := p.ident()
		if err != nil {
			return err
		}
		d := &Def{Kind: "union", Name: name, File: p.file, Cond: start.cond}
		if err := p.unionBody(d, d.Name); err != nil {
			return err
		}
		p.defs = append(p.defs, d)
		return p.expect(";")
	default:
		p.pos--
		return p.errf("expected a definition, found %q", kw)
	}
}

// value parses a constant or enum value: an optionally negative decimal, hex or octal number, or a name.
func (p *parser) value() (string, error) {
	neg := ""
	if p.peek() == "-" {
		p.next()
		neg = "-"
	}
	t := p.next()
	if t == "" || t == ";" || t == "," || t == "}" {
		p.pos--
		return "", p.errf("expected a value, found %q", t)
	}
	return neg + t, nil
}

func (p *parser) enumBody() ([]Member, error) {
	if err := p.expect("{"); err != nil {
		return nil, err
	}
	var ms []Member
	for {
		switch p.peek() {
		case "}":
			p.next()
			return ms, nil
		case ",":
			p.next()
			continue
		}
		start := p.tok()
		name, err := p.ident()
		if err != nil {
			return nil, err
		}
		if err := p.expect("="); err != nil {
			return nil, err
		}
		raw, err := p.value()
		if err != nil {
			return nil, err
		}
		m := Member{Name: name, Cond: start.cond}
		if v, err := strconv.ParseInt(raw, 0, 64); err == nil {
			m.Value = v
		} else {
			// A name (another enum's member or a constant): resolved by NewSet, which sees every file.
			m.raw = raw
		}
		ms = append(ms, m)
	}
}

func (p *parser) structBody(parent string) ([]Field, error) {
	if err := p.expect("{"); err != nil {
		return nil, err
	}
	var fs []Field
	for p.peek() != "}" {
		if p.pos >= len(p.toks) {
			return nil, p.errf("struct %s is not closed", parent)
		}
		f, err := p.declaration(parent)
		if err != nil {
			return nil, err
		}
		if f == nil {
			return nil, p.errf("void field in struct %s", parent)
		}
		fs = append(fs, *f)
		if err := p.expect(";"); err != nil {
			return nil, err
		}
	}
	p.next()
	return fs, nil
}

// normNumber writes a numeric constant in decimal (hex masks such as 0x7 compare equal to 7); a name is kept.
func normNumber(v string) string {
	if n, err := strconv.ParseInt(v, 0, 64); err == nil {
		return strconv.FormatInt(n, 10)
	}
	return v
}

// unionBody parses `switch (disc) { arms }`. Anonymous types declared in an arm are named after armParent:
// the union itself when it is named, the enclosing definition when it is anonymous (rs-stellar-xdr names
// the `v1` arm struct of `ContractCodeEntry.ext` `ContractCodeEntryV1`, not `ContractCodeEntryExtV1`).
func (p *parser) unionBody(d *Def, armParent string) error {
	if err := p.expect("switch"); err != nil {
		return err
	}
	if err := p.expect("("); err != nil {
		return err
	}
	disc, err := p.declaration(d.Name)
	if err != nil {
		return err
	}
	if disc == nil {
		return p.errf("union %s: void discriminant", d.Name)
	}
	d.Disc = disc
	if err := p.expect(")"); err != nil {
		return err
	}
	if err := p.expect("{"); err != nil {
		return err
	}
	for p.peek() != "}" {
		if p.pos >= len(p.toks) {
			return p.errf("union %s is not closed", d.Name)
		}
		var arm Arm
		arm.Cond = p.tok().cond
		for p.peek() == "case" || p.peek() == "default" {
			ct := p.tok()
			if p.next() == "default" {
				arm.Cases = append(arm.Cases, Case{Default: true, Cond: ct.cond})
			} else {
				raw, err := p.value()
				if err != nil {
					return err
				}
				c := Case{Cond: ct.cond}
				if v, err := strconv.ParseInt(raw, 0, 64); err == nil {
					c.Value = v
				} else {
					c.Label = raw
				}
				arm.Cases = append(arm.Cases, c)
			}
			if err := p.expect(":"); err != nil {
				return err
			}
		}
		if len(arm.Cases) == 0 {
			return p.errf("union %s: expected case or default, found %q", d.Name, p.peek())
		}
		// The arm's own condition is the one in force at its declaration; its cases keep theirs.
		arm.Cond = p.tok().cond
		f, err := p.declaration(armParent)
		if err != nil {
			return err
		}
		if f != nil {
			arm.Name, arm.Type = f.Name, f.Type
		}
		if err := p.expect(";"); err != nil {
			return err
		}
		d.Arms = append(d.Arms, arm)
	}
	p.next()
	return nil
}

// declaration parses `void`, `T name`, `T name[N]`, `T name<N>`, `T *name`, `opaque name[N]`,
// `opaque name<N>`, `string name<N>`. An anonymous struct or union as T becomes a definition named
// parent + UpperCamel(name). Returns nil for void.
func (p *parser) declaration(parent string) (*Field, error) {
	start := p.tok()
	if p.peek() == "void" {
		p.next()
		return nil, nil
	}
	var base *Type
	var anon *Def
	// Types nested in an anonymous type are named after it, whose name is known only after its body.
	placeholder := fmt.Sprintf("\x00%d.", p.pos)
	switch kw := p.next(); kw {
	case "opaque", "string":
		name, err := p.ident()
		if err != nil {
			return nil, err
		}
		open := p.next()
		size, err := p.size(open)
		if err != nil {
			return nil, err
		}
		t := &Type{Kind: "opaque_var", Size: size}
		switch {
		case kw == "opaque" && open == "[":
			t.Kind = "opaque_fixed"
		case kw == "string" && open == "<":
			t.Kind = "string"
		case kw == "string":
			return nil, p.errf("string %s needs <N>", name)
		}
		return &Field{Name: name, Type: t, Cond: start.cond}, nil
	case "unsigned":
		switch p.peek() {
		case "int":
			p.next()
			base = &Type{Kind: "uint"}
		case "hyper":
			p.next()
			base = &Type{Kind: "uhyper"}
		default:
			base = &Type{Kind: "uint"}
		}
	case "int", "hyper", "bool", "float", "double", "quadruple":
		base = &Type{Kind: kw}
	case "struct":
		anon = &Def{Kind: "struct", File: p.file, Cond: start.cond}
		fs, err := p.structBody(placeholder)
		if err != nil {
			return nil, err
		}
		anon.Fields = fs
	case "union":
		anon = &Def{Kind: "union", File: p.file, Cond: start.cond, Name: placeholder}
		if err := p.unionBody(anon, parent); err != nil {
			return nil, err
		}
	case "enum":
		anon = &Def{Kind: "enum", File: p.file, Cond: start.cond}
		ms, err := p.enumBody()
		if err != nil {
			return nil, err
		}
		anon.Members = ms
	default:
		if kw == "" || !isIdentStart(kw[0]) {
			p.pos--
			return nil, p.errf("expected a type, found %q", kw)
		}
		base = &Type{Kind: "ref", Name: kw}
	}
	optional := false
	if p.peek() == "*" {
		p.next()
		optional = true
	}
	name, err := p.ident()
	if err != nil {
		return nil, err
	}
	if anon != nil {
		anon.Name = parent + upperCamel(name)
		if parent == "" {
			anon.Name = name
		}
		p.defs = append(p.defs, anon)
		p.renameNested(placeholder, anon.Name)
		base = &Type{Kind: "ref", Name: anon.Name}
	}
	t := base
	switch p.peek() {
	case "[", "<":
		open := p.next()
		size, err := p.size(open)
		if err != nil {
			return nil, err
		}
		kind := "var_array"
		if open == "[" {
			kind = "array"
		}
		t = &Type{Kind: kind, Elem: base, Size: size}
	}
	if optional {
		t = &Type{Kind: "optional", Elem: t}
	}
	return &Field{Name: name, Type: t, Cond: start.cond}, nil
}

// renameNested replaces the placeholder prefix of nested anonymous types with their parent's real name, in
// their definitions and in every reference to them.
func (p *parser) renameNested(placeholder, name string) {
	fix := func(t *Type) {
		for ; t != nil; t = t.Elem {
			if t.Kind == "ref" && strings.HasPrefix(t.Name, placeholder) {
				t.Name = name + t.Name[len(placeholder):]
			}
		}
	}
	for _, d := range p.defs {
		if strings.HasPrefix(d.Name, placeholder) {
			d.Name = name + d.Name[len(placeholder):]
		}
		fix(d.Type)
		for i := range d.Fields {
			fix(d.Fields[i].Type)
		}
		if d.Disc != nil {
			fix(d.Disc.Type)
		}
		for i := range d.Arms {
			fix(d.Arms[i].Type)
		}
	}
}

// size parses the bound after `[` or `<` up to the closing bracket; empty for `<>`.
func (p *parser) size(open string) (string, error) {
	closer := map[string]string{"[": "]", "<": ">"}[open]
	if closer == "" {
		p.pos--
		return "", p.errf("expected [ or <, found %q", open)
	}
	if p.peek() == closer {
		p.next()
		if open == "[" {
			return "", p.errf("fixed size missing")
		}
		return "", nil
	}
	s := p.next()
	if err := p.expect(closer); err != nil {
		return "", err
	}
	return s, nil
}

// upperCamel converts a field name the way rs-stellar-xdr's generator does (heck's UpperCamelCase): words
// split at underscores, at a lower-to-upper change and before the last capital of an acronym followed by a
// lower-case letter; each word capitalised, the rest of it lower-cased.
func upperCamel(s string) string {
	var words []string
	cur := []rune{}
	rs := []rune(s)
	flush := func() {
		if len(cur) > 0 {
			words = append(words, string(cur))
			cur = cur[:0]
		}
	}
	for i, r := range rs {
		if r == '_' || r == '-' {
			flush()
			continue
		}
		if i > 0 && len(cur) > 0 {
			prev := rs[i-1]
			if unicode.IsUpper(r) && (unicode.IsLower(prev) || unicode.IsDigit(prev)) {
				flush()
			} else if unicode.IsUpper(r) && unicode.IsUpper(prev) && i+1 < len(rs) && unicode.IsLower(rs[i+1]) {
				flush()
			}
		}
		cur = append(cur, r)
	}
	flush()
	var b strings.Builder
	for _, w := range words {
		r := []rune(strings.ToLower(w))
		r[0] = unicode.ToUpper(r[0])
		b.WriteString(string(r))
	}
	return b.String()
}

// ParseDir parses every *.x file of a directory (not recursive), in name order.
func ParseDir(dir string) (*Set, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.x"))
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("%s: no .x files", dir)
	}
	sort.Strings(files)
	var all []*Def
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		defs, err := ParseFile(filepath.Base(f), string(b))
		if err != nil {
			return nil, err
		}
		all = append(all, defs...)
	}
	return NewSet(all)
}

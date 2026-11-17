package framework

// Inline directives.
//
//	//xdrlint:ignore XDR201 <reason>            one rule
//	//xdrlint:ignore XDR101,XDR102 -- <reason>  several rules; a leading "--" is dropped
//	//xdrlint:sink participant                  marks a function or field as a sink (used by rules)
//
// An ignore directive applies to
//
//   - the line it is on, when it trails code;
//   - when it stands on its own line, that line and the first line after its
//     comment block (so it may sit directly above the reported statement);
//   - when it is in a function's doc comment, the whole function.
//
// The reason is mandatory. A directive without one, naming an unknown rule,
// written with a space after "//", or with an unknown verb, is reported as
// XDR000 and suppresses nothing. A valid directive that suppresses no report
// of a rule that ran is also XDR000.
//
// Inside golangci-lint, `//nolint:xdrlint // <reason>` is golangci-lint's own
// mechanism; the framework does not interpret it.

import (
	"go/ast"
	"go/token"
	"os"
	"regexp"
	"strings"
)

// Directive is one parsed //xdrlint: comment.
type Directive struct {
	Pos     token.Pos
	Verb    string   // "ignore", "sink", or what was written
	Rules   []string // ignore: the rule IDs named
	Arg     string   // sink: the sink kind
	Reason  string   // ignore: the reason
	Problem string   // non-empty: malformed; it suppresses nothing

	fromLine, toLine int       // line scope (inclusive), when not function-scoped
	fnFrom, fnTo     token.Pos // function scope
	file             *token.File
}

// Covers reports whether the directive applies to a report at pos.
func (d *Directive) Covers(fset *token.FileSet, pos token.Pos) bool {
	if d.fnFrom.IsValid() {
		return d.fnFrom <= pos && pos < d.fnTo
	}
	if d.file == nil || fset.File(pos) != d.file {
		return false
	}
	line := d.file.Line(pos)
	return d.fromLine <= line && line <= d.toLine
}

var (
	directivePrefix = "//xdrlint:"
	spacedDirective = regexp.MustCompile(`^//\s+xdrlint:`)
)

// ParseDirectives returns every //xdrlint: directive in files. readFile
// supplies file contents (to tell a trailing comment from one on its own
// line); it may be nil.
func ParseDirectives(fset *token.FileSet, files []*ast.File, readFile func(string) ([]byte, error)) []*Directive {
	if readFile == nil {
		readFile = os.ReadFile
	}
	var out []*Directive
	for _, f := range files {
		tf := fset.File(f.Pos())
		if tf == nil {
			continue
		}
		docOf := map[*ast.CommentGroup]*ast.FuncDecl{}
		for _, decl := range f.Decls {
			if fd, ok := decl.(*ast.FuncDecl); ok && fd.Doc != nil {
				docOf[fd.Doc] = fd
			}
		}
		var content []byte
		loaded := false
		for _, group := range f.Comments {
			for _, c := range group.List {
				d := parseComment(c)
				if d == nil {
					continue
				}
				d.file = tf
				if fd, ok := docOf[group]; ok {
					d.fnFrom, d.fnTo = fd.Pos(), fd.End()
				} else {
					if !loaded {
						content, _ = readFile(tf.Name())
						loaded = true
					}
					line := tf.Line(c.Pos())
					d.fromLine, d.toLine = line, line
					if standalone(tf, content, c.Pos()) {
						d.toLine = tf.Line(group.End()) + 1
					}
				}
				out = append(out, d)
			}
		}
	}
	return out
}

func parseComment(c *ast.Comment) *Directive {
	text := c.Text
	if spacedDirective.MatchString(text) {
		return &Directive{Pos: c.Pos(), Verb: "?", Problem: `malformed directive: write "//xdrlint:" with no space after "//"`}
	}
	rest, ok := strings.CutPrefix(text, directivePrefix)
	if !ok {
		return nil
	}
	d := &Directive{Pos: c.Pos()}
	verb, args, _ := strings.Cut(rest, " ")
	d.Verb = verb
	args = strings.TrimSpace(args)
	switch verb {
	case "ignore":
		ids, reason, _ := strings.Cut(args, " ")
		if ids == "" {
			d.Problem = "ignore directive names no rule"
			return d
		}
		d.Rules = strings.Split(ids, ",")
		for _, id := range d.Rules {
			if !ruleIDPattern.MatchString(id) {
				d.Problem = "ignore directive: " + quote(id) + " is not a rule ID (XDRnnn)"
				return d
			}
		}
		reason = strings.TrimSpace(reason)
		reason = strings.TrimSpace(strings.TrimPrefix(reason, "--"))
		d.Reason = reason
		if d.Reason == "" {
			d.Problem = "suppression of " + strings.Join(d.Rules, ",") + " has no reason"
		}
	case "sink":
		d.Arg = args
		if args == "" {
			d.Problem = "sink directive names no sink kind"
		}
	default:
		d.Problem = "unknown directive " + quote("//xdrlint:"+verb)
	}
	return d
}

func quote(s string) string { return "\"" + s + "\"" }

// standalone reports whether only blanks precede pos on its line.
func standalone(tf *token.File, content []byte, pos token.Pos) bool {
	if content == nil {
		return false
	}
	start := tf.Offset(tf.LineStart(tf.Line(pos)))
	end := tf.Offset(pos)
	if start < 0 || end > len(content) || start > end {
		return false
	}
	return strings.TrimSpace(string(content[start:end])) == ""
}

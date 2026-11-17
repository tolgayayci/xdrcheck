package framework

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"

	"golang.org/x/tools/go/analysis"
)

// Spec describes one rule analyzer. An analyzer may implement several rule
// IDs of one family (the rule set groups XDR1xx, XDR2xx and XDR3xx into three
// analyzers); each ID is declared in Rules.
type Spec struct {
	Name             string // analyzer name, a Go identifier ("caps")
	Doc              string // first line is the summary
	Rules            []Rule
	Requires         []*analysis.Analyzer
	FactTypes        []analysis.Fact
	RunDespiteErrors bool
	// Run does the analysis. It reports through Pass.Report / Pass.Reportf
	// (or the embedded analysis.Pass.Report with Category set to the rule
	// ID; both go through the framework). Its return value is available to
	// dependent analyzers through ResultOf.
	Run func(*Pass) (any, error)
}

// Report is one report of a rule.
type Report struct {
	Rule           string
	Pos, End       token.Pos
	Message        string   // one sentence, without the rule ID
	Severity       Severity // "" = the rule's default; the configuration still overrides
	Assumption     string   // "" = the rule's default key; else a registered key
	Related        []analysis.RelatedInformation
	SuggestedFixes []analysis.SuggestedFix
}

// Finding is a report after the framework processed it. Suppressed findings
// are kept; they are not printed but are written by `-report`.
type Finding struct {
	Rule        string
	Severity    Severity
	Message     string         // without the "XDRnnn (severity): " prefix
	Assumption  string         // registered assumption key (RegisterAssumption)
	Position    token.Position // absolute file name
	File        string         // relative to the module root (or to the working directory), slash-separated
	Function    string         // enclosing declared function: "F" or "Type.Method"; "" at package level
	Suppressed  bool
	Suppression *SuppressionRef // set when Suppressed
}

// SuppressionRef says what suppressed a finding.
type SuppressionRef struct {
	Kind    string // "inline" or "file"
	Reason  string
	Finding string // finding record ID (external entries only)
	Source  string // file:line of the directive or the entry
}

// Result is the result every framework analyzer returns.
type Result struct {
	Findings         []Finding
	RulesRun         []string                      // rule IDs enabled for this package
	UsedDirectives   map[token.Pos]map[string]bool // ignore directive → rule IDs it suppressed
	UsedSuppressions map[string]bool               // external entries (Suppression.Key) that matched
	Value            any                           // what Spec.Run returned
}

// ResultOf returns what Spec.Run of a required framework analyzer returned.
func ResultOf(pass *analysis.Pass, a *analysis.Analyzer) any {
	if r, ok := pass.ResultOf[a].(*Result); ok {
		return r.Value
	}
	return pass.ResultOf[a]
}

var resultType = reflect.TypeOf((*Result)(nil))

// Registry holds the rules and analyzers of one build of xdrlint.
type Registry struct {
	mu        sync.Mutex
	rules     map[string]Rule
	analyzers []*analysis.Analyzer
	byRule    map[string]*analysis.Analyzer
	xdr000    *analysis.Analyzer
	sealed    bool

	config   *Config            // set by the driver; nil = load per package directory
	cfgCache map[string]*Config // directory → configuration, when config is nil
}

// NewRegistry returns an empty registry that already knows XDR000.
func NewRegistry() *Registry {
	return &Registry{
		rules:    map[string]Rule{XDR000.ID: XDR000},
		byRule:   map[string]*analysis.Analyzer{},
		cfgCache: map[string]*Config{},
	}
}

// Default is the registry the xdrlint command uses. Rule packages register
// into it from init functions; cmd/xdrlint imports them.
var Default = NewRegistry()

// Register adds a rule analyzer to the Default registry.
func Register(s Spec) *analysis.Analyzer { return Default.Register(s) }

// Analyzers returns every analyzer of the Default registry, XDR000 last.
func Analyzers() []*analysis.Analyzer { return Default.Analyzers() }

// SetConfig sets the configuration of the Default registry.
func SetConfig(c *Config) { Default.SetConfig(c) }

// Register builds the analyzer for s and adds it with its rules. It panics on
// a malformed spec (a programming error, found by any test that imports the
// rule package) or when called after Analyzers.
func (reg *Registry) Register(s Spec) *analysis.Analyzer {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	if reg.sealed {
		panic("framework: Register called after Analyzers")
	}
	if s.Name == "" || s.Run == nil || len(s.Rules) == 0 {
		panic(fmt.Sprintf("framework: analyzer %q needs a name, a Run function and at least one rule", s.Name))
	}
	for _, r := range s.Rules {
		if err := r.validate(); err != nil {
			panic("framework: " + err.Error())
		}
		if _, dup := reg.rules[r.ID]; dup {
			panic("framework: rule " + r.ID + " registered twice")
		}
	}
	a := reg.newAnalyzer(s)
	for _, r := range s.Rules {
		reg.rules[r.ID] = r
		reg.byRule[r.ID] = a
	}
	reg.analyzers = append(reg.analyzers, a)
	return a
}

// Analyzers returns the registered analyzers followed by the XDR000
// analyzer, which requires all of them. After the first call the registry
// accepts no more registrations.
func (reg *Registry) Analyzers() []*analysis.Analyzer {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	if !reg.sealed {
		reg.sealed = true
		reg.xdr000 = reg.newAnalyzer(Spec{
			Name:     "xdr000",
			Doc:      "XDR000: " + XDR000.Title,
			Rules:    []Rule{XDR000},
			Requires: slices.Clone(reg.analyzers),
			Run:      reg.runXDR000,
		})
	}
	return append(slices.Clone(reg.analyzers), reg.xdr000)
}

// Directive returns the XDR000 analyzer.
func (reg *Registry) Directive() *analysis.Analyzer {
	reg.Analyzers()
	return reg.xdr000
}

// Rule returns the metadata of a registered rule, or nil.
func (reg *Registry) Rule(id string) *Rule {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	if r, ok := reg.rules[id]; ok {
		return &r
	}
	return nil
}

// Rules returns every registered rule, ordered by ID.
func (reg *Registry) Rules() []Rule {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	var out []Rule
	for _, r := range reg.rules {
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b Rule) int { return strings.Compare(a.ID, b.ID) })
	return out
}

// SetConfig fixes the configuration for every package. Without it, each
// package loads its own: XDRLINT_PROFILE / XDRLINT_CONFIG / XDRLINT_OVERLAY,
// else .xdrlint.yml found from the package directory up to its module root.
func (reg *Registry) SetConfig(c *Config) {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	reg.config = c
}

func (reg *Registry) configFor(pass *analysis.Pass) (*Config, error) {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	if reg.config != nil {
		return reg.config, nil
	}
	dir := ""
	if len(pass.Files) > 0 {
		dir = filepath.Dir(pass.Fset.File(pass.Files[0].Pos()).Name())
	}
	if c, ok := reg.cfgCache[dir]; ok {
		return c, nil
	}
	opts := LoadOptions{
		Profile:      os.Getenv(EnvProfile),
		ConfigFile:   os.Getenv(EnvConfig),
		OverlayDir:   os.Getenv(EnvOverlay),
		DiscoverFrom: dir,
	}
	c, err := Load(opts)
	if err == nil {
		err = c.validate(func(id string) bool { _, ok := reg.rules[id]; return ok })
	}
	if err != nil {
		return nil, fmt.Errorf("xdrlint configuration: %w", err)
	}
	reg.cfgCache[dir] = c
	return c, nil
}

func (reg *Registry) newAnalyzer(s Spec) *analysis.Analyzer {
	rules := slices.Clone(s.Rules)
	return &analysis.Analyzer{
		Name:             s.Name,
		Doc:              s.Doc,
		Requires:         s.Requires,
		FactTypes:        s.FactTypes,
		RunDespiteErrors: s.RunDespiteErrors,
		ResultType:       resultType,
		Run: func(pass *analysis.Pass) (any, error) {
			cfg, err := reg.configFor(pass)
			if err != nil {
				return nil, err
			}
			if err := cfg.CheckNames(PackageLookup([]*types.Package{pass.Pkg}, cfg.XDRPackageAliases)); err != nil {
				return nil, fmt.Errorf("xdrlint configuration: %w", err)
			}
			res := &Result{UsedDirectives: map[token.Pos]map[string]bool{}, UsedSuppressions: map[string]bool{}}
			p := &Pass{cfg: cfg, rules: map[string]Rule{}, res: res, report: pass.Report}
			for _, r := range rules {
				p.rules[r.ID] = r
				if cfg.Enabled(r) {
					res.RulesRun = append(res.RulesRun, r.ID)
				}
			}
			if len(res.RulesRun) == 0 {
				return res, nil
			}
			inner := *pass
			inner.Report = func(d analysis.Diagnostic) {
				p.Report(Report{Rule: d.Category, Pos: d.Pos, End: d.End, Message: d.Message,
					Related: d.Related, SuggestedFixes: d.SuggestedFixes})
			}
			p.Pass = &inner
			v, err := s.Run(p)
			res.Value = v
			return res, err
		},
	}
}

// Pass is what a rule's Run function receives: the analysis pass plus the
// configuration and the framework's reporting.
type Pass struct {
	*analysis.Pass
	cfg    *Config
	rules  map[string]Rule
	res    *Result
	report func(analysis.Diagnostic) // the driver's Report

	directives []*Directive
	parsed     bool
	lines      map[string][]string
}

// Config returns the configuration in force (never nil).
func (p *Pass) Config() *Config { return p.cfg }

// Enabled reports whether rule id is declared by this analyzer and enabled.
func (p *Pass) Enabled(id string) bool {
	r, ok := p.rules[id]
	return ok && p.cfg.Enabled(r)
}

// Reportf reports rule id at rng with a formatted message.
func (p *Pass) Reportf(id string, rng analysis.Range, format string, args ...any) {
	p.Report(Report{Rule: id, Pos: rng.Pos(), End: rng.End(), Message: fmt.Sprintf(format, args...)})
}

// Report processes one report: enablement, severity, location, suppression.
// Reporting a rule the analyzer did not declare panics.
func (p *Pass) Report(rep Report) {
	r, ok := p.rules[rep.Rule]
	if !ok {
		panic(fmt.Sprintf("framework: analyzer %s reported undeclared rule %q", p.Analyzer.Name, rep.Rule))
	}
	if !p.cfg.Enabled(r) {
		return
	}
	posn := p.Fset.Position(rep.Pos)
	assume := rep.Assumption
	if assume == "" {
		assume = r.Assumption
	}
	if _, ok := LookupAssumption(assume); !ok {
		panic(fmt.Sprintf("framework: rule %s reported unregistered assumption %q", r.ID, assume))
	}
	f := Finding{
		Rule:       r.ID,
		Severity:   p.cfg.SeverityOf(r, rep.Severity),
		Message:    rep.Message,
		Assumption: assume,
		Position:   posn,
		File:       ModuleRelPath(posn.Filename),
		Function:   EnclosingFunction(p.Fset, p.Files, rep.Pos),
	}
	if r.ID != XDR000.ID {
		f.Suppression = p.suppress(r.ID, rep.Pos, f)
		f.Suppressed = f.Suppression != nil
	}
	p.res.Findings = append(p.res.Findings, f)
	if f.Suppressed {
		return
	}
	p.report(analysis.Diagnostic{
		Pos:            rep.Pos,
		End:            rep.End,
		Category:       r.ID,
		Message:        prefix(r.ID, f.Severity) + rep.Message,
		Related:        rep.Related,
		SuggestedFixes: rep.SuggestedFixes,
	})
}

// Directives returns the //xdrlint: directives of the package's files.
func (p *Pass) Directives() []*Directive {
	if !p.parsed {
		p.parsed = true
		p.directives = ParseDirectives(p.Fset, p.Files, p.ReadFile)
	}
	return p.directives
}

func (p *Pass) suppress(id string, pos token.Pos, f Finding) *SuppressionRef {
	for _, d := range p.Directives() {
		if d.Verb != "ignore" || d.Problem != "" || !slices.Contains(d.Rules, id) || !d.Covers(p.Fset, pos) {
			continue
		}
		if p.res.UsedDirectives[d.Pos] == nil {
			p.res.UsedDirectives[d.Pos] = map[string]bool{}
		}
		p.res.UsedDirectives[d.Pos][id] = true
		dp := p.Fset.Position(d.Pos)
		return &SuppressionRef{Kind: "inline", Reason: d.Reason, Source: fmt.Sprintf("%s:%d", ModuleRelPath(dp.Filename), dp.Line)}
	}
	if s := p.cfg.matchSuppression(id, f.File, f.Function, f.Position.Line, p.lineText(f.Position), f.Message); s != nil {
		p.res.UsedSuppressions[s.Key()] = true
		return &SuppressionRef{Kind: "file", Reason: s.Reason, Finding: s.Finding, Source: s.Key()}
	}
	return nil
}

func (p *Pass) lineText(posn token.Position) string {
	if p.lines == nil {
		p.lines = map[string][]string{}
	}
	lines, ok := p.lines[posn.Filename]
	if !ok {
		read := p.ReadFile
		if read == nil {
			read = os.ReadFile
		}
		if data, err := read(posn.Filename); err == nil {
			lines = strings.Split(string(data), "\n")
		}
		p.lines[posn.Filename] = lines
	}
	if posn.Line >= 1 && posn.Line <= len(lines) {
		return lines[posn.Line-1]
	}
	return ""
}

// EnclosingFunction names the declared function containing pos: "F" for a
// function, "Type.Method" for a method (pointer or value receiver), and ""
// outside any function. Function literals belong to their declared function.
func EnclosingFunction(fset *token.FileSet, files []*ast.File, pos token.Pos) string {
	for _, f := range files {
		if pos < f.FileStart || pos > f.FileEnd {
			continue
		}
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || pos < fd.Pos() || pos >= fd.End() {
				continue
			}
			if fd.Recv != nil && len(fd.Recv.List) == 1 {
				if t := recvTypeName(fd.Recv.List[0].Type); t != "" {
					return t + "." + fd.Name.Name
				}
			}
			return fd.Name.Name
		}
	}
	return ""
}

func recvTypeName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.StarExpr:
		return recvTypeName(t.X)
	case *ast.ParenExpr:
		return recvTypeName(t.X)
	case *ast.IndexExpr:
		return recvTypeName(t.X)
	case *ast.IndexListExpr:
		return recvTypeName(t.X)
	case *ast.Ident:
		return t.Name
	}
	return ""
}

var (
	moduleRootMu    sync.Mutex
	moduleRootCache = map[string]string{}
)

// ModuleRelPath returns filename relative to the root of its module (the
// nearest directory above it holding a go.mod), slash-separated. Without a
// module it is relative to the working directory when inside it.
func ModuleRelPath(filename string) string {
	if filename == "" {
		return ""
	}
	abs, err := filepath.Abs(filename)
	if err != nil {
		return filepath.ToSlash(filename)
	}
	root := moduleRoot(filepath.Dir(abs))
	if root == "" {
		return displayPath(abs)
	}
	rel, err := filepath.Rel(root, abs)
	if err != nil {
		return filepath.ToSlash(abs)
	}
	return filepath.ToSlash(rel)
}

func moduleRoot(dir string) string {
	moduleRootMu.Lock()
	defer moduleRootMu.Unlock()
	if r, ok := moduleRootCache[dir]; ok {
		return r
	}
	root := ""
	for d := dir; ; {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			root = d
			break
		}
		parent := filepath.Dir(d)
		if parent == d {
			break
		}
		d = parent
	}
	moduleRootCache[dir] = root
	return root
}

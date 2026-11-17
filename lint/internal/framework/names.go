package framework

// Validation of the qualified names a configuration lists (sinks,
// sanitisers, budget methods, halting functions, overflow markers, ingest
// entry points). A name is `<import path>.<Name>` or
// `<import path>.<Type>.<Field|Method>`. It can be checked only where its
// package is loaded: the standalone command checks it against every package
// it loaded, and each analysis pass against the package under analysis and
// the packages it imports. A name whose package is loaded but which does
// not resolve there is an error; a name whose package is not loaded is
// skipped. A bare identifier (allowed for overflowflags and haltingfuncs,
// which also match by plain name) is not checked.

import (
	"fmt"
	"go/types"
	"sort"
	"strings"

	"github.com/tolgayayci/xdrcheck/lint/internal/catalogue"
)

// qualifiedNames returns every configured name that names a package, keyed
// by name, with the configuration key it came from.
func (c *Config) qualifiedNames() map[string]string {
	out := map[string]string{}
	for key, list := range map[string][]string{
		"sinksparticipant": c.SinksParticipant, "sinksaccountkey": c.SinksAccountKey, "sinkstext": c.SinksText,
		"sinksmovement": c.SinksMovement, "sanitizersaddress": c.SanitizersAddress, "sanitizerstext": c.SanitizersText,
		"sanitizersevent": c.SanitizersEvent, "budgetmethods": c.BudgetMethods, "haltingfuncs": c.HaltingFuncs,
		"overflowflags": c.OverflowFlags, "ingestentrypoints": c.IngestEntryPoints,
	} {
		for _, n := range list {
			if strings.Contains(n, ".") {
				out[n] = key
			}
		}
	}
	return out
}

// splitName splits "a/b/pkg.T.M" into "a/b/pkg" and ["T", "M"].
func splitName(name string) (string, []string) {
	slash := strings.LastIndex(name, "/")
	dot := strings.Index(name[slash+1:], ".")
	if dot < 0 {
		return "", nil
	}
	pkg := name[:slash+1+dot]
	return pkg, strings.Split(name[slash+1+dot+1:], ".")
}

// resolveName reports whether the member path resolves in pkg.
func resolveName(pkg *types.Package, parts []string) error {
	if len(parts) == 0 || len(parts) > 2 || parts[0] == "" {
		return fmt.Errorf("want <package>.<Name> or <package>.<Type>.<Field or Method>")
	}
	obj := pkg.Scope().Lookup(parts[0])
	if obj == nil {
		return fmt.Errorf("package %s has no %s", pkg.Path(), parts[0])
	}
	if len(parts) == 1 {
		return nil
	}
	tn, ok := obj.(*types.TypeName)
	if !ok {
		return fmt.Errorf("%s.%s is not a type, so it has no member %s", pkg.Path(), parts[0], parts[1])
	}
	if o, _, _ := types.LookupFieldOrMethod(types.NewPointer(tn.Type()), true, pkg, parts[1]); o == nil {
		return fmt.Errorf("type %s.%s has no field or method %s", pkg.Path(), parts[0], parts[1])
	}
	return nil
}

// CheckNames validates the configured names against the packages lookup
// knows (by import path, after mapping xdrpackagealiases and the pre-split
// module onto the SDK's paths); names in packages it does not know are
// skipped.
func (c *Config) CheckNames(lookup func(path string) *types.Package) error {
	var errs []string
	for name, key := range c.qualifiedNames() {
		path, parts := splitName(name)
		if path == "" {
			continue
		}
		pkg := lookup(path)
		if pkg == nil {
			continue
		}
		if err := resolveName(pkg, parts); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %s: %v", key, name, err))
		}
	}
	if len(errs) == 0 {
		return nil
	}
	sort.Strings(errs)
	return fmt.Errorf("%s", strings.Join(errs, "; "))
}

// PackageLookup indexes packages and everything they import by import path,
// for CheckNames.
func PackageLookup(roots []*types.Package, xdrAliases []string) func(string) *types.Package {
	byPath := map[string]*types.Package{}
	var visit func(p *types.Package)
	visit = func(p *types.Package) {
		if p == nil {
			return
		}
		if _, seen := byPath[p.Path()]; seen {
			return
		}
		byPath[p.Path()] = p
		byPath[catalogue.Canonical(p.Path(), xdrAliases)] = p
		for _, q := range p.Imports() {
			visit(q)
		}
	}
	for _, r := range roots {
		visit(r)
	}
	return func(path string) *types.Package { return byPath[path] }
}

// LoadsSourcePackage reports whether lookup (from PackageLookup) knows the
// go-stellar-sdk xdr package, under its own path, the pre-split module path
// or a configured xdrpackagealiases path. Every rule's sources are types of
// that package or of packages built on it, so a run that has not loaded it
// analyses nothing: its silence, like the skipped names above, would say
// nothing about the code.
func LoadsSourcePackage(lookup func(path string) *types.Package) bool {
	return lookup(catalogue.XDR) != nil
}

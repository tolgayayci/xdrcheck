// Package xdrdef reads Stellar XDR definition sets (.x files, or the JSON definitions rs-stellar-xdr's
// generator writes) into one structural model, and compares two of them.
//
// The model keeps the feature gates of the .x source: every definition, enum member, struct field and union
// arm carries the `#ifdef` / `#ifndef` / `#else` conditions it was written under, so one parsed set can be
// resolved with no features (what stellar-xdr's `curr` branch holds), with every feature (`next`), or with a
// chosen list, and every difference can be traced to the gate that introduced it and that gate's CAP.
//
// Anonymous structs and unions nested in a field or a union arm become definitions of their own, named the
// way rs-stellar-xdr names them (the parent's name followed by the field or arm name in upper camel case,
// e.g. `LedgerHeaderExtensionV1Ext`, `ClaimantV0`), so arm identifiers match the ones the corpus tools use
// (`Union::CASE`, `Union::v<N>`, `Struct.field?some`).
package xdrdef

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Cond is the set of preprocessor conditions an element was written under: a feature name for `#ifdef X`,
// `!X` for `#ifndef X` or the `#else` branch of `#ifdef X`. An element is present when every one holds.
type Cond []string

// Holds reports whether the condition holds for the enabled feature set.
func (c Cond) Holds(enabled map[string]bool) bool {
	for _, x := range c {
		if strings.HasPrefix(x, "!") {
			if enabled[x[1:]] {
				return false
			}
		} else if !enabled[x] {
			return false
		}
	}
	return true
}

// Features are the feature names a condition mentions.
func (c Cond) Features() []string {
	var out []string
	for _, x := range c {
		out = append(out, strings.TrimPrefix(x, "!"))
	}
	return out
}

// Type is an XDR type expression.
type Type struct {
	// Kind is one of int, uint, hyper, uhyper, bool, float, double, quadruple, opaque_fixed, opaque_var,
	// string, array, var_array, optional, ref.
	Kind string `json:"kind"`
	// Name is the referenced definition (ref).
	Name string `json:"name,omitempty"`
	// Elem is the element type (array, var_array, optional).
	Elem *Type `json:"elem,omitempty"`
	// Size is the fixed size (opaque_fixed, array) or the maximum (opaque_var, string, var_array; empty when
	// unbounded), as written: a number or a constant's name.
	Size string `json:"size,omitempty"`
}

// String renders a type as XDR-like text, used to compare types and in reports.
func (t *Type) String() string {
	if t == nil {
		return "void"
	}
	switch t.Kind {
	case "ref":
		return t.Name
	case "uint":
		return "unsigned int"
	case "uhyper":
		return "unsigned hyper"
	case "opaque_fixed":
		return "opaque[" + t.Size + "]"
	case "opaque_var":
		return "opaque<" + t.Size + ">"
	case "string":
		return "string<" + t.Size + ">"
	case "array":
		return t.Elem.String() + "[" + t.Size + "]"
	case "var_array":
		return t.Elem.String() + "<" + t.Size + ">"
	case "optional":
		return t.Elem.String() + "*"
	}
	return t.Kind
}

// refs appends the definitions a type names.
func (t *Type) refs(out []string) []string {
	for ; t != nil; t = t.Elem {
		if t.Kind == "ref" {
			out = append(out, t.Name)
		}
	}
	return out
}

// Member is an enum member.
type Member struct {
	Name  string `json:"name"`
	Value int64  `json:"value"`
	Cond  Cond   `json:"cond,omitempty"`
	// raw is the value as written when it is a name, until NewSet resolves it.
	raw string
}

// Field is a struct field, or a union's discriminant.
type Field struct {
	Name string `json:"name"`
	Type *Type  `json:"type"`
	Cond Cond   `json:"cond,omitempty"`
}

// Case is one case label of a union arm: an enum member or constant name with its value, an integer, or
// `default`.
type Case struct {
	Label   string `json:"label,omitempty"`
	Value   int64  `json:"value"`
	Default bool   `json:"default,omitempty"`
	Cond    Cond   `json:"cond,omitempty"`
}

// Arm is a union arm: one or more case labels sharing a declaration. Type is nil for `void`.
type Arm struct {
	Cases []Case `json:"cases"`
	Name  string `json:"name,omitempty"`
	Type  *Type  `json:"type,omitempty"`
	Cond  Cond   `json:"cond,omitempty"`
}

// Def is one definition.
type Def struct {
	// Kind is const, typedef, enum, struct or union.
	Kind string `json:"kind"`
	Name string `json:"name"`
	File string `json:"file,omitempty"`
	Cond Cond   `json:"cond,omitempty"`
	// Value is a constant's value as written.
	Value string `json:"value,omitempty"`
	// Type is a typedef's type.
	Type    *Type    `json:"type,omitempty"`
	Members []Member `json:"members,omitempty"`
	Fields  []Field  `json:"fields,omitempty"`
	Disc    *Field   `json:"discriminant,omitempty"`
	Arms    []Arm    `json:"arms,omitempty"`
}

// Set is a definition set: the definitions in source order, with an index by name.
type Set struct {
	Defs   []*Def
	byName map[string]*Def
}

// NewSet indexes definitions; a later definition of a name replaces an earlier one only when their
// conditions differ (the two sides of an `#ifdef`/`#else`), otherwise the name is reported as a duplicate.
func NewSet(defs []*Def) (*Set, error) {
	s := &Set{byName: map[string]*Def{}}
	for _, d := range defs {
		if prev, ok := s.byName[d.Name]; ok && condKey(prev.Cond) == condKey(d.Cond) {
			return nil, fmt.Errorf("%s: %s is defined twice", d.File, d.Name)
		}
		s.byName[d.Name] = d
		s.Defs = append(s.Defs, d)
	}
	return s, s.resolveNames()
}

// resolveNames gives a value to enum members written as a name and to union cases labelled with one: an enum
// member (for a case, of the union's discriminant enum first) or a constant, from any file of the set.
func (s *Set) resolveNames() error {
	consts := map[string]int64{}
	members := map[string]int64{}
	for _, d := range s.Defs {
		if d.Kind == "const" {
			if v, err := strconv.ParseInt(d.Value, 0, 64); err == nil {
				consts[d.Name] = v
			}
		}
	}
	lookup := func(raw string, local map[string]int64) (int64, bool) {
		name := strings.TrimPrefix(raw, "-")
		sign := int64(1)
		if name != raw {
			sign = -1
		}
		for _, m := range []map[string]int64{local, members, consts} {
			if v, ok := m[name]; ok {
				return sign * v, true
			}
		}
		return 0, false
	}
	// Members may refer to members of enums defined later, so resolve until nothing changes.
	for pass := 0; pass < 8; pass++ {
		pending := 0
		for _, d := range s.Defs {
			if d.Kind != "enum" {
				continue
			}
			local := map[string]int64{}
			for i := range d.Members {
				m := &d.Members[i]
				if m.raw != "" {
					if v, ok := lookup(m.raw, local); ok {
						m.Value, m.raw = v, ""
					} else {
						pending++
						continue
					}
				}
				local[m.Name] = m.Value
				members[m.Name] = m.Value
			}
		}
		if pending == 0 {
			break
		}
	}
	for _, d := range s.Defs {
		for _, m := range d.Members {
			if m.raw != "" {
				return fmt.Errorf("%s: enum %s: cannot resolve %s = %s", d.File, d.Name, m.Name, m.raw)
			}
		}
		if d.Kind != "union" {
			continue
		}
		local := map[string]int64{}
		if e := s.discEnum(d); e != nil {
			for _, m := range e.Members {
				local[m.Name] = m.Value
			}
		}
		for i := range d.Arms {
			for j := range d.Arms[i].Cases {
				c := &d.Arms[i].Cases[j]
				if c.Label == "" || c.Default {
					continue
				}
				v, ok := lookup(c.Label, local)
				if !ok {
					return fmt.Errorf("%s: union %s: unknown case %s", d.File, d.Name, c.Label)
				}
				c.Value = v
			}
		}
	}
	return nil
}

// Get returns a definition by name.
func (s *Set) Get(name string) *Def { return s.byName[name] }

// Features lists every feature name any element of the set is gated on, sorted.
func (s *Set) Features() []string {
	seen := map[string]bool{}
	add := func(c Cond) {
		for _, f := range c.Features() {
			seen[f] = true
		}
	}
	for _, d := range s.Defs {
		add(d.Cond)
		for _, m := range d.Members {
			add(m.Cond)
		}
		for _, f := range d.Fields {
			add(f.Cond)
		}
		for _, a := range d.Arms {
			add(a.Cond)
			for _, c := range a.Cases {
				add(c.Cond)
			}
		}
	}
	return sortedKeys(seen)
}

// Resolve returns the set as the preprocessor would leave it with the given features enabled: elements whose
// conditions do not hold are dropped, and conditions are kept on what remains (they record the gate).
func (s *Set) Resolve(enabled map[string]bool) *Set {
	out := &Set{byName: map[string]*Def{}}
	for _, d := range s.Defs {
		if !d.Cond.Holds(enabled) {
			continue
		}
		c := *d
		c.Members, c.Fields, c.Arms = nil, nil, nil
		for _, m := range d.Members {
			if m.Cond.Holds(enabled) {
				c.Members = append(c.Members, m)
			}
		}
		for _, f := range d.Fields {
			if f.Cond.Holds(enabled) {
				c.Fields = append(c.Fields, f)
			}
		}
		for _, a := range d.Arms {
			if !a.Cond.Holds(enabled) {
				continue
			}
			na := a
			na.Cases = nil
			for _, cs := range a.Cases {
				if cs.Cond.Holds(enabled) {
					na.Cases = append(na.Cases, cs)
				}
			}
			if len(na.Cases) > 0 {
				c.Arms = append(c.Arms, na)
			}
		}
		out.Defs = append(out.Defs, &c)
		out.byName[c.Name] = &c
	}
	return out
}

// EnableAll is the feature set with every feature of s enabled.
func (s *Set) EnableAll() map[string]bool {
	m := map[string]bool{}
	for _, f := range s.Features() {
		m[f] = true
	}
	return m
}

// refs lists the definitions a definition names directly.
func (d *Def) refs() []string {
	var out []string
	out = d.Type.refs(out)
	for _, f := range d.Fields {
		out = f.Type.refs(out)
	}
	if d.Disc != nil {
		out = d.Disc.Type.refs(out)
	}
	for _, a := range d.Arms {
		out = a.Type.refs(out)
	}
	return out
}

// Reachable is the set of definitions reachable from root (root included); empty when root is not defined.
func (s *Set) Reachable(root string) map[string]bool {
	seen := map[string]bool{}
	var walk func(string)
	walk = func(n string) {
		d := s.byName[n]
		if d == nil || seen[n] {
			return
		}
		seen[n] = true
		for _, r := range d.refs() {
			walk(r)
		}
	}
	walk(root)
	return seen
}

// resolveTypedef follows typedefs to the type they name, for deciding whether a field or arm is optional.
func (s *Set) resolveTypedef(t *Type) *Type {
	for i := 0; t != nil && t.Kind == "ref" && i < 64; i++ {
		d := s.byName[t.Name]
		if d == nil || d.Kind != "typedef" {
			return t
		}
		t = d.Type
	}
	return t
}

// discEnum is the enum a union switches on, or nil for an integer discriminant.
func (s *Set) discEnum(u *Def) *Def {
	if u.Disc == nil {
		return nil
	}
	t := s.resolveTypedef(u.Disc.Type)
	if t != nil && t.Kind == "ref" {
		if d := s.byName[t.Name]; d != nil && d.Kind == "enum" {
			return d
		}
	}
	return nil
}

// CaseLabel is the arm label the corpus tools use for one case: the enum member name for an enum
// discriminant, `v<N>` for an integer one, `default` for the default arm.
func (s *Set) CaseLabel(u *Def, c Case) string {
	if c.Default {
		return "default"
	}
	if e := s.discEnum(u); e != nil {
		for _, m := range e.Members {
			if m.Value == c.Value {
				return m.Name
			}
		}
		if c.Label != "" {
			return c.Label
		}
	}
	return "v" + strconv.FormatInt(c.Value, 10)
}

// ArmIDs is the universe of arm identifiers reachable from root, as `xdrcheck-corpus coverage --arms` counts
// them: every union case (`Union::CASE`, `Union::v<N>`) and every optional state (`Struct.field?some|none`,
// `Union::CASE?some|none`).
func (s *Set) ArmIDs(root string) map[string]bool {
	out := map[string]bool{}
	for n := range s.Reachable(root) {
		d := s.byName[n]
		switch d.Kind {
		case "struct":
			for _, f := range d.Fields {
				if t := s.resolveTypedef(f.Type); t != nil && t.Kind == "optional" {
					out[d.Name+"."+f.Name+"?some"] = true
					out[d.Name+"."+f.Name+"?none"] = true
				}
			}
		case "union":
			for _, a := range d.Arms {
				for i, c := range a.Cases {
					l := s.CaseLabel(d, c)
					out[d.Name+"::"+l] = true
					if i == 0 {
						if t := s.resolveTypedef(a.Type); t != nil && t.Kind == "optional" {
							out[d.Name+"::"+l+"?some"] = true
							out[d.Name+"::"+l+"?none"] = true
						}
					}
				}
			}
		}
	}
	return out
}

// EnumMax is the highest member value of an enum, and whether the enum exists with at least one member.
func (s *Set) EnumMax(name string) (int64, bool) {
	d := s.byName[name]
	if d == nil || d.Kind != "enum" || len(d.Members) == 0 {
		return 0, false
	}
	m := d.Members[0].Value
	for _, x := range d.Members[1:] {
		if x.Value > m {
			m = x.Value
		}
	}
	return m, true
}

// FindEnumFold finds an enum by name ignoring case (SDKs spell `SCAddressType` as `ScAddressType`,
// `ConfigSettingID` as `ConfigSettingId`).
func (s *Set) FindEnumFold(name string) *Def {
	for _, d := range s.Defs {
		if d.Kind == "enum" && strings.EqualFold(d.Name, name) {
			return d
		}
	}
	return nil
}

func condKey(c Cond) string { return strings.Join(c, "&") }

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

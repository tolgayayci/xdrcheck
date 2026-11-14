package xdrdef

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// DiffSchema names the JSON report format of a structural diff.
const DiffSchema = "xcc.xdr-diff/1"

// DefaultRoots are the types whose reachability decides reader impact: what an indexer reads
// (LedgerCloseMetaBatch) and what an SDK decodes from a transaction (TransactionEnvelope).
var DefaultRoots = []string{"LedgerCloseMetaBatch", "TransactionEnvelope"}

// Side describes one input of a diff.
type Side struct {
	// Label is what the input was given as (a directory, a git ref, a definitions file).
	Label string `json:"label"`
	// Commit is the stellar-xdr commit, when the input was a git ref.
	Commit string `json:"commit,omitempty"`
	// Features are the features that were enabled when resolving the input's `#ifdef` blocks.
	Features []string `json:"features"`
	// Gates are every feature the input's source mentions, enabled or not.
	Gates []string `json:"gates"`
}

// Change is one structural difference.
type Change struct {
	// Kind is one of: type-added, type-removed, kind-changed, const-changed, typedef-type-changed,
	// typedef-optional-changed, typedef-size-changed, enum-member-added, enum-member-removed,
	// enum-value-changed, field-added, field-removed, field-type-changed, field-optional-changed,
	// field-size-changed, fields-reordered, discriminant-changed, arm-added, arm-removed, arm-changed.
	Kind    string `json:"kind"`
	Def     string `json:"type"`
	DefKind string `json:"type_kind"`
	// Member is the enum member, struct field or union case label the change is about.
	Member string `json:"member,omitempty"`
	Old    string `json:"old,omitempty"`
	New    string `json:"new,omitempty"`
	File   string `json:"file,omitempty"`
	// Gates are the `#ifdef` features the changed element is written under (directly, or because every
	// reference to a new type is); CAPs are the CAPs those gates name.
	Gates []string `json:"gates,omitempty"`
	CAPs  []string `json:"caps,omitempty"`
	// Reach lists the roots the changed type is reachable from: the readers that see the change.
	Reach []string `json:"reach,omitempty"`
	// ArmIDs are the corpus arm identifiers the change adds or removes, when it is about an arm or an
	// optional state.
	ArmIDs []string `json:"arm_ids,omitempty"`
}

// ArmRef is a union arm or optional state that one side's universe has and the other's lacks.
type ArmRef struct {
	ID    string   `json:"id"`
	Gates []string `json:"gates,omitempty"`
	CAPs  []string `json:"caps,omitempty"`
	// Class is the class `corpus/arms.toml`'s default rule gives the arm: apply-time-result for a case of a
	// union switched on a `*ResultCode` enum (validation-only when it ends in `_MALFORMED`), else in-ledger.
	Class string `json:"default_class"`
}

// Report is a structural diff of two definition sets.
type Report struct {
	Schema  string   `json:"schema"`
	Base    Side     `json:"base"`
	Head    Side     `json:"head"`
	Roots   []string `json:"roots"`
	Changes []Change `json:"changes"`
	// NewArms and RemovedArms are, per root, the arm universe of head minus that of base and the reverse:
	// the identifiers `xdrcheck-corpus coverage --arms` would count.
	NewArms     map[string][]ArmRef `json:"new_arms"`
	RemovedArms map[string][]string `json:"removed_arms"`
	// CAPGates maps each gate seen to its CAP ("" when the gate names none).
	CAPGates map[string]string `json:"cap_gates"`
}

// Empty reports whether the two sets are structurally equal.
func (r *Report) Empty() bool { return len(r.Changes) == 0 }

var capGate = regexp.MustCompile(`^CAP_?0*(\d{1,4})(?:_|$)`)

// knownGates maps gates that do not spell their CAP to it, from stellar-xdr's history.
var knownGates = map[string]string{
	"MS_CLOSE_TIME": "CAP-0088",
}

// CAPOfGate is the CAP a feature gate stands for (`CAP_0084_MUXED_CONTRACT` → `CAP-0084`), or "".
func CAPOfGate(g string) string {
	if c, ok := knownGates[g]; ok {
		return c
	}
	if m := capGate.FindStringSubmatch(g); m != nil {
		n, _ := strconv.Atoi(m[1])
		return fmt.Sprintf("CAP-%04d", n)
	}
	return ""
}

// DiffOptions tune a diff.
type DiffOptions struct {
	Roots []string
	// CAP, when set, is stamped on every change (a CAP document's own XDR diff).
	CAP string
}

// Diff compares two resolved sets. base and head are the sets as resolved for the features of each side;
// conditions kept on their elements are what the change is attributed to.
func Diff(base, head *Set, bs, hs Side, o DiffOptions) *Report {
	if len(o.Roots) == 0 {
		o.Roots = DefaultRoots
	}
	r := &Report{Schema: DiffSchema, Base: bs, Head: hs, Roots: o.Roots, Changes: []Change{},
		NewArms: map[string][]ArmRef{}, RemovedArms: map[string][]string{}, CAPGates: map[string]string{}}
	d := &differ{base: base, head: head, r: r, o: o,
		bGates: inferGates(base), hGates: inferGates(head),
		bReach: map[string]map[string]bool{}, hReach: map[string]map[string]bool{}}
	for _, root := range o.Roots {
		d.bReach[root] = base.Reachable(root)
		d.hReach[root] = head.Reachable(root)
	}
	seen := map[string]bool{}
	for _, hd := range head.Defs {
		seen[hd.Name] = true
		bd := base.Get(hd.Name)
		if bd == nil {
			d.add(Change{Kind: "type-added", Def: hd.Name, DefKind: hd.Kind, New: summary(head, hd), File: hd.File}, nil, hd.Cond, true)
			continue
		}
		d.defs(bd, hd)
	}
	for _, bd := range base.Defs {
		if !seen[bd.Name] {
			d.add(Change{Kind: "type-removed", Def: bd.Name, DefKind: bd.Kind, Old: summary(base, bd), File: bd.File}, bd.Cond, nil, false)
		}
	}
	for _, root := range o.Roots {
		bu, hu := base.ArmIDs(root), head.ArmIDs(root)
		for _, id := range sortedKeys(hu) {
			if !bu[id] {
				gates := d.armGates(id)
				r.NewArms[root] = append(r.NewArms[root], ArmRef{ID: id, Gates: gates, CAPs: d.caps(gates), Class: defaultClass(head, id)})
			}
		}
		for _, id := range sortedKeys(bu) {
			if !hu[id] {
				r.RemovedArms[root] = append(r.RemovedArms[root], id)
			}
		}
		if r.NewArms[root] == nil {
			r.NewArms[root] = []ArmRef{}
		}
		if r.RemovedArms[root] == nil {
			r.RemovedArms[root] = []string{}
		}
	}
	for _, g := range append(append([]string{}, bs.Gates...), hs.Gates...) {
		r.CAPGates[g] = CAPOfGate(g)
	}
	return r
}

type differ struct {
	base, head     *Set
	r              *Report
	o              DiffOptions
	bGates, hGates map[string]Cond
	bReach, hReach map[string]map[string]bool
}

// add records a change. bc and hc are the conditions of the element on each side (nil where it is absent);
// inHead says whether reachability is judged in head (else in base).
func (d *differ) add(c Change, bc, hc Cond, inHead bool) {
	gates := map[string]bool{}
	for _, x := range bc {
		gates[strings.TrimPrefix(x, "!")] = true
	}
	for _, x := range hc {
		gates[strings.TrimPrefix(x, "!")] = true
	}
	if inHead {
		for _, x := range d.hGates[c.Def] {
			gates[strings.TrimPrefix(x, "!")] = true
		}
	} else {
		for _, x := range d.bGates[c.Def] {
			gates[strings.TrimPrefix(x, "!")] = true
		}
	}
	c.Gates = sortedKeys(gates)
	c.CAPs = d.caps(c.Gates)
	reach := d.hReach
	if !inHead {
		reach = d.bReach
	}
	for _, root := range d.o.Roots {
		if reach[root][c.Def] {
			c.Reach = append(c.Reach, root)
		}
	}
	d.r.Changes = append(d.r.Changes, c)
}

func (d *differ) caps(gates []string) []string {
	if d.o.CAP != "" {
		return []string{d.o.CAP}
	}
	set := map[string]bool{}
	for _, g := range gates {
		if c := CAPOfGate(g); c != "" {
			set[c] = true
		}
	}
	return sortedKeys(set)
}

func (d *differ) defs(bd, hd *Def) {
	base, head := d.base, d.head
	ch := func(kind, member, old, new string, bc, hc Cond) {
		d.add(Change{Kind: kind, Def: hd.Name, DefKind: hd.Kind, Member: member, Old: old, New: new, File: hd.File}, bc, hc, true)
	}
	if bd.Kind != hd.Kind {
		ch("kind-changed", "", bd.Kind, hd.Kind, bd.Cond, hd.Cond)
		return
	}
	switch hd.Kind {
	case "const":
		if bd.Value != hd.Value {
			ch("const-changed", "", bd.Value, hd.Value, bd.Cond, hd.Cond)
		}
	case "typedef":
		if k := typeChange(base, head, bd.Type, hd.Type); k != "" {
			ch("typedef-"+k, "", bd.Type.String(), hd.Type.String(), bd.Cond, hd.Cond)
		}
	case "enum":
		bm := map[string]Member{}
		for _, m := range bd.Members {
			bm[m.Name] = m
		}
		hm := map[string]bool{}
		for _, m := range hd.Members {
			hm[m.Name] = true
			o, ok := bm[m.Name]
			switch {
			case !ok:
				ch("enum-member-added", m.Name, "", strconv.FormatInt(m.Value, 10), nil, m.Cond)
			case o.Value != m.Value:
				ch("enum-value-changed", m.Name, strconv.FormatInt(o.Value, 10), strconv.FormatInt(m.Value, 10), o.Cond, m.Cond)
			}
		}
		for _, m := range bd.Members {
			if !hm[m.Name] {
				d.add(Change{Kind: "enum-member-removed", Def: hd.Name, DefKind: "enum", Member: m.Name, Old: strconv.FormatInt(m.Value, 10), File: hd.File}, m.Cond, nil, false)
			}
		}
	case "struct":
		bf := map[string]Field{}
		var bOrder []string
		for _, f := range bd.Fields {
			bf[f.Name] = f
			bOrder = append(bOrder, f.Name)
		}
		hf := map[string]bool{}
		var hOrder []string
		for _, f := range hd.Fields {
			hf[f.Name] = true
			o, ok := bf[f.Name]
			if !ok {
				c := Change{Kind: "field-added", Def: hd.Name, DefKind: "struct", Member: f.Name, New: f.Type.String(), File: hd.File}
				if t := head.resolveTypedef(f.Type); t != nil && t.Kind == "optional" {
					c.ArmIDs = []string{hd.Name + "." + f.Name + "?some", hd.Name + "." + f.Name + "?none"}
				}
				d.add(c, nil, f.Cond, true)
				continue
			}
			hOrder = append(hOrder, f.Name)
			if k := typeChange(base, head, o.Type, f.Type); k != "" {
				c := Change{Kind: "field-" + k, Def: hd.Name, DefKind: "struct", Member: f.Name, Old: o.Type.String(), New: f.Type.String(), File: hd.File}
				if k == "optional-changed" {
					c.ArmIDs = []string{hd.Name + "." + f.Name + "?some", hd.Name + "." + f.Name + "?none"}
				}
				d.add(c, o.Cond, f.Cond, true)
			}
		}
		var common []string
		for _, n := range bOrder {
			if hf[n] {
				common = append(common, n)
			}
		}
		if strings.Join(common, ",") != strings.Join(hOrder, ",") {
			ch("fields-reordered", "", strings.Join(common, ", "), strings.Join(hOrder, ", "), bd.Cond, hd.Cond)
		}
		for _, f := range bd.Fields {
			if !hf[f.Name] {
				d.add(Change{Kind: "field-removed", Def: hd.Name, DefKind: "struct", Member: f.Name, Old: f.Type.String(), File: hd.File}, f.Cond, nil, false)
			}
		}
	case "union":
		if k := typeChange(base, head, bd.Disc.Type, hd.Disc.Type); k != "" {
			ch("discriminant-changed", bd.Disc.Name, bd.Disc.Type.String(), hd.Disc.Type.String(), bd.Cond, hd.Cond)
		}
		type armAt struct {
			arm  Arm
			cond Cond
		}
		cases := func(s *Set, u *Def) (map[string]armAt, []string) {
			m := map[string]armAt{}
			var order []string
			for _, a := range u.Arms {
				for _, c := range a.Cases {
					l := s.CaseLabel(u, c)
					m[l] = armAt{a, append(append(Cond{}, a.Cond...), c.Cond...)}
					order = append(order, l)
				}
			}
			return m, order
		}
		bc, bOrder := cases(base, bd)
		hc, hOrder := cases(head, hd)
		for _, l := range hOrder {
			h := hc[l]
			b, ok := bc[l]
			if !ok {
				c := Change{Kind: "arm-added", Def: hd.Name, DefKind: "union", Member: l, New: armText(h.arm), File: hd.File,
					ArmIDs: []string{hd.Name + "::" + l}}
				if t := head.resolveTypedef(h.arm.Type); t != nil && t.Kind == "optional" {
					c.ArmIDs = append(c.ArmIDs, hd.Name+"::"+l+"?some", hd.Name+"::"+l+"?none")
				}
				d.add(c, nil, h.cond, true)
				continue
			}
			if b.arm.Name != h.arm.Name || typeChange(base, head, b.arm.Type, h.arm.Type) != "" {
				ch("arm-changed", l, armText(b.arm), armText(h.arm), b.cond, h.cond)
			}
		}
		for _, l := range bOrder {
			if _, ok := hc[l]; !ok {
				d.add(Change{Kind: "arm-removed", Def: hd.Name, DefKind: "union", Member: l, Old: armText(bc[l].arm), File: hd.File,
					ArmIDs: []string{hd.Name + "::" + l}}, bc[l].cond, nil, false)
			}
		}
	}
}

func armText(a Arm) string {
	if a.Type == nil {
		return "void"
	}
	return a.Type.String() + " " + a.Name
}

// typeKey renders a type with sizes given as constants replaced by their values.
func typeKey(s *Set, t *Type) string {
	if t == nil {
		return "void"
	}
	c := *t
	if d := s.Get(c.Size); d != nil && d.Kind == "const" {
		c.Size = d.Value
	}
	if c.Elem != nil {
		c.Elem = &Type{Kind: "ref", Name: typeKey(s, c.Elem)}
	}
	return c.String()
}

// typeChange classifies how a type changed: "" when equal, "optional-changed" when only optionality changed,
// "size-changed" when only a size or bound changed, else "type-changed"; callers prefix the
// element (field-, typedef-).
func typeChange(bs, hs *Set, b, h *Type) string {
	if typeKey(bs, b) == typeKey(hs, h) {
		return ""
	}
	if b != nil && h != nil {
		if b.Kind == "optional" && h.Kind != "optional" && typeKey(bs, b.Elem) == typeKey(hs, h) {
			return "optional-changed"
		}
		if h.Kind == "optional" && b.Kind != "optional" && typeKey(bs, b) == typeKey(hs, h.Elem) {
			return "optional-changed"
		}
		if b.Kind == h.Kind && b.Size != h.Size && typeKey(bs, b.Elem) == typeKey(hs, h.Elem) && b.Name == h.Name {
			return "size-changed"
		}
	}
	return "type-changed"
}

// summary is a one-line description of a definition, for added and removed types.
func summary(s *Set, d *Def) string {
	switch d.Kind {
	case "const":
		return "const " + d.Value
	case "typedef":
		return "typedef " + d.Type.String()
	case "enum":
		var p []string
		for _, m := range d.Members {
			p = append(p, m.Name+" = "+strconv.FormatInt(m.Value, 10))
		}
		return "enum { " + strings.Join(p, ", ") + " }"
	case "struct":
		var p []string
		for _, f := range d.Fields {
			p = append(p, f.Type.String()+" "+f.Name)
		}
		return "struct { " + strings.Join(p, "; ") + " }"
	case "union":
		var p []string
		for _, a := range d.Arms {
			var ls []string
			for _, c := range a.Cases {
				ls = append(ls, s.CaseLabel(d, c))
			}
			p = append(p, strings.Join(ls, ", ")+": "+armText(a))
		}
		return "union switch (" + d.Disc.Type.String() + ") { " + strings.Join(p, "; ") + " }"
	}
	return d.Kind
}

// inferGates gives every definition the gates it is effectively under: its own condition, or, for an
// ungated definition that only gated elements refer to (a new struct used only by a gated arm), the union of
// those elements' gates. Repeated until nothing changes, so chains of new types inherit too.
func inferGates(s *Set) map[string]Cond {
	eff := map[string]Cond{}
	for _, d := range s.Defs {
		eff[d.Name] = d.Cond
	}
	type ref struct {
		from string
		cond Cond
	}
	refs := map[string][]ref{}
	addRefs := func(from string, c Cond, t *Type) {
		for _, n := range t.refs(nil) {
			refs[n] = append(refs[n], ref{from, c})
		}
	}
	for _, d := range s.Defs {
		addRefs(d.Name, d.Cond, d.Type)
		for _, f := range d.Fields {
			addRefs(d.Name, f.Cond, f.Type)
		}
		if d.Disc != nil {
			addRefs(d.Name, d.Cond, d.Disc.Type)
		}
		for _, a := range d.Arms {
			addRefs(d.Name, a.Cond, a.Type)
		}
	}
	for pass := 0; pass < 16; pass++ {
		changed := false
		for _, d := range s.Defs {
			if len(d.Cond) > 0 || len(refs[d.Name]) == 0 {
				continue
			}
			union := map[string]bool{}
			all := true
			for _, r := range refs[d.Name] {
				c := append(append(Cond{}, r.cond...), eff[r.from]...)
				if len(c) == 0 || r.from == d.Name {
					all = false
					break
				}
				for _, x := range c {
					union[x] = true
				}
			}
			if !all {
				continue
			}
			nc := Cond(sortedKeys(union))
			if strings.Join(nc, "&") != strings.Join(eff[d.Name], "&") {
				eff[d.Name] = nc
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	return eff
}

// armGates are the gates of an arm identifier in head: the arm's or field's own condition and its type's.
func (d *differ) armGates(id string) []string {
	head := d.head
	set := map[string]bool{}
	add := func(c Cond) {
		for _, x := range c {
			set[strings.TrimPrefix(x, "!")] = true
		}
	}
	name, member := id, ""
	if i := strings.Index(id, "::"); i >= 0 {
		name, member = id[:i], id[i+2:]
	} else if i := strings.Index(id, "."); i >= 0 {
		name, member = id[:i], id[i+1:]
	}
	member = strings.TrimSuffix(strings.TrimSuffix(member, "?some"), "?none")
	def := head.Get(name)
	if def == nil {
		return nil
	}
	add(d.hGates[name])
	for _, f := range def.Fields {
		if f.Name == member {
			add(f.Cond)
		}
	}
	for _, a := range def.Arms {
		for _, c := range a.Cases {
			if head.CaseLabel(def, c) == member {
				add(a.Cond)
				add(c.Cond)
			}
		}
	}
	return sortedKeys(set)
}

// defaultClass applies the default rule of corpus/arms.toml to an arm identifier.
func defaultClass(s *Set, id string) string {
	i := strings.Index(id, "::")
	if i < 0 {
		return "in-ledger"
	}
	u := s.Get(id[:i])
	if u == nil || u.Disc == nil {
		return "in-ledger"
	}
	if e := s.discEnum(u); e != nil && strings.HasSuffix(e.Name, "ResultCode") {
		if strings.HasSuffix(strings.TrimSuffix(strings.TrimSuffix(id[i+2:], "?some"), "?none"), "_MALFORMED") {
			return "validation-only"
		}
		return "apply-time-result"
	}
	return "in-ledger"
}

// SortChanges orders changes by CAP, then type, kind and member, for stable output.
func (r *Report) SortChanges() {
	sort.SliceStable(r.Changes, func(i, j int) bool {
		a, b := r.Changes[i], r.Changes[j]
		ka := strings.Join(a.CAPs, ",") + "\x00" + a.Def + "\x00" + a.Kind + "\x00" + a.Member
		kb := strings.Join(b.CAPs, ",") + "\x00" + b.Def + "\x00" + b.Kind + "\x00" + b.Member
		return ka < kb
	})
}

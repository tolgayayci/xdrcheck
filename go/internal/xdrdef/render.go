package xdrdef

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// sideText describes a side for a heading.
func sideText(s Side) string {
	t := "`" + s.Label + "`"
	if s.Commit != "" && !strings.HasPrefix(s.Label, s.Commit) {
		t += " (" + short(s.Commit) + ")"
	}
	if len(s.Features) > 0 {
		t += ", features " + strings.Join(s.Features, ", ")
	} else {
		t += ", no features"
	}
	return t
}

func short(c string) string {
	if len(c) > 12 {
		return c[:12]
	}
	return c
}

func mdCell(s string) string {
	s = strings.ReplaceAll(s, "|", `\|`)
	if len(s) > 160 {
		s = s[:157] + "..."
	}
	return s
}

// WriteMarkdown renders a diff report as Markdown: what was compared, the gates and their CAPs, the arms
// readers gain or lose per root, and every change grouped by CAP.
func (r *Report) WriteMarkdown(w io.Writer, heading string) {
	if heading == "" {
		heading = "XDR diff"
	}
	fmt.Fprintf(w, "## %s\n\n", heading)
	fmt.Fprintf(w, "- base: %s\n- head: %s\n", sideText(r.Base), sideText(r.Head))
	if r.Empty() {
		fmt.Fprintf(w, "\nNo structural difference.\n")
		return
	}
	reader := 0
	for _, c := range r.Changes {
		if len(c.Reach) > 0 {
			reader++
		}
	}
	fmt.Fprintf(w, "- %d changes, %d of them in types reachable from %s\n", len(r.Changes), reader, strings.Join(r.Roots, " or "))
	if len(r.CAPGates) > 0 {
		var gs []string
		for _, g := range sortedKeys(r.CAPGates) {
			if c := r.CAPGates[g]; c != "" {
				gs = append(gs, "`"+g+"` → "+c)
			} else {
				gs = append(gs, "`"+g+"` (no CAP)")
			}
		}
		fmt.Fprintf(w, "- gates: %s\n", strings.Join(gs, ", "))
	}
	for _, root := range r.Roots {
		if len(r.NewArms[root]) == 0 && len(r.RemovedArms[root]) == 0 {
			continue
		}
		fmt.Fprintf(w, "\n### Arms reachable from `%s`\n\n", root)
		if len(r.NewArms[root]) > 0 {
			fmt.Fprintf(w, "| New arm or optional state | CAP | Gate | Default class |\n|---|---|---|---|\n")
			for _, a := range r.NewArms[root] {
				fmt.Fprintf(w, "| `%s` | %s | %s | %s |\n", a.ID, orDash(strings.Join(a.CAPs, ", ")), orDash(strings.Join(a.Gates, ", ")), a.Class)
			}
		}
		if len(r.RemovedArms[root]) > 0 {
			fmt.Fprintf(w, "\nRemoved: %s\n", "`"+strings.Join(r.RemovedArms[root], "`, `")+"`")
		}
	}
	groups := map[string][]Change{}
	for _, c := range r.Changes {
		k := strings.Join(c.CAPs, ", ")
		groups[k] = append(groups[k], c)
	}
	keys := sortedKeys(groups)
	sort.SliceStable(keys, func(i, j int) bool { return keys[i] != "" && keys[j] == "" })
	for _, k := range keys {
		title := k
		if title == "" {
			title = "Not mapped to a CAP"
		}
		fmt.Fprintf(w, "\n### %s\n\n| Change | Type | Member | Old | New | Gate | Readers |\n|---|---|---|---|---|---|---|\n", title)
		for _, c := range groups[k] {
			fmt.Fprintf(w, "| %s | `%s` (%s) | %s | %s | %s | %s | %s |\n", c.Kind, c.Def, c.DefKind, codeOrDash(c.Member),
				codeOrDash(mdCell(c.Old)), codeOrDash(mdCell(c.New)), orDash(strings.Join(c.Gates, ", ")), orDash(strings.Join(c.Reach, ", ")))
		}
	}
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func codeOrDash(s string) string {
	if s == "" {
		return "—"
	}
	return "`" + s + "`"
}

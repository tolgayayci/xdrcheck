package xdrdef

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Candidate corpus rows from structural diffs: the edits a draft pull request proposes to corpus/caps.toml,
// corpus/arms.toml and corpus/plan.json when the XDR gains shapes. Every row is marked as a candidate for a
// person to review: the CAP's reader visibility and wording, each arm's class, and how an entry will be
// produced. Rows already present are left alone, so running it again changes nothing.

// CAPInfo is what a CAP's preamble says.
type CAPInfo struct {
	Title    string `json:"title"`
	Status   string `json:"status"`
	Protocol string `json:"protocol"`
}

// CandidateInput is everything the candidate rows are made from.
type CandidateInput struct {
	Diffs []*Report
	// CAPs maps `CAP-NNNN` to its preamble, when known.
	CAPs map[string]CAPInfo
	// NextProtocol is the protocol rows without a CAP are filed under (the pinned maximum plus one).
	NextProtocol int
	// CapsToml, ArmsToml and PlanJSON are the current file texts.
	CapsToml, ArmsToml, PlanJSON string
}

// CandidateOutput holds the new file texts and what was added.
type CandidateOutput struct {
	CapsToml, ArmsToml, PlanJSON string
	Added                        []string
}

// candidateArm is a new arm reachable from the ledger batch, with where it came from.
type candidateArm struct {
	ArmRef
	group  string
	cap    int
	source string
}

var capNum = regexp.MustCompile(`^CAP-(\d{4})$`)

// planRow is a corpus/plan.json row, fields in the file's order.
type planRow struct {
	ID          string            `json:"id"`
	Kind        string            `json:"kind"`
	Negative    bool              `json:"negative"`
	Caps        []int             `json:"caps"`
	ProtocolMin int               `json:"protocol_min"`
	Source      []string          `json:"source"`
	Locator     string            `json:"locator"`
	Networks    []string          `json:"networks"`
	Synthetic   bool              `json:"synthetic"`
	Serves      []string          `json:"serves"`
	Pins        []string          `json:"pins"`
	Levels      []string          `json:"levels"`
	Replayable  bool              `json:"replayable"`
	Priority    string            `json:"priority"`
	Scenario    *string           `json:"scenario"`
	Shape       string            `json:"shape"`
	VectorCount int               `json:"vector_count"`
	Note        string            `json:"note"`
	Members     []string          `json:"members"`
	Evidence    map[string]string `json:"evidence"`
}

func slug(s string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			dash = false
		} else if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
	}
	return strings.TrimSuffix(b.String(), "-")
}

func tomlString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// Candidates computes the edits.
func Candidates(in CandidateInput) (*CandidateOutput, error) {
	out := &CandidateOutput{CapsToml: in.CapsToml, ArmsToml: in.ArmsToml, PlanJSON: in.PlanJSON}
	arms := map[string]candidateArm{}
	capChanged := map[string]map[string]bool{}
	for _, r := range in.Diffs {
		src := r.Base.Label + ".." + r.Head.Label
		for _, a := range r.NewArms["LedgerCloseMetaBatch"] {
			if _, ok := arms[a.ID]; ok {
				continue
			}
			ca := candidateArm{ArmRef: a, source: src, group: fmt.Sprintf("protocol-%02d", in.NextProtocol)}
			if len(a.CAPs) == 1 {
				if m := capNum.FindStringSubmatch(a.CAPs[0]); m != nil {
					ca.cap, _ = strconv.Atoi(m[1])
					ca.group = "cap-" + m[1]
				}
			}
			arms[a.ID] = ca
		}
		for _, c := range r.Changes {
			if len(c.Reach) == 0 {
				continue
			}
			for _, cp := range c.CAPs {
				if capChanged[cp] == nil {
					capChanged[cp] = map[string]bool{}
				}
				what := c.Def
				if c.Member != "" {
					what += "::" + c.Member
				}
				capChanged[cp][what] = true
			}
		}
	}
	ids := sortedKeys(arms)

	// corpus/arms.toml: one [[arm]] record per new arm, with the default rule's class.
	var ab strings.Builder
	for _, id := range ids {
		if strings.Contains(in.ArmsToml, "id = "+tomlString(id)+"\n") {
			continue
		}
		a := arms[id]
		fmt.Fprintf(&ab, "\n[[arm]]\nid = %s\nclass = %q\n", tomlString(id), a.Class)
		if a.Class == "validation-only" || a.Class == "never-built" {
			ab.WriteString("evidence = \"unverified\"\n")
		}
		gate := strings.Join(append(append([]string{}, a.CAPs...), a.Gates...), ", ")
		if gate == "" {
			gate = "no gate, no CAP"
		}
		fmt.Fprintf(&ab, "reason = %s\n", tomlString(fmt.Sprintf("CANDIDATE from xdrcheck xdr diff %s (%s): the default rule's class; confirm it or replace it with the class and reason stellar-core's code gives", a.source, gate)))
		out.Added = append(out.Added, "arms.toml: "+id)
	}
	if ab.Len() > 0 {
		out.ArmsToml = strings.TrimRight(in.ArmsToml, "\n") + "\n" + ab.String()
	}

	// corpus/caps.toml: make each CAP with reader-visible changes a reader-visible row.
	caps := out.CapsToml
	var cb strings.Builder
	for _, cp := range sortedKeys(capChanged) {
		m := capNum.FindStringSubmatch(cp)
		if m == nil {
			continue
		}
		file := "cap-" + m[1] + ".md"
		group := "cap-" + m[1]
		var what []string
		for _, w := range sortedKeys(capChanged[cp]) {
			what = append(what, "`"+w+"`")
		}
		if len(what) > 8 {
			what = append(what[:8], fmt.Sprintf("and %d more", len(what)-8))
		}
		changed := "CANDIDATE: " + strings.Join(what, ", ")
		start, end, ok := tomlRecord(caps, "[[cap]]", "file = "+tomlString(file))
		info := in.CAPs[cp]
		if !ok {
			fmt.Fprintf(&cb, "\n[[cap]]\nfile = %s\ntitle = %s\nstatus = %s\n", tomlString(file), tomlString(orTODO(info.Title)), tomlString(orTODO(info.Status)))
			if p, err := strconv.Atoi(info.Protocol); err == nil {
				fmt.Fprintf(&cb, "protocol = %d\n", p)
			}
			fmt.Fprintf(&cb, "reader_visible = true\ngroup = %s\nchanged = %s\n", tomlString(group), tomlString(changed))
			out.Added = append(out.Added, "caps.toml: new "+file)
			continue
		}
		rec := caps[start:end]
		if strings.Contains(rec, "\nreader_visible = true") {
			continue
		}
		var lines []string
		for _, l := range strings.Split(strings.TrimRight(rec, "\n"), "\n") {
			switch {
			case strings.HasPrefix(l, "reader_visible = "):
				lines = append(lines, "reader_visible = true", "group = "+tomlString(group), "changed = "+tomlString(changed))
			case strings.HasPrefix(l, "reason = "), strings.HasPrefix(l, "group = "), strings.HasPrefix(l, "changed = "):
			default:
				lines = append(lines, l)
			}
		}
		caps = caps[:start] + strings.Join(lines, "\n") + rec[len(strings.TrimRight(rec, "\n")):] + caps[end:]
		out.Added = append(out.Added, "caps.toml: "+file+" now reader-visible")
	}
	// A [[group]] row for arms that no CAP gate explains (an ungated branch such as a new meta version).
	needGroup := map[string]bool{}
	for _, a := range arms {
		if a.cap == 0 {
			needGroup[a.group] = true
		}
	}
	for _, g := range sortedKeys(needGroup) {
		if _, _, ok := tomlRecord(caps+cb.String(), "[[group]]", "group = "+tomlString(g)); ok {
			continue
		}
		fmt.Fprintf(&cb, "\n[[group]]\ngroup = %s\ntitle = %s\nprotocol = %d\nchanged = %s\n", tomlString(g),
			tomlString(fmt.Sprintf("CANDIDATE: XDR changes without a CAP gate, filed under protocol %d", in.NextProtocol)), in.NextProtocol,
			tomlString("CANDIDATE: new arms from an XDR diff that no #ifdef names; say what readers see"))
		out.Added = append(out.Added, "caps.toml: new group "+g)
	}
	out.CapsToml = caps
	if cb.Len() > 0 {
		out.CapsToml = strings.TrimRight(caps, "\n") + "\n" + cb.String()
	}

	// corpus/plan.json: one planned row per new in-ledger or apply-time arm.
	var existing []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(in.PlanJSON), &existing); err != nil {
		return nil, fmt.Errorf("plan.json: %w", err)
	}
	have := map[string]bool{}
	for _, e := range existing {
		have[e.ID] = true
	}
	var rows []string
	for _, id := range ids {
		a := arms[id]
		if a.Class == "validation-only" {
			continue
		}
		rid := a.group + "/" + slug(id)
		if have[rid] {
			continue
		}
		pmin := in.NextProtocol
		capsList := []int{}
		if a.cap != 0 {
			capsList = []int{a.cap}
			if p, err := strconv.Atoi(in.CAPs[fmt.Sprintf("CAP-%04d", a.cap)].Protocol); err == nil {
				pmin = p
			}
		}
		row := planRow{
			ID: rid, Kind: "ledger", Caps: capsList, ProtocolMin: pmin, Source: []string{"local-core"},
			Locator: "TBD: a scenario that makes stellar-core build this arm", Networks: []string{"testnet", "pubnet"},
			Serves: []string{}, Pins: []string{}, Levels: []string{"L0", "L1", "L2"}, Priority: "should",
			Shape:       fmt.Sprintf("CANDIDATE: `%s` (default class %s)", id, a.Class),
			VectorCount: 1, Note: "candidate from xdrcheck xdr diff " + a.source, Members: []string{},
			Evidence: map[string]string{"local-core": "not-built"},
		}
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		enc.SetIndent(" ", " ")
		if err := enc.Encode(row); err != nil {
			return nil, err
		}
		rows = append(rows, " "+strings.TrimRight(buf.String(), "\n"))
		out.Added = append(out.Added, "plan.json: "+rid)
	}
	if len(rows) > 0 {
		t := strings.TrimRight(in.PlanJSON, "\n")
		if !strings.HasSuffix(t, "]") {
			return nil, fmt.Errorf("plan.json does not end with ]")
		}
		t = strings.TrimRight(strings.TrimSuffix(t, "]"), "\n")
		sep := ",\n"
		if strings.HasSuffix(t, "[") {
			sep = "\n"
		}
		out.PlanJSON = t + sep + strings.Join(rows, ",\n") + "\n]\n"
	}
	sort.Strings(out.Added)
	return out, nil
}

func orTODO(s string) string {
	if s == "" {
		return "TODO"
	}
	return s
}

// tomlRecord finds the array-of-tables record (header line, e.g. `[[cap]]`) that contains the key line, and
// returns its byte range up to the next record or the end of the text.
func tomlRecord(text, header, keyLine string) (int, int, bool) {
	at := strings.Index(text, "\n"+keyLine+"\n")
	if at < 0 {
		return 0, 0, false
	}
	start := strings.LastIndex(text[:at+1], header+"\n")
	if start < 0 {
		return 0, 0, false
	}
	end := len(text)
	if n := strings.Index(text[at+1:], "\n[["); n >= 0 {
		end = at + 1 + n + 1
	}
	return start, end, true
}

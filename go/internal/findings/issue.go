package findings

import (
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strings"
)

// Draft is a rendered issue body and the command that would file it. The command is text for a person to run
// after the user has approved this draft; nothing in the kit executes it.
type Draft struct {
	File    string // file name in the record's directory, issue-<repository name>.md
	Kind    string // new-issue, comment-on-existing, release-request, private-report
	Body    string
	Command string // one line for public channels; instructions for a private report
}

const toBeWritten = "_To be written by the reviewer before approval._"

var itemURL = regexp.MustCompile(`^https://github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/(issues|pull)/([0-9]+)`)

// RenderIssue renders the draft for a record. recDir is the record directory as the command should name it,
// relative to the repository root (findings/<id>) or, for an embargoed record, to the overlay.
func RenderIssue(rec *Record, recDir string) (*Draft, error) {
	repoName := path.Base(rec.Target.Project)
	d := &Draft{File: "issue-" + repoName + ".md", Kind: "new-issue"}
	if rec.IssueDraft != nil && rec.IssueDraft.Path != "" {
		d.File = rec.IssueDraft.Path
	}
	bodyPath := path.Join(filepathToSlash(recDir), d.File)
	title := rec.Title

	var existing []string // repo, "issues"|"pull", number
	if us := rec.UpstreamSearch; us != nil {
		switch us.Result {
		case "existing-open":
			if m := itemURL.FindStringSubmatch(us.Existing); m != nil {
				existing = m[1:]
				d.Kind = "comment-on-existing"
			}
		case "fix-merged-unreleased":
			d.Kind = "release-request"
			title = "Release request: " + rec.Title
		}
	}
	if rec.Visibility == "embargoed" {
		d.Kind = "private-report"
	}
	d.Body = body(rec, title)

	switch d.Kind {
	case "private-report":
		channel, policy := "not yet decided", "not yet looked up"
		if e := rec.Embargo; e != nil {
			channel, policy = e.Channel, e.Policy
		}
		d.Command = strings.Join([]string{
			"# private report — embargoed: do not open a public issue, comment or pull request",
			"# channel: " + channel,
			"# policy:  " + policy,
			"# body:    " + bodyPath + " (in the overlay; it never enters the public tree)",
			"# after the user approves this draft, a person submits the body through that channel and records",
			"# upstream.private_reference and upstream.filed_at in the record",
		}, "\n")
	case "comment-on-existing":
		verb := "issue"
		if existing[1] == "pull" {
			verb = "pr"
		}
		d.Command = fmt.Sprintf("gh %s comment %s --repo %s --body-file %s", verb, existing[2], existing[0], shellQuote(bodyPath))
	default:
		d.Command = fmt.Sprintf("gh issue create --repo %s --title %s --body-file %s", rec.Target.Project, shellQuote(title), shellQuote(bodyPath))
	}
	return d, nil
}

func filepathToSlash(p string) string { return strings.ReplaceAll(p, `\`, "/") }

// shellQuote quotes s for a POSIX shell: plain words stay bare; anything else goes in double quotes with ", \,
// $ and ` escaped.
func shellQuote(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\n\"'\\$`!*?[]{}()<>|&;#~") {
		return s
	}
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, `$`, `\$`, "`", "\\`")
	return `"` + r.Replace(s) + `"`
}

func orWrite(s string) string {
	if strings.TrimSpace(s) == "" {
		return toBeWritten
	}
	return s
}

// body renders the draft issue template: title, affected versions, summary, reproduction, why the expectation
// holds, the same defect elsewhere, a suggested fix, and how to run the corpus entry.
func body(rec *Record, title string) string {
	var b strings.Builder
	pkg := rec.Target.Package
	if pkg == "" {
		pkg = rec.Target.Project
	}
	fixed := "n/a"
	if rec.Target.FixedIn != "" {
		fixed = rec.Target.FixedIn
	}
	fmt.Fprintf(&b, "Title: %s\n\n", title)
	fmt.Fprintf(&b, "Affected: `%s@%s`     Fixed in: %s\n\n", pkg, strings.Join(rec.Target.VersionsTested, ", "), fixed)
	fmt.Fprintf(&b, "## Summary\n\n%s\n\n", orWrite(rec.SeverityBasis))

	b.WriteString("## Reproduce\n\n")
	for i, e := range rec.Entries {
		label := "Entry"
		if i == 0 {
			label = "Minimal entry"
		}
		id := "`" + e.ID + "`"
		if e.Variant != "" {
			id += " (variant `" + e.Variant + "`)"
		}
		fmt.Fprintf(&b, "- %s: %s, scope %s\n  - observed: %s\n  - expected: %s\n", label, id, e.Scope, e.Observed, e.Expected)
	}
	if l := rec.Location; l != nil {
		fmt.Fprintf(&b, "- Location: `%s`", l.File)
		if l.Lines != "" {
			fmt.Fprintf(&b, " lines %s", l.Lines)
		}
		if l.Function != "" {
			fmt.Fprintf(&b, " in `%s`", l.Function)
		}
		fmt.Fprintf(&b, " at commit %s\n", l.Commit)
	}
	if ev := rec.Evidence; ev != nil && ev.PreFix != "" {
		fmt.Fprintf(&b, "- Observed on an affected version: %s\n", ev.PreFix)
	}
	if ev := rec.Evidence; ev != nil && ev.PostFix != "" {
		fmt.Fprintf(&b, "- Observed on a fixed version: %s\n", ev.PostFix)
	}
	b.WriteString("\n")

	basis := ""
	if rec.Evidence != nil {
		basis = rec.Evidence.ExpectedBasis
	}
	fmt.Fprintf(&b, "## Why this is expected\n\n%s\n\n", orWrite(basis))

	b.WriteString("## Same defect elsewhere\n\n")
	var links []string
	for _, s := range rec.Siblings {
		links = append(links, "- sibling finding "+s)
	}
	for _, r := range rec.Related {
		if u, err := url.Parse(r); err == nil && u.Scheme == "https" {
			links = append(links, "- "+r)
		}
	}
	if len(links) == 0 {
		b.WriteString("None known.\n\n")
	} else {
		b.WriteString(strings.Join(links, "\n") + "\n\n")
	}

	fmt.Fprintf(&b, "## Suggested fix\n\n%s\n\n", toBeWritten)

	b.WriteString("## Corpus\n\n")
	e := rec.Entries[0]
	switch {
	case e.Scope == "replay":
		fmt.Fprintf(&b, "    xdrcheck replay --corpus corpus --entries %s --adapter \"<adapter command>\" --target-version %s\n", e.ID, rec.Target.VersionsTested[0])
	case strings.HasPrefix(e.Scope, "XDR"):
		fmt.Fprintf(&b, "    xdrlint -report report.json ./...    # at %s; rule %s\n", rec.Target.VersionsTested[0], e.Scope)
	default:
		fmt.Fprintf(&b, "    xdrcheck conform run --entries %s --levels %s --report out/\n", e.ID, e.Scope)
	}
	return b.String()
}

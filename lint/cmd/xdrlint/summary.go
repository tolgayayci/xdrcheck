package main

// The closing summary of a text run, written to stderr: what was found, why
// the run passes or fails, and how to accept a report that was checked.

import (
	"fmt"
	"io"
	"strings"

	"github.com/tolgayayci/xdrcheck/lint/internal/framework"
)

func writeSummary(w io.Writer, findings []framework.Finding, pending []framework.PendingEntry, failOn framework.Severity) {
	bySev := map[framework.Severity]int{}
	shown, suppressed, failing, onPending := 0, 0, 0, 0
	example := "XDR103"
	for _, f := range findings {
		if f.Suppressed {
			suppressed++
			continue
		}
		if shown == 0 && f.Rule != framework.XDR000.ID {
			example = f.Rule
		}
		shown++
		bySev[f.Severity]++
		if f.Severity.Rank() >= failOn.Rank() {
			if framework.IsPending(pending, f) {
				onPending++
			} else {
				failing++
			}
		}
	}
	accepted := ""
	if suppressed > 0 {
		accepted = fmt.Sprintf(" %s accepted with a reason (suppressed) and not shown.", plural(suppressed, "report", "reports"))
	}
	if shown == 0 {
		fmt.Fprintf(w, "xdrlint: no problems found.%s\n", accepted)
		return
	}
	var parts []string
	for _, s := range []framework.Severity{framework.SeverityError, framework.SeverityWarning, framework.SeverityInfo} {
		if n := bySev[s]; n > 0 {
			name := string(s)
			if n > 1 && s != framework.SeverityInfo {
				name += "s"
			}
			parts = append(parts, fmt.Sprintf("%d %s", n, name))
		}
	}
	fmt.Fprintf(w, "\nxdrlint: %s (%s).%s\n", plural(shown, "problem", "problems"), strings.Join(parts, ", "), accepted)
	switch {
	case failing > 0:
		fmt.Fprintf(w, "The run fails (exit 1): %s at or above -fail-on %s.\n", plural(failing, "report is", "reports are"), failOn)
	default:
		fmt.Fprintf(w, "The run passes (exit 0): nothing unaccepted is at or above -fail-on %s; the rest is advice.\n", failOn)
	}
	if onPending > 0 {
		fmt.Fprintf(w, "%s on the -pending list and %s not fail the run; %s still not fixed or accepted.\n",
			plural(onPending, "report is", "reports are"), map[bool]string{true: "does", false: "do"}[onPending == 1],
			map[bool]string{true: "it is", false: "they are"}[onPending == 1])
	}
	fmt.Fprintf(w, "Fix each one as its \"fix:\" line says; its \"docs:\" page explains the rule.\n"+
		"If you checked a report and the code is right, accept it with a reason instead:\n"+
		"  //xdrlint:ignore %s <why this is safe>   on the reported line, or on the function's doc comment\n"+
		"  suppressions: FILE   in .xdrlint.yml, for code you cannot edit; FILE lists rule, file, line, reason\n"+
		"A suppression without a reason, or one that matches nothing, is itself reported (XDR000).\n", example)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

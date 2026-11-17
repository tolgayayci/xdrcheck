// Command xdrlint-docs builds the rule pages in lint/docs from the rule
// registry, the fragments in lint/docs/src and the fixtures, and the guide's
// checklist page (guide/checklist.mdx, with its fragments in
// guide/generated/) from the same registry and the checklist item table
// (see package internal/ruledoc).
//
//	go run ./cmd/xdrlint-docs [-root DIR] [--check]
//
// Run it in the lint module root (or name that directory with -root). With
// --check (or -check) it writes nothing and exits 1 when a page is missing,
// out of date or documents no rule; it exits 2 when the sources themselves
// are wrong (a rule without a fragment or without exactly one checklist
// item, an unknown guide anchor or corpus entry, an example naming no
// function).
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/tolgayayci/xdrcheck/lint/internal/ruledoc"
)

func main() {
	root := flag.String("root", ".", "lint module root")
	check := flag.Bool("check", false, "compare the pages and the checklist on disk with a fresh build; write nothing")
	flag.Parse()
	if !*check {
		if err := ruledoc.Write(*root); err != nil {
			fmt.Fprintf(os.Stderr, "xdrlint-docs: %v\n", err)
			os.Exit(2)
		}
		return
	}
	diffs, err := ruledoc.Check(*root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "xdrlint-docs: %v\n", err)
		os.Exit(2)
	}
	for _, d := range diffs {
		fmt.Fprintf(os.Stderr, "xdrlint-docs: %s\n", d)
	}
	if len(diffs) > 0 {
		fmt.Fprintln(os.Stderr, "xdrlint-docs: run `go run ./cmd/xdrlint-docs` in lint/ to rebuild the pages and the checklist")
		os.Exit(1)
	}
	fmt.Println("xdrlint-docs: rule pages and guide checklist match the rule registry")
}

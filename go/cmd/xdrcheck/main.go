// Command xdrcheck is the Go side of the kit: the ledger server, the replay harness, the conformance
// orchestrator, and the report, findings and pins command groups. Each command group lives in its own file;
// the command surface is documented in docs/cli.md.
package main

import (
	"fmt"
	"os"
	"sort"

	"github.com/tolgayayci/xdrcheck/go/internal/userdir"
)

// command is one top-level command group. Its run function receives the arguments after the group name and
// returns the process exit code.
type command struct {
	summary string
	run     func(args []string) int
}

var commands = map[string]command{}

func register(name, summary string, run func(args []string) int) {
	commands[name] = command{summary: summary, run: run}
}

func notImplemented(name string) func([]string) int {
	return func([]string) int {
		fmt.Fprintf(os.Stderr, "xdrcheck %s: not implemented yet\n", name)
		return 2
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: xdrcheck <command> [arguments]\n\ncommands:")
	names := make([]string, 0, len(commands))
	for n := range commands {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(os.Stderr, "  %-9s %s\n", n, commands[n].summary)
	}
}

func main() {
	// Settings exported under the command's earlier name (XCC_*) still apply, here and in every program it starts.
	userdir.LegacyEnv()
	if len(os.Args) < 2 || os.Args[1] == "-h" || os.Args[1] == "--help" || os.Args[1] == "help" {
		usage()
		os.Exit(2)
	}
	c, ok := commands[os.Args[1]]
	if !ok {
		fmt.Fprintf(os.Stderr, "xdrcheck: unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	os.Exit(c.run(os.Args[2:]))
}

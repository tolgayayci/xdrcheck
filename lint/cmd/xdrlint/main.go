// Command xdrlint finds the three ingestion mistakes of the XDR CAP coverage
// kit in Go code that uses the go-stellar-sdk ingest stack.
//
//	xdrlint [-profile NAME|PATH] [-config FILE] [-json] [-sarif FILE] [-report FILE]
//	        [-expect FILE] [-pending FILE] [-fail-on error|warning] [-overlay DIR] <packages>
//
// The same binary is a `go vet` tool: `go vet -vettool=$(which xdrlint) ./...`.
// In that mode the command line belongs to go vet, so the configuration comes
// from XDRLINT_PROFILE / XDRLINT_CONFIG / XDRLINT_OVERLAY, or from an
// .xdrlint.yml found from each package directory up to its module root;
// external suppression files and -report / -expect are standalone features.
//
// Exit status: 0 clean; 1 an unsuppressed finding at or above -fail-on
// (default error) that no -pending list names, or, with -expect, any
// difference from the expected list (then findings alone do not fail the run);
// 2 a usage, configuration or package-loading error, or no recognised source
// package loaded (none of the packages, nor anything they import, is
// go-stellar-sdk's xdr package or an alias of it, so there was nothing to
// analyse).
//
// Rule packages register their analyzers with internal/framework from
// package-level variables; a blank import below builds one into xdrlint.
package main

import (
	"os"
	"strings"

	"golang.org/x/tools/go/analysis/unitchecker"

	"github.com/tolgayayci/xdrcheck/lint/internal/framework"
	// Rule packages, one blank import each.
	_ "github.com/tolgayayci/xdrcheck/lint/rules/xdr1xx"
	_ "github.com/tolgayayci/xdrcheck/lint/rules/xdr2xx"
	_ "github.com/tolgayayci/xdrcheck/lint/rules/xdr3xx"
	_ "github.com/tolgayayci/xdrcheck/lint/rules/xdr4xx"
)

func main() {
	analyzers := framework.Analyzers()
	if vetMode(os.Args[1:]) {
		unitchecker.Main(analyzers...) // does not return
	}
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// vetMode reports whether go vet is driving the binary: it first asks for
// the version (-V=full) and the flags (-flags), then passes one *.cfg file
// per package.
func vetMode(args []string) bool {
	for _, a := range args {
		if a == "-flags" || strings.HasPrefix(a, "-V") {
			return true
		}
	}
	return len(args) > 0 && strings.HasSuffix(args[len(args)-1], ".cfg")
}

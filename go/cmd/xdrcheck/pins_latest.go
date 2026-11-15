package main

// xdrcheck pins latest [--pins FILE] [--json FILE] [--list]: for every pin annotated with a `# renovate:` comment in
// pins.toml (go/internal/pins, latest.go), the newest stable published version, and whether the pin is behind
// it. It is the bot-free half of the pin-bump automation: the nightly canary job runs it and reports drift
// without failing anything; renovate.json reads the same annotations to open one pull request per move.
//
// Output: one line per pin, `current`, `BEHIND` or `ERROR`, then a summary line. Exit codes: 0 every pin is
// the newest; 1 at least one pin is behind; 2 a lookup failed or the arguments or pins file are wrong.

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/tolgayayci/xdrcheck/go/internal/pins"
)

// latestRow is one pin in the --json output.
type latestRow struct {
	pins.Tracked
	Latest string `json:"latest,omitempty"`
	Behind bool   `json:"behind"`
	Error  string `json:"error,omitempty"`
}

func pinsLatestMain(args []string, stdout, stderr io.Writer, reg *pins.Registries) int {
	fs := flag.NewFlagSet("xdrcheck pins latest", flag.ContinueOnError)
	fs.SetOutput(stderr)
	pinsFile := fs.String("pins", "", "pins file (default pins.toml at the repository root)")
	jsonOut := fs.String("json", "", "also write the rows as JSON to this file")
	list := fs.Bool("list", false, "only list the tracked pins and where each is looked up; no network")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "xdrcheck pins latest: unexpected arguments %v\n", fs.Args())
		return 2
	}
	_, path, code := resolvePinsFile(*pinsFile, stderr, "xdrcheck pins latest")
	if code != 0 {
		return code
	}
	text, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(stderr, "xdrcheck pins latest: %v\n", err)
		return 2
	}
	tracked, err := pins.TrackedPins(string(text))
	if err != nil {
		fmt.Fprintf(stderr, "xdrcheck pins latest: %s: %v\n", path, err)
		return 2
	}
	if *list {
		for _, t := range tracked {
			fmt.Fprintf(stdout, "%-36s %-16s %s %s\n", t.Key, t.Current, t.Datasource, t.DepName)
		}
		if *jsonOut != "" {
			data, _ := json.MarshalIndent(tracked, "", "  ")
			if err := os.WriteFile(*jsonOut, append(data, '\n'), 0o644); err != nil {
				fmt.Fprintf(stderr, "xdrcheck pins latest: %v\n", err)
				return 2
			}
		}
		return 0
	}
	if reg == nil {
		reg = pins.DefaultRegistries()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	rows := make([]latestRow, 0, len(tracked))
	behind, failed := 0, 0
	for _, t := range tracked {
		r := latestRow{Tracked: t}
		latest, err := reg.Latest(ctx, t)
		switch {
		case err != nil:
			failed++
			r.Error = err.Error()
			fmt.Fprintf(stdout, "ERROR   %-36s %-16s %s %s: %v\n", t.Key, t.Current, t.Datasource, t.DepName, err)
		case pins.Behind(t.Current, latest):
			behind++
			r.Latest, r.Behind = latest, true
			fmt.Fprintf(stdout, "BEHIND  %-36s %-16s -> %-16s %s %s\n", t.Key, t.Current, latest, t.Datasource, t.DepName)
		default:
			r.Latest = latest
			fmt.Fprintf(stdout, "current %-36s %-16s (newest %s) %s %s\n", t.Key, t.Current, latest, t.Datasource, t.DepName)
		}
		rows = append(rows, r)
	}
	fmt.Fprintf(stdout, "pins latest: %d tracked pins, %d behind, %d lookup(s) failed\n", len(rows), behind, failed)
	if *jsonOut != "" {
		data, _ := json.MarshalIndent(rows, "", "  ")
		if err := os.WriteFile(*jsonOut, append(data, '\n'), 0o644); err != nil {
			fmt.Fprintf(stderr, "xdrcheck pins latest: %v\n", err)
			return 2
		}
	}
	switch {
	case failed > 0:
		return 2
	case behind > 0:
		return 1
	}
	return 0
}

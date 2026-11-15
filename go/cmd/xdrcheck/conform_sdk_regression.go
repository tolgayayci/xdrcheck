package main

// xdrcheck conform sdk-regression [--pins FILE] [--report DIR] [--timeout DUR] [--memory-max SIZE]
//
// The sdk-regression acceptance assertions: the conformance runner reproduces js-stellar-sdk#1766, #1785 and #1789 on
// their pre-fix releases and sees them fixed on the next (the rows are internal/conform/sdk_regression.go). It runs the
// assertion entries on the columns js@17.2.0, js@17.2.1 and js@17.3.0 (the drivers must be built), judges every
// cell with the verdict engine against the manifest and its known divergences, and checks each row. With
// --report it writes sdk-regression.json (the rows and their results) into DIR. Exit codes: 0 every row holds, 1 a row
// fails, 2 the run could not be made (a column missing from drivers/sets.toml, a driver that does not start, a
// protocol error).

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/tolgayayci/xdrcheck/go/internal/conform"
	"github.com/tolgayayci/xdrcheck/go/internal/conform/verdict"
	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
)

func conformSDKRegression(ctx context.Context, args []string) int {
	f := newFlags("sdk-regression", false)
	var reportDir string
	timeout := conform.DefaultTimeout
	var memMax sizeFlag = 1 << 30
	f.fs.StringVar(&reportDir, "report", "", "directory for sdk-regression.json")
	f.fs.DurationVar(&timeout, "timeout", conform.DefaultTimeout, "per-request base timeout")
	f.fs.Var(&memMax, "memory-max", "memory cap per driver process (0 = none)")
	if !f.parse(args) {
		return 2
	}
	if f.columns != "" {
		fmt.Fprintln(os.Stderr, "xdrcheck conform sdk-regression: the columns are fixed by the assertions; --columns is not accepted")
		return 2
	}
	fail := func(err error) int {
		fmt.Fprintf(os.Stderr, "xdrcheck conform sdk-regression: %v\n", err)
		return 2
	}
	env, err := loadConformEnv(f.pins, "")
	if err != nil {
		return fail(err)
	}
	cols, err := env.sets.Select("", strings.Join(conform.SDKRegressionColumns, ","))
	if err != nil {
		return fail(err)
	}
	if len(cols) != len(conform.SDKRegressionColumns) {
		return fail(fmt.Errorf("drivers/sets.toml lacks some of the columns %s", strings.Join(conform.SDKRegressionColumns, ", ")))
	}
	v, err := validator(env.root)
	if err != nil {
		return fail(err)
	}
	corpus, err := manifest.Load(filepath.Join(env.root, "corpus"), manifest.Options{})
	if err != nil {
		return fail(err)
	}
	globs, err := conform.CompileGlobs(strings.Join(conform.SDKRegressionEntries(), ","))
	if err != nil {
		return fail(err)
	}
	var selected []*manifest.Entry
	for _, e := range corpus.Entries {
		if globs.Match(e.ID) {
			selected = append(selected, e)
		}
	}
	if err := verdict.CheckRanges(selected); err != nil {
		return fail(err)
	}
	res, err := conform.Run(ctx, conform.Options{
		Sets: env.sets, Columns: cols, Corpus: corpus, Entries: globs, Validator: v, Log: os.Stderr,
		Limits: conform.Limits{Timeout: timeout, MemoryMax: int64(memMax)},
	})
	if err != nil {
		return fail(err)
	}
	if errs := res.InfraErrors(); len(errs) > 0 {
		return fail(fmt.Errorf("%d infrastructure problem(s):\n  %s", len(errs), strings.Join(errs, "\n  ")))
	}
	res.Apply(verdict.Engine{})
	results := conform.AssertSDKRegression(res.Observations)
	failed := 0
	for _, r := range results {
		status := "PASS"
		if !r.Pass {
			status = "FAIL"
			failed++
		}
		fmt.Printf("%s %-3s %s %-10s %-62s %s %s: %s\n", status, r.ID, r.Check, r.Column, r.Entry, orDash(r.Variant), r.Level, orDash(r.Observed))
		for _, p := range r.Problems {
			fmt.Printf("           %s\n", p)
		}
	}
	if reportDir != "" {
		if err := os.MkdirAll(reportDir, 0o755); err != nil {
			return fail(err)
		}
		out, _ := json.MarshalIndent(map[string]any{"schema": "xcc.conform.sdk-regression/v1", "columns": conform.SDKRegressionColumns, "rows": results,
			"passed": failed == 0}, "", "  ")
		if err := os.WriteFile(filepath.Join(reportDir, "sdk-regression.json"), append(out, '\n'), 0o644); err != nil {
			return fail(err)
		}
	}
	fmt.Fprintf(os.Stderr, "xdrcheck conform sdk-regression: %d assertion cells, %d failing\n", len(results), failed)
	if failed > 0 {
		return 1
	}
	return 0
}

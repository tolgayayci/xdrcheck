package rundir

import (
	"bufio"
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// The schemas are a copy of the repository's schemas/ directory (TestSchemasMatchRepository keeps them equal),
// embedded so that a binary without a checkout can validate a run directory or a bundle.
//
//go:embed schemas/*.schema.json
var schemaFS embed.FS

// Schema file names.
const (
	SchemaManifest = "run-manifest.schema.json"
	SchemaVerdict  = "run-verdict.schema.json"
	SchemaClusters = "run-clusters.schema.json"
	SchemaSummary  = "run-summary.schema.json"
	SchemaBundle   = "bundle.schema.json"
	SchemaDataset  = "dataset-manifest.schema.json"
	SchemaIssues   = "issues.schema.json"
)

// SchemaFiles returns the embedded schemas by file name.
func SchemaFiles() (map[string][]byte, error) {
	out := map[string][]byte{}
	err := fs.WalkDir(schemaFS, "schemas", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := schemaFS.ReadFile(p)
		out[filepath.Base(p)] = b
		return err
	})
	return out, err
}

// Compile returns the compiled schema of one embedded file.
func Compile(name string) (*jsonschema.Schema, error) {
	files, err := SchemaFiles()
	if err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	for n, b := range files {
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
		if err != nil {
			return nil, fmt.Errorf("%s: %v", n, err)
		}
		if err := c.AddResource(n, doc); err != nil {
			return nil, err
		}
	}
	return c.Compile(name)
}

// ValidateValue validates one decoded JSON document against an embedded schema.
func ValidateValue(schema string, b []byte) error {
	s, err := Compile(schema)
	if err != nil {
		return err
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		return err
	}
	return s.Validate(doc)
}

// ValidateFile validates a JSON file against an embedded schema.
func ValidateFile(schema, path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := ValidateValue(schema, b); err != nil {
		return fmt.Errorf("%s: %v", path, err)
	}
	return nil
}

// ValidateDir validates every contract file of a run directory and returns one message per problem, plus
// cross-file checks: every verdict row is counted in clusters.json and summary.json.
func ValidateDir(path string) []string {
	var bad []string
	add := func(err error) {
		if err != nil {
			bad = append(bad, err.Error())
		}
	}
	add(ValidateFile(SchemaManifest, filepath.Join(path, ManifestFile)))
	add(ValidateFile(SchemaClusters, filepath.Join(path, ClustersFile)))
	add(ValidateFile(SchemaSummary, filepath.Join(path, SummaryFile)))
	vs, err := Compile(SchemaVerdict)
	if err != nil {
		return append(bad, err.Error())
	}
	f, err := os.Open(filepath.Join(path, VerdictsFile))
	if err != nil {
		return append(bad, err.Error())
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	rows := 0
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		rows++
		doc, err := jsonschema.UnmarshalJSON(strings.NewReader(line))
		if err == nil {
			err = vs.Validate(doc)
		}
		if err != nil {
			bad = append(bad, fmt.Sprintf("%s:%d: %v", VerdictsFile, n, err))
			if len(bad) > 20 {
				return append(bad, "(more problems not shown)")
			}
		}
	}
	if len(bad) > 0 {
		return bad
	}
	var cl Clusters
	var sum Summary
	if err := ReadJSON(filepath.Join(path, ClustersFile), &cl); err != nil {
		return append(bad, err.Error())
	}
	if err := ReadJSON(filepath.Join(path, SummaryFile), &sum); err != nil {
		return append(bad, err.Error())
	}
	inClusters := 0
	for _, c := range cl.Clusters {
		inClusters += c.Count
	}
	inSummary := 0
	for _, n := range sum.Verdicts {
		inSummary += n
	}
	if inClusters != rows {
		bad = append(bad, fmt.Sprintf("clusters.json counts %d rows, verdicts.jsonl has %d", inClusters, rows))
	}
	if inSummary != rows {
		bad = append(bad, fmt.Sprintf("summary.json counts %d rows, verdicts.jsonl has %d", inSummary, rows))
	}
	if sum.Clusters["total"] != len(cl.Clusters) {
		bad = append(bad, fmt.Sprintf("summary.json counts %d clusters, clusters.json has %d", sum.Clusters["total"], len(cl.Clusters)))
	}
	if sum.Status == StatusUnavailable && rows > 0 {
		bad = append(bad, "an unavailable run must hold no verdict rows")
	}
	return bad
}

// Pretty is a helper for messages: compact JSON of v.
func Pretty(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

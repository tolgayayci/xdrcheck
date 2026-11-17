package main

// SARIF 2.1.0 output (-sarif FILE). x/tools has no SARIF writer, so this is
// the minimal log code-scanning tools read: one run, the rules of this build
// as reportingDescriptors (with their documentation page, guide anchor,
// checklist item and demonstrating corpus entry), and one result per finding.
// Suppressed findings are included with a SARIF suppression (inSource for a
// directive, external for a suppression file), so a viewer can show or hide
// them; file locations are relative to %SRCROOT%, the working directory.

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/tolgayayci/xdrcheck/lint/internal/framework"
	"github.com/tolgayayci/xdrcheck/lint/internal/ruledoc"
)

const sarifSchema = "https://json.schemastore.org/sarif-2.1.0.json"

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool               sarifTool                   `json:"tool"`
	OriginalURIBaseIDs map[string]sarifArtifactLoc `json:"originalUriBaseIds,omitempty"`
	Results            []sarifResult               `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string         `json:"id"`
	Name                 string         `json:"name"`
	ShortDescription     sarifText      `json:"shortDescription"`
	HelpURI              string         `json:"helpUri"`
	DefaultConfiguration sarifRuleConf  `json:"defaultConfiguration"`
	Properties           map[string]any `json:"properties,omitempty"`
}

type sarifRuleConf struct {
	Level   string `json:"level"`
	Enabled bool   `json:"enabled"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID       string             `json:"ruleId"`
	RuleIndex    int                `json:"ruleIndex"`
	Level        string             `json:"level"`
	Message      sarifText          `json:"message"`
	Locations    []sarifLocation    `json:"locations"`
	Suppressions []sarifSuppression `json:"suppressions,omitempty"`
	Properties   map[string]any     `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifactLoc `json:"artifactLocation"`
	Region           sarifRegion      `json:"region"`
}

type sarifArtifactLoc struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
}

type sarifSuppression struct {
	Kind          string `json:"kind"`
	Justification string `json:"justification,omitempty"`
}

// sarifLevel maps a severity onto a SARIF level.
func sarifLevel(s framework.Severity) string {
	switch s {
	case framework.SeverityError:
		return "error"
	case framework.SeverityWarning:
		return "warning"
	}
	return "note"
}

// buildSARIF returns the log for findings; enabled reports whether a rule
// runs under the configuration.
func buildSARIF(findings []framework.Finding, enabled func(framework.Rule) bool) *sarifLog {
	rules := framework.Default.Rules()
	index := map[string]int{}
	driver := sarifDriver{Name: "xdrlint", Version: Version, InformationURI: ruledoc.BaseURL + "README.md"}
	for i, r := range rules {
		index[r.ID] = i
		props := map[string]any{"family": string(r.Family), "tags": []string{"stellar", "xdr", string(r.Family)}}
		if r.Guide != "" {
			props["guide"] = r.Guide
		}
		if r.Checklist != "" {
			props["checklist"] = r.Checklist
		}
		if r.Corpus != "" {
			props["corpus"] = r.Corpus
		}
		driver.Rules = append(driver.Rules, sarifRule{
			ID: r.ID, Name: r.ID, ShortDescription: sarifText{r.Title}, HelpURI: ruledoc.URL(r.ID),
			DefaultConfiguration: sarifRuleConf{Level: sarifLevel(r.Severity), Enabled: enabled(r)},
			Properties:           props,
		})
	}
	run := sarifRun{Tool: sarifTool{Driver: driver}, Results: []sarifResult{}}
	wd, _ := os.Getwd()
	if wd != "" {
		u := url.URL{Scheme: "file", Path: filepath.ToSlash(wd) + "/"}
		run.OriginalURIBaseIDs = map[string]sarifArtifactLoc{"SRCROOT": {URI: u.String()}}
	}
	for _, f := range framework.SortFindings(findings) {
		loc := sarifArtifactLoc{URI: filepath.ToSlash(f.Position.Filename)}
		if rel, err := filepath.Rel(wd, f.Position.Filename); wd != "" && err == nil && !strings.HasPrefix(rel, "..") {
			loc = sarifArtifactLoc{URI: filepath.ToSlash(rel), URIBaseID: "SRCROOT"}
		}
		res := sarifResult{
			RuleID: f.Rule, RuleIndex: index[f.Rule], Level: sarifLevel(f.Severity),
			Message: sarifText{f.Message},
			Locations: []sarifLocation{{PhysicalLocation: sarifPhysical{ArtifactLocation: loc,
				Region: sarifRegion{StartLine: max(f.Position.Line, 1), StartColumn: f.Position.Column}}}},
		}
		res.Properties = map[string]any{}
		if f.Function != "" {
			res.Properties["function"] = f.Function
		}
		if f.Assumption != "" {
			res.Properties["assumption"] = f.Assumption
		}
		if s := f.Suppression; f.Suppressed && s != nil {
			kind := "external"
			if s.Kind == "inline" {
				kind = "inSource"
			}
			res.Suppressions = []sarifSuppression{{Kind: kind, Justification: s.Reason}}
			if s.Finding != "" {
				res.Properties["finding"] = s.Finding
			}
		}
		if len(res.Properties) == 0 {
			res.Properties = nil
		}
		run.Results = append(run.Results, res)
	}
	return &sarifLog{Schema: sarifSchema, Version: "2.1.0", Runs: []sarifRun{run}}
}

func writeSARIF(path string, findings []framework.Finding, enabled func(framework.Rule) bool) error {
	data, err := json.MarshalIndent(buildSARIF(findings, enabled), "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

package report

import (
	"encoding/json"

	"github.com/sriharifortitude/apkwarden/internal/rules"
	"github.com/sriharifortitude/apkwarden/internal/waiver"
)

// SARIF 2.1.0, the subset GitHub code scanning reads: one run, every rule
// declared up front, one result per finding still open. Waived findings
// are left out (that's what a waiver is for) and the JSON report keeps
// them. An indeterminate finding is a "note", not a warning or an error,
// because nothing in the manifest says it's wrong.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string    `json:"id"`
	ShortDescription sarifText `json:"shortDescription"`
	DefaultConfig    struct {
		Level string `json:"level"`
	} `json:"defaultConfiguration"`
	Properties map[string]any `json:"properties"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation struct {
		ArtifactLocation struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
	} `json:"physicalLocation"`
	LogicalLocations []struct {
		FullyQualifiedName string `json:"fullyQualifiedName"`
	} `json:"logicalLocations"`
}

func level(s rules.Severity, status rules.Status) string {
	if status == rules.Indeterminate {
		return "note"
	}
	switch s {
	case rules.Critical, rules.High:
		return "error"
	case rules.Medium:
		return "warning"
	}
	return "note"
}

func (r *Run) SARIF() ([]byte, error) {
	driver := sarifDriver{Name: r.ToolName, Version: r.ToolVer, InformationURI: r.ToolURL}
	for _, rule := range r.Rules {
		sr := sarifRule{ID: rule.ID(), ShortDescription: sarifText{rule.Description()}, Properties: map[string]any{"severity": string(rule.Severity())}}
		sr.DefaultConfig.Level = level(rule.Severity(), rules.Fail)
		driver.Rules = append(driver.Rules, sr)
	}
	results := []sarifResult{}
	for _, i := range r.Items {
		if i.Outcome == waiver.Waived {
			continue
		}
		res := sarifResult{RuleID: i.RuleID, Level: level(i.Severity, i.Status), Message: sarifText{i.Location + ": " + i.Message}}
		var loc sarifLocation
		loc.PhysicalLocation.ArtifactLocation.URI = r.Input
		loc.LogicalLocations = []struct {
			FullyQualifiedName string `json:"fullyQualifiedName"`
		}{{FullyQualifiedName: i.Location}}
		res.Locations = []sarifLocation{loc}
		results = append(results, res)
	}
	b, err := json.MarshalIndent(sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{{Tool: sarifTool{Driver: driver}, Results: results}},
	}, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

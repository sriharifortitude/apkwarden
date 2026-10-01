package report

import (
	"encoding/json"

	"github.com/sriharifortitude/apkwarden/internal/rules"
	"github.com/sriharifortitude/apkwarden/internal/waiver"
)

type jsonRun struct {
	Input    string        `json:"input"`
	Package  string        `json:"package"`
	TargetSD int           `json:"targetSdk"`
	MinSDK   int           `json:"minSdk"`
	FailOn   string        `json:"failOn"`
	Exit     int           `json:"exitCode"`
	Summary  jsonCounts    `json:"summary"`
	Findings []jsonFinding `json:"findings"`
	Unused   []jsonWaiver  `json:"unusedWaivers"`
}

type jsonCounts struct {
	Total         int `json:"total"`
	Failing       int `json:"failing"`
	Waived        int `json:"waived"`
	Expired       int `json:"expiredWaivers"`
	Indeterminate int `json:"indeterminate"`
}

type jsonFinding struct {
	Rule        string      `json:"rule"`
	Severity    string      `json:"severity"`
	Location    string      `json:"location"`
	Status      string      `json:"status"`
	Outcome     string      `json:"outcome"`
	Message     string      `json:"message"`
	Remediation string      `json:"remediation,omitempty"`
	Reference   string      `json:"reference,omitempty"`
	Waiver      *jsonWaiver `json:"waiver,omitempty"`
}

type jsonWaiver struct {
	Rule     string `json:"rule"`
	Location string `json:"location"`
	Reason   string `json:"reason"`
	Expires  string `json:"expires"`
}

func toJSONWaiver(w *waiver.Entry) *jsonWaiver {
	if w == nil {
		return nil
	}
	return &jsonWaiver{w.Rule, w.Location, w.Reason, w.Expires}
}

// JSON renders the full run, waived findings included: it's the report
// that keeps what was accepted, and why, visible.
func (r *Run) JSON() ([]byte, error) {
	c := r.Counts()
	out := jsonRun{
		Input: r.Input, Package: r.Manifest.Package, TargetSD: r.Manifest.SDK.Target, MinSDK: r.Manifest.SDK.Min,
		FailOn: string(r.FailOn), Exit: r.ExitCode(),
		Summary:  jsonCounts(c),
		Findings: []jsonFinding{}, Unused: []jsonWaiver{},
	}
	for _, i := range r.Items {
		outcome := "open"
		switch i.Outcome {
		case waiver.Waived:
			outcome = "waived"
		case waiver.Expired:
			outcome = "waiver-expired"
		}
		if i.Status == rules.Indeterminate && i.Outcome == waiver.NotWaived {
			outcome = "indeterminate"
		}
		out.Findings = append(out.Findings, jsonFinding{
			Rule: i.RuleID, Severity: string(i.Severity), Location: i.Location, Status: string(i.Status), Outcome: outcome,
			Message: i.Message, Remediation: i.Remediation, Reference: i.Reference, Waiver: toJSONWaiver(i.Waiver),
		})
	}
	for _, w := range r.Unused {
		w := w
		out.Unused = append(out.Unused, *toJSONWaiver(&w))
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

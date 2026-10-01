// Package report decides what each finding means for the exit code and
// renders a run as text, JSON or SARIF.
package report

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/sriharifortitude/apkwarden/internal/manifest"
	"github.com/sriharifortitude/apkwarden/internal/rules"
	"github.com/sriharifortitude/apkwarden/internal/waiver"
)

// Item is a finding after waivers have been applied.
type Item struct {
	rules.Finding
	Outcome waiver.Outcome
	Waiver  *waiver.Entry
}

// Failing is whether this item should fail a build at the threshold. Only
// a real failure counts: an indeterminate finding is shown but can't fail
// on its own, since nobody can fix what the manifest doesn't say; a
// waived one doesn't; an expired waiver counts again.
func (i Item) Failing(threshold rules.Severity) bool {
	return i.Status == rules.Fail && i.Outcome != waiver.Waived && i.Severity.AtLeast(threshold)
}

// Run is everything a report needs.
type Run struct {
	Input     string
	Manifest  *manifest.Manifest
	Items     []Item
	Unused    []waiver.Entry
	FailOn    rules.Severity
	Today     time.Time
	Rules     []rules.Rule
	ToolName  string
	ToolVer   string
	ToolURL   string
	WaiverSrc string
}

// Build applies waivers to findings and orders them: failures first, most
// severe first, then by location.
func Build(findings []rules.Finding, w *waiver.File, today time.Time) []Item {
	items := make([]Item, len(findings))
	for i, f := range findings {
		o, entry := w.Apply(f, today)
		items[i] = Item{Finding: f, Outcome: o, Waiver: entry}
	}
	rank := func(i Item) int {
		switch {
		case i.Outcome == waiver.Expired:
			return 0
		case i.Status == rules.Fail && i.Outcome == waiver.NotWaived:
			return 0
		case i.Status == rules.Indeterminate && i.Outcome == waiver.NotWaived:
			return 1
		}
		return 2 // waived
	}
	sort.SliceStable(items, func(a, b int) bool {
		x, y := items[a], items[b]
		if rank(x) != rank(y) {
			return rank(x) < rank(y)
		}
		if x.Severity != y.Severity {
			return x.Severity.AtLeast(y.Severity)
		}
		if x.Location != y.Location {
			return x.Location < y.Location
		}
		return x.RuleID < y.RuleID
	})
	return items
}

// Counts summarises a run.
type Counts struct {
	Total, Failing, Waived, Expired, Indeterminate int
}

func (r *Run) Counts() Counts {
	var c Counts
	c.Total = len(r.Items)
	for _, i := range r.Items {
		switch {
		case i.Outcome == waiver.Waived:
			c.Waived++
		case i.Outcome == waiver.Expired:
			c.Expired++
			if i.Failing(r.FailOn) {
				c.Failing++
			}
		case i.Status == rules.Indeterminate:
			c.Indeterminate++
		case i.Failing(r.FailOn):
			c.Failing++
		}
	}
	return c
}

// ExitCode is 1 when anything fails at the threshold, else 0.
func (r *Run) ExitCode() int {
	for _, i := range r.Items {
		if i.Failing(r.FailOn) {
			return 1
		}
	}
	return 0
}

// Terminal renders the human-readable report.
func (r *Run) Terminal() string {
	var b strings.Builder
	line := func(format string, args ...any) {
		fmt.Fprintf(&b, format+"\n", args...)
	}
	m := r.Manifest
	line("%s  targetSdk %s, minSdk %s, %d components\n", m.Package, sdk(m.SDK.Target), sdk(m.SDK.Min), len(m.Components))

	for _, i := range r.Items {
		label := "FAIL"
		switch {
		case i.Outcome == waiver.Waived:
			label = "waived"
		case i.Outcome == waiver.Expired:
			label = "EXPIRED"
		case i.Status == rules.Indeterminate:
			label = "?"
		}
		line("%-8s %-8s %s  %s", label, i.Severity, i.RuleID, i.Location)
		line("%s%s", indent, i.Message)
		switch {
		case i.Outcome == waiver.Waived:
			line("%swaived until %s: %s", indent, i.Waiver.Expires, i.Waiver.Reason)
		case i.Outcome == waiver.Expired:
			line("%sWAIVER EXPIRED %s: %s", indent, i.Waiver.Expires, i.Waiver.Reason)
			fallthrough
		default:
			if i.Remediation != "" {
				line("%sfix: %s", indent, i.Remediation)
			}
		}
		line("")
	}
	for _, w := range r.Unused {
		line("unused   %s  %s", w.Rule, w.Location)
		line("%smatches no finding: remove it if the component is gone\n", indent)
	}
	c := r.Counts()
	if c.Total == 0 && len(r.Unused) == 0 {
		line("No findings.")
		return b.String()
	}
	line("%d findings: %d failing at %s or above, %d waived, %d expired waivers, %d indeterminate",
		c.Total, c.Failing, strings.ToLower(string(r.FailOn)), c.Waived, c.Expired, c.Indeterminate)
	return b.String()
}

const indent = "         "

func sdk(n int) string {
	switch n {
	case 0:
		return "(unset)"
	case manifest.SDKUnknown:
		return "(not a number)"
	}
	return fmt.Sprint(n)
}

// Package rules holds the checks over a decoded Android manifest.
//
// Each rule returns findings of one of two kinds, never a score:
//
//	Fail           the manifest shows the problem
//	Indeterminate  the deciding value is not in the manifest
//
// The second exists because an attribute can be a resource reference
// (android:debuggable="@bool/is_debug"), whose value lives in
// resources.arsc, which apkwarden does not read. Reporting such a case as
// a pass hides a real problem and reporting it as a failure invents one,
// so it is its own state, and a rule says nothing when the manifest gives
// it nothing to say.
package rules

import (
	"fmt"
	"strings"

	"github.com/sriharifortitude/apkwarden/internal/manifest"
)

type Severity string

const (
	Critical Severity = "CRITICAL"
	High     Severity = "HIGH"
	Medium   Severity = "MEDIUM"
	Low      Severity = "LOW"
)

var severityOrder = map[Severity]int{Low: 0, Medium: 1, High: 2, Critical: 3}

// AtLeast reports whether s is at or above threshold.
func (s Severity) AtLeast(threshold Severity) bool {
	return severityOrder[s] >= severityOrder[threshold]
}

// ParseSeverity reads a --fail-on value.
func ParseSeverity(s string) (Severity, bool) {
	sev := Severity(strings.ToUpper(s))
	switch sev {
	case Critical, High, Medium, Low:
		return sev, true
	}
	return "", false
}

type Status string

const (
	Fail          Status = "fail"
	Indeterminate Status = "indeterminate"
)

// Finding is one rule's verdict on one location.
type Finding struct {
	RuleID   string
	Severity Severity
	// Location is "application" for app-level settings, or "<kind> <class>"
	// for a component, e.g. "service org.example.SyncService".
	Location    string
	Status      Status
	Message     string
	Remediation string
	// Reference names the OWASP MASVS control group the rule belongs to,
	// where one clearly applies. Empty means none is claimed.
	Reference string
}

// Config is what a run can change.
type Config struct {
	// MinTargetSDK is the lowest targetSdkVersion that doesn't trigger
	// target-sdk-below-floor.
	MinTargetSDK int
}

// DefaultConfig is what a run uses unless told otherwise.
func DefaultConfig() Config { return Config{MinTargetSDK: 34} }

type Rule interface {
	ID() string
	Severity() Severity
	Description() string
	Check(m *manifest.Manifest, cfg Config) []Finding
}

var registry []Rule

func register(r Rule) {
	for _, existing := range registry {
		if existing.ID() == r.ID() {
			panic(fmt.Sprintf("rule ID %q registered twice", r.ID()))
		}
	}
	registry = append(registry, r)
}

// All returns every rule in registration order.
func All() []Rule {
	out := make([]Rule, len(registry))
	copy(out, registry)
	return out
}

// RunAll runs every rule.
func RunAll(m *manifest.Manifest, cfg Config) []Finding {
	var out []Finding
	for _, r := range All() {
		out = append(out, r.Check(m, cfg)...)
	}
	return out
}

func newFinding(r Rule, location string, status Status, msg, fix, ref string) Finding {
	return Finding{RuleID: r.ID(), Severity: r.Severity(), Location: location, Status: status, Message: msg, Remediation: fix, Reference: ref}
}

const appLocation = "application"

func componentLocation(c manifest.Component) string {
	name := c.FullName
	if name == "" {
		name = "(unnamed)"
	}
	return c.Kind + " " + name
}

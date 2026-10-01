// Package waiver applies accepted-risk exceptions to findings.
//
// A waiver names one rule at one exact location ("service
// org.example.SyncService"), never a rule everywhere: waiving
// exported-service-unprotected for one service on purpose must not
// silence it for the next service someone adds. It needs a reason and an
// expiry date, and an expired waiver stops suppressing, so the finding
// fails again and someone has to decide again.
package waiver

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/sriharifortitude/apkwarden/internal/rules"
)

type Entry struct {
	Rule     string `yaml:"rule"`
	Location string `yaml:"location"`
	Reason   string `yaml:"reason"`
	Expires  string `yaml:"expires"` // YYYY-MM-DD
}

type File struct {
	Waivers []Entry `yaml:"waivers"`
}

// Parse reads and validates a waiver file. Unknown keys are an error: a
// misspelled "expires" must not quietly become a waiver that never expires.
func Parse(data []byte) (*File, error) {
	var f File
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && !errors.Is(err, io.EOF) { // an empty file is a valid, empty list
		return nil, fmt.Errorf("invalid waiver file: %w", err)
	}
	known := map[string]bool{}
	for _, r := range rules.All() {
		known[r.ID()] = true
	}
	for i, w := range f.Waivers {
		at := fmt.Sprintf("waivers[%d]", i)
		switch {
		case w.Rule == "":
			return nil, fmt.Errorf("%s.rule: required", at)
		case !known[w.Rule]:
			return nil, fmt.Errorf("%s.rule: %q is not a rule (see `apkwarden rules`)", at, w.Rule)
		case w.Location == "":
			return nil, fmt.Errorf("%s.location: required, the exact location as printed, e.g. %q", at, "service org.example.Sync")
		case w.Reason == "":
			return nil, fmt.Errorf("%s.reason: required: say why this is accepted", at)
		case w.Expires == "":
			return nil, fmt.Errorf("%s.expires: required (YYYY-MM-DD): a waiver with no review date is forgetting on purpose", at)
		}
		if _, err := time.Parse("2006-01-02", w.Expires); err != nil {
			return nil, fmt.Errorf("%s.expires: %q is not YYYY-MM-DD", at, w.Expires)
		}
	}
	return &f, nil
}

type Outcome int

const (
	NotWaived Outcome = iota
	Waived
	Expired
)

// Apply says whether a finding is covered, and whether that waiver is
// still in date. The expiry day itself is still covered.
func (f *File) Apply(finding rules.Finding, today time.Time) (Outcome, *Entry) {
	if f == nil {
		return NotWaived, nil
	}
	for i := range f.Waivers {
		w := &f.Waivers[i]
		if w.Rule != finding.RuleID || w.Location != finding.Location {
			continue
		}
		// ISO dates sort as strings, and comparing whole days means the expiry
		// day itself is still covered, whatever the time of day.
		if today.Format("2006-01-02") > w.Expires {
			return Expired, w
		}
		return Waived, w
	}
	return NotWaived, nil
}

// Unused returns the waivers that matched no finding, so a waiver for a
// component that no longer exists is noticed instead of lingering.
func (f *File) Unused(findings []rules.Finding) []Entry {
	if f == nil {
		return nil
	}
	var out []Entry
	for _, w := range f.Waivers {
		used := false
		for _, fi := range findings {
			if fi.RuleID == w.Rule && fi.Location == w.Location {
				used = true
				break
			}
		}
		if !used {
			out = append(out, w)
		}
	}
	return out
}

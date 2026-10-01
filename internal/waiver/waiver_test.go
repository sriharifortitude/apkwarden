package waiver

import (
	"strings"
	"testing"
	"time"

	"github.com/sriharifortitude/apkwarden/internal/rules"
)

const valid = `
waivers:
  - rule: exported-receiver-unprotected
    location: receiver org.example.MediaButtonReceiver
    reason: Android delivers headset button presses to an exported receiver; it cannot be private
    expires: "2027-06-30"
`

func finding(rule, location string) rules.Finding {
	return rules.Finding{RuleID: rule, Location: location, Status: rules.Fail}
}

func day(s string) time.Time {
	d, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(err)
	}
	return d
}

func TestWaiverCoversOnlyItsExactRuleAndLocation(t *testing.T) {
	f, err := Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	today := day("2026-10-01")
	if o, w := f.Apply(finding("exported-receiver-unprotected", "receiver org.example.MediaButtonReceiver"), today); o != Waived || w == nil {
		t.Errorf("exact match: %v", o)
	}
	for _, c := range []rules.Finding{
		finding("exported-receiver-unprotected", "receiver org.example.OtherReceiver"),      // a different component
		finding("exported-service-unprotected", "receiver org.example.MediaButtonReceiver"), // a different rule
	} {
		if o, _ := f.Apply(c, today); o != NotWaived {
			t.Errorf("%+v must not be waived", c)
		}
	}
}

func TestExpiredWaiverNoLongerSuppresses(t *testing.T) {
	f, _ := Parse([]byte(valid))
	fi := finding("exported-receiver-unprotected", "receiver org.example.MediaButtonReceiver")
	for _, c := range []struct {
		today string
		want  Outcome
	}{{"2027-06-29", Waived}, {"2027-06-30", Waived}, {"2027-07-01", Expired}} {
		if got, _ := f.Apply(fi, day(c.today)); got != c.want {
			t.Errorf("on %s: got %v, want %v (the expiry day itself is still covered)", c.today, got, c.want)
		}
	}
	// Late on the expiry day is still the expiry day.
	if got, _ := f.Apply(fi, day("2027-06-30").Add(23*time.Hour+59*time.Minute)); got != Waived {
		t.Errorf("23:59 on the expiry day: got %v", got)
	}
}

func TestParseRefusesIncompleteOrUnknownWaivers(t *testing.T) {
	cases := map[string]string{
		"no rule":         "waivers:\n  - location: service a\n    reason: r\n    expires: \"2027-01-01\"\n",
		"unknown rule":    "waivers:\n  - rule: no-such-rule\n    location: service a\n    reason: r\n    expires: \"2027-01-01\"\n",
		"no location":     "waivers:\n  - rule: debuggable\n    reason: r\n    expires: \"2027-01-01\"\n",
		"no reason":       "waivers:\n  - rule: debuggable\n    location: application\n    expires: \"2027-01-01\"\n",
		"no expiry":       "waivers:\n  - rule: debuggable\n    location: application\n    reason: r\n",
		"bad date":        "waivers:\n  - rule: debuggable\n    location: application\n    reason: r\n    expires: next year\n",
		"misspelled key":  "waivers:\n  - rule: debuggable\n    location: application\n    reason: r\n    expiers: \"2027-01-01\"\n",
		"not yaml at all": "waivers: [unclosed",
	}
	for name, doc := range cases {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// The message for an unknown rule says how to find the right one.
	_, err := Parse([]byte(cases["unknown rule"]))
	if err == nil || !strings.Contains(err.Error(), "apkwarden rules") {
		t.Errorf("err = %v", err)
	}
}

func TestEmptyFileIsAnEmptyList(t *testing.T) {
	f, err := Parse(nil)
	if err != nil || len(f.Waivers) != 0 {
		t.Errorf("empty file: %v, %+v", err, f)
	}
}

func TestUnusedReportsWaiversThatMatchNothing(t *testing.T) {
	f, _ := Parse([]byte(valid))
	if got := f.Unused(nil); len(got) != 1 {
		t.Errorf("a waiver with no matching finding should be reported, got %v", got)
	}
	if got := f.Unused([]rules.Finding{finding("exported-receiver-unprotected", "receiver org.example.MediaButtonReceiver")}); len(got) != 0 {
		t.Errorf("a waiver that matches should not be reported, got %v", got)
	}
	var none *File
	if none.Unused(nil) != nil {
		t.Error("a nil file has nothing unused")
	}
}

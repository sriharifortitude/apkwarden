package report

import (
	"testing"
	"time"

	"github.com/sriharifortitude/apkwarden/internal/manifest"
	"github.com/sriharifortitude/apkwarden/internal/rules"
	"github.com/sriharifortitude/apkwarden/internal/waiver"
)

func f(rule string, sev rules.Severity, status rules.Status, loc string) rules.Finding {
	return rules.Finding{RuleID: rule, Severity: sev, Status: status, Location: loc, Message: "m"}
}

const waivers = `
waivers:
  - rule: exported-service-unprotected
    location: service a.InDate
    reason: r
    expires: "2027-01-01"
  - rule: exported-service-unprotected
    location: service a.Lapsed
    reason: r
    expires: "2026-01-01"
`

func run(t *testing.T, failOn rules.Severity, findings ...rules.Finding) *Run {
	t.Helper()
	w, err := waiver.Parse([]byte(waivers))
	if err != nil {
		t.Fatal(err)
	}
	today := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	return &Run{Manifest: &manifest.Manifest{Package: "a"}, FailOn: failOn, Today: today, Items: Build(findings, w, today)}
}

func TestOrderIsOpenFailuresThenIndeterminateThenWaived(t *testing.T) {
	r := run(t, rules.High,
		f("exported-service-unprotected", rules.High, rules.Fail, "service a.InDate"), // waived
		f("debuggable", rules.Critical, rules.Indeterminate, "application"),
		f("backup-allowed", rules.Medium, rules.Fail, "application"),
		f("debuggable", rules.Critical, rules.Fail, "application"),
		f("exported-service-unprotected", rules.High, rules.Fail, "service a.Lapsed"), // expired: counts again
	)
	var got []string
	for _, i := range r.Items {
		got = append(got, i.RuleID+"|"+i.Location+"|"+string(i.Status))
	}
	want := []string{
		"debuggable|application|fail",
		"exported-service-unprotected|service a.Lapsed|fail",
		"backup-allowed|application|fail",
		"debuggable|application|indeterminate",
		"exported-service-unprotected|service a.InDate|fail",
	}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("position %d: got %q, want %q\nfull: %v", i, got[i], want[i], got)
		}
	}
}

func TestCountsAndExitCode(t *testing.T) {
	r := run(t, rules.High,
		f("exported-service-unprotected", rules.High, rules.Fail, "service a.InDate"),
		f("exported-service-unprotected", rules.High, rules.Fail, "service a.Lapsed"),
		f("backup-allowed", rules.Medium, rules.Fail, "application"),
		f("debuggable", rules.Critical, rules.Indeterminate, "application"),
	)
	c := r.Counts()
	if c.Total != 4 || c.Waived != 1 || c.Expired != 1 || c.Indeterminate != 1 || c.Failing != 1 {
		t.Errorf("counts = %+v (the medium finding is under the high threshold; only the expired waiver fails)", c)
	}
	if r.ExitCode() != 1 {
		t.Errorf("an expired waiver must fail the build")
	}

	r = run(t, rules.High,
		f("exported-service-unprotected", rules.High, rules.Fail, "service a.InDate"),
		f("debuggable", rules.Critical, rules.Indeterminate, "application"),
	)
	if r.ExitCode() != 0 {
		t.Errorf("a waived failure and an indeterminate one must not fail the build, got %+v", r.Counts())
	}

	r = run(t, rules.Medium, f("backup-allowed", rules.Medium, rules.Fail, "application"))
	if r.ExitCode() != 1 {
		t.Errorf("a medium failure fails a medium threshold")
	}
}

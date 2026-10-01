package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sriharifortitude/apkwarden/internal/axmltest"
)

const (
	idName       = 0x01010003
	idExported   = 0x01010010
	idDebuggable = 0x0101000f
	idBackup     = 0x01010280
	idTarget     = 0x01010270
)

func manifestEl(app *axmltest.El, attrs ...axmltest.Attr) *axmltest.El {
	children := []*axmltest.El{{Name: "uses-sdk", Attrs: []axmltest.Attr{axmltest.Int("targetSdkVersion", idTarget, 35)}}}
	if app != nil {
		children = append(children, app)
	}
	return &axmltest.El{
		Name:     "manifest",
		Attrs:    append([]axmltest.Attr{{Name: "package", Type: 0x03, Raw: "com.example.test"}}, attrs...),
		Children: children,
	}
}

// writeAPK writes an APK around the manifest and returns its path.
func writeAPK(t *testing.T, root *axmltest.El) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "app.apk")
	if err := os.WriteFile(path, axmltest.APK(axmltest.Encode(root, axmltest.Options{UTF8: true}), nil), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func debuggableApp() *axmltest.El {
	return &axmltest.El{Name: "application", Attrs: []axmltest.Attr{
		axmltest.Bool("debuggable", idDebuggable, true),
		axmltest.Bool("allowBackup", idBackup, false),
	}}
}

func receiverApp() *axmltest.El {
	return &axmltest.El{Name: "application", Attrs: []axmltest.Attr{axmltest.Bool("allowBackup", idBackup, false)}, Children: []*axmltest.El{{
		Name:  "receiver",
		Attrs: []axmltest.Attr{axmltest.Str("name", idName, ".HeadsetReceiver"), axmltest.Bool("exported", idExported, true)},
	}}}
}

func exec(args ...string) (code int, stdout, stderr string) {
	var out, errb bytes.Buffer
	code = run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func write(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDebuggableAppFailsTheBuild(t *testing.T) {
	code, out, _ := exec("scan", "--today", "2026-10-01", writeAPK(t, manifestEl(debuggableApp())))
	if code != 1 {
		t.Fatalf("exit %d, want 1\n%s", code, out)
	}
	for _, want := range []string{"com.example.test  targetSdk 35", "FAIL     CRITICAL debuggable  application", "adb run-as"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestACleanAppPasses(t *testing.T) {
	clean := &axmltest.El{Name: "application", Attrs: []axmltest.Attr{axmltest.Bool("allowBackup", idBackup, false)}}
	code, out, _ := exec("scan", writeAPK(t, manifestEl(clean)))
	if code != 0 || !strings.Contains(out, "No findings.") {
		t.Errorf("exit %d\n%s", code, out)
	}
}

func TestFailOnThreshold(t *testing.T) {
	apk := writeAPK(t, manifestEl(receiverApp())) // one MEDIUM finding
	for _, c := range []struct {
		level string
		want  int
	}{{"low", 1}, {"medium", 1}, {"high", 0}, {"critical", 0}} {
		if code, out, _ := exec("scan", "--fail-on", c.level, apk); code != c.want {
			t.Errorf("--fail-on %s: exit %d, want %d\n%s", c.level, code, c.want, out)
		}
	}
}

const receiverWaiver = `
waivers:
  - rule: exported-receiver-unprotected
    location: receiver com.example.test.HeadsetReceiver
    reason: Headset buttons are delivered by Android to an exported receiver
    expires: "2027-03-01"
`

func TestWaiverSuppressesUntilItExpires(t *testing.T) {
	apk := writeAPK(t, manifestEl(receiverApp()))
	waivers := write(t, "waivers.yaml", receiverWaiver)

	code, out, _ := exec("scan", "--fail-on", "medium", "--waivers", waivers, "--today", "2026-10-01", apk)
	if code != 0 || !strings.Contains(out, "waived until 2027-03-01: Headset buttons") || !strings.Contains(out, "1 waived") {
		t.Errorf("in date: exit %d\n%s", code, out)
	}

	code, out, _ = exec("scan", "--fail-on", "medium", "--waivers", waivers, "--today", "2027-03-02", apk)
	if code != 1 || !strings.Contains(out, "WAIVER EXPIRED 2027-03-01") || !strings.Contains(out, "1 expired waivers") {
		t.Errorf("expired: exit %d\n%s", code, out)
	}
}

func TestUnusedWaiverIsReported(t *testing.T) {
	clean := &axmltest.El{Name: "application", Attrs: []axmltest.Attr{axmltest.Bool("allowBackup", idBackup, false)}}
	_, out, _ := exec("scan", "--waivers", write(t, "w.yaml", receiverWaiver), "--today", "2026-10-01", writeAPK(t, manifestEl(clean)))
	if !strings.Contains(out, "matches no finding") {
		t.Errorf("a waiver for a component that doesn't exist should be called out:\n%s", out)
	}
}

func TestIndeterminateIsShownButNeverFailsTheBuild(t *testing.T) {
	// debuggable written as a resource reference: its value is not in the manifest.
	app := &axmltest.El{Name: "application", Attrs: []axmltest.Attr{
		axmltest.Ref("debuggable", idDebuggable, 0x7f050001),
		axmltest.Bool("allowBackup", idBackup, false),
	}}
	code, out, _ := exec("scan", "--fail-on", "low", writeAPK(t, manifestEl(app)))
	if code != 0 {
		t.Errorf("exit %d, an unknowable value must not fail a build\n%s", code, out)
	}
	if !strings.Contains(out, "?        CRITICAL debuggable") || !strings.Contains(out, "1 indeterminate") {
		t.Errorf("the indeterminate finding should be shown:\n%s", out)
	}
}

func TestJSONOutput(t *testing.T) {
	apk := writeAPK(t, manifestEl(debuggableApp()))
	code, out, _ := exec("scan", "--format", "json", apk)
	if code != 1 {
		t.Fatalf("exit %d", code)
	}
	var doc struct {
		Package  string `json:"package"`
		Exit     int    `json:"exitCode"`
		Summary  struct{ Total, Failing int }
		Findings []struct{ Rule, Severity, Location, Outcome string }
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if doc.Package != "com.example.test" || doc.Exit != 1 || doc.Summary.Failing != 1 || len(doc.Findings) != 1 {
		t.Errorf("unexpected document: %+v", doc)
	}
	if f := doc.Findings[0]; f.Rule != "debuggable" || f.Severity != "CRITICAL" || f.Location != "application" || f.Outcome != "open" {
		t.Errorf("finding: %+v", f)
	}
}

func TestJSONKeepsWaivedFindingsAndSARIFDropsThem(t *testing.T) {
	apk := writeAPK(t, manifestEl(receiverApp()))
	waivers := write(t, "w.yaml", receiverWaiver)

	_, js, _ := exec("scan", "--format", "json", "--waivers", waivers, "--today", "2026-10-01", apk)
	if !strings.Contains(js, `"outcome": "waived"`) || !strings.Contains(js, "Headset buttons") {
		t.Errorf("JSON should keep the waived finding and its reason:\n%s", js)
	}

	_, sarif, _ := exec("scan", "--format", "sarif", "--waivers", waivers, "--today", "2026-10-01", apk)
	var doc struct {
		Version string
		Runs    []struct {
			Tool struct {
				Driver struct{ Rules []struct{ ID string } }
			}
			Results []struct{ RuleID string }
		}
	}
	if err := json.Unmarshal([]byte(sarif), &doc); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if doc.Version != "2.1.0" || len(doc.Runs) != 1 {
		t.Fatalf("not SARIF 2.1.0: %s", sarif)
	}
	if n := len(doc.Runs[0].Tool.Driver.Rules); n != 12 {
		t.Errorf("SARIF declares %d rules, want all 12", n)
	}
	if n := len(doc.Runs[0].Results); n != 0 {
		t.Errorf("a waived finding must not be a SARIF result, got %d", n)
	}
}

func TestBadInputExitsTwoWithAReason(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		message string
	}{
		{"no such file", []string{"scan", filepath.Join(t.TempDir(), "nope.apk")}, "no such file"},
		{"a source-tree manifest", []string{"scan", write(t, "AndroidManifest.xml", `<?xml version="1.0"?><manifest package="a.b"/>`)}, "plain-text manifest"},
		{"not an apk", []string{"scan", write(t, "notes.txt", "hello world")}, "not an APK"},
		{"a zip with no manifest", []string{"scan", write(t, "x.zip", string(axmltest.Zip(map[string][]byte{"classes.dex": []byte("dex")})))}, "no AndroidManifest.xml"},
		{"bad format", []string{"scan", "--format", "xml", "x"}, "--format"},
		{"bad fail-on", []string{"scan", "--fail-on", "severe", "x"}, "--fail-on"},
		{"bad date", []string{"scan", "--today", "tomorrow", "x"}, "--today"},
		{"two files", []string{"scan", "a", "b"}, "exactly one file"},
		{"unknown flag", []string{"scan", "--frobnicate", "x"}, "frobnicate"},
		{"unknown command", []string{"explode"}, "unknown command"},
		{"invalid waiver file", []string{"scan", "--waivers", write(t, "w.yaml", "waivers:\n  - rule: debuggable\n"), "x"}, "waivers[0].location"},
		{"no command", nil, "usage"},
	}
	for _, c := range cases {
		code, out, errOut := exec(c.args...)
		if code != 2 || !strings.Contains(errOut, c.message) || out != "" {
			t.Errorf("%s: exit %d, stderr %q, stdout %q; want exit 2 and %q on stderr", c.name, code, errOut, out, c.message)
		}
	}
}

func TestRulesCommandListsEveryRule(t *testing.T) {
	code, out, _ := exec("rules")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if code != 0 || len(lines) != 12 || !strings.HasPrefix(lines[0], "debuggable") {
		t.Errorf("exit %d, %d lines:\n%s", code, len(lines), out)
	}
}

func TestMinTargetSDKFlag(t *testing.T) {
	apk := writeAPK(t, manifestEl(&axmltest.El{Name: "application", Attrs: []axmltest.Attr{axmltest.Bool("allowBackup", idBackup, false)}})) // target 35
	if code, _, _ := exec("scan", "--fail-on", "medium", "--min-target-sdk", "36", apk); code != 1 {
		t.Errorf("target 35 under a floor of 36 should fail, exit %d", code)
	}
	if code, _, _ := exec("scan", "--fail-on", "medium", "--min-target-sdk", "35", apk); code != 0 {
		t.Errorf("target 35 at a floor of 35 should pass, exit %d", code)
	}
}

package rules

import (
	"strings"
	"testing"

	"github.com/sriharifortitude/apkwarden/internal/manifest"
)

// base is a manifest every rule is happy with; each test breaks one thing.
func base() *manifest.Manifest {
	return &manifest.Manifest{
		Package:     "com.example",
		SDK:         manifest.SDK{Min: 24, Target: 35},
		AllowBackup: manifest.False,
	}
}

func ruleByID(id string) Rule {
	for _, r := range All() {
		if r.ID() == id {
			return r
		}
	}
	panic("no rule " + id)
}

type verdict struct {
	status   Status
	location string
}

func run(id string, m *manifest.Manifest) []verdict {
	var out []verdict
	for _, f := range ruleByID(id).Check(m, DefaultConfig()) {
		out = append(out, verdict{f.Status, f.Location})
	}
	return out
}

func expect(t *testing.T, id string, m *manifest.Manifest, want ...verdict) {
	t.Helper()
	got := run(id, m)
	if len(got) != len(want) {
		t.Fatalf("%s: got %v, want %v", id, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s: got %v, want %v", id, got, want)
		}
	}
}

func svc(name string, exported manifest.Tri, perm string, actions ...string) manifest.Component {
	c := manifest.Component{Kind: "service", Name: name, FullName: "com.example." + name, Exported: exported, Permission: perm}
	if len(actions) > 0 {
		c.Filters = []manifest.Filter{{Actions: actions}}
	}
	return c
}

func TestRegistryHasUniqueIDsAndDescriptions(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range All() {
		if seen[r.ID()] || r.Description() == "" || r.Severity() == "" {
			t.Errorf("rule %q: duplicate ID, empty description or empty severity", r.ID())
		}
		seen[r.ID()] = true
	}
	if len(seen) != 12 {
		t.Errorf("%d rules registered, the README says 12", len(seen))
	}
}

func TestDebuggable(t *testing.T) {
	m := base()
	expect(t, "debuggable", m)
	m.Debuggable = manifest.True
	expect(t, "debuggable", m, verdict{Fail, "application"})
	m.Debuggable = manifest.Unknown
	expect(t, "debuggable", m, verdict{Indeterminate, "application"})
}

func TestTestOnly(t *testing.T) {
	m := base()
	m.TestOnly = manifest.True
	expect(t, "test-only", m, verdict{Fail, "application"})
}

func TestBackup(t *testing.T) {
	cases := []struct {
		name  string
		edit  func(*manifest.Manifest)
		wants []verdict
	}{
		{"explicitly off", func(m *manifest.Manifest) {}, nil},
		{"on by default", func(m *manifest.Manifest) { m.AllowBackup = manifest.Unset }, []verdict{{Fail, "application"}}},
		{"on explicitly", func(m *manifest.Manifest) { m.AllowBackup = manifest.True }, []verdict{{Fail, "application"}}},
		{"on, with a backup rules file", func(m *manifest.Manifest) { m.AllowBackup = manifest.True; m.DataExtractionRules = true }, nil},
		{"default, with the old-style rules file", func(m *manifest.Manifest) { m.AllowBackup = manifest.Unset; m.FullBackupContent = true }, nil},
		{"unreadable", func(m *manifest.Manifest) { m.AllowBackup = manifest.Unknown }, []verdict{{Indeterminate, "application"}}},
	}
	for _, c := range cases {
		m := base()
		c.edit(m)
		expect(t, "backup-allowed", m, c.wants...)
	}
}

func TestCleartext(t *testing.T) {
	cases := []struct {
		name  string
		edit  func(*manifest.Manifest)
		wants []verdict
	}{
		{"modern target, nothing set", func(m *manifest.Manifest) {}, nil},
		{"explicitly on", func(m *manifest.Manifest) { m.CleartextTraffic = manifest.True }, []verdict{{Fail, "application"}}},
		{"explicitly on, but a network security config overrides", func(m *manifest.Manifest) {
			m.CleartextTraffic = manifest.True
			m.NetworkSecurityConf = true
		}, []verdict{{Indeterminate, "application"}}},
		{"explicitly off", func(m *manifest.Manifest) { m.CleartextTraffic = manifest.False }, nil},
		{"old target, nothing set: the platform default allows it", func(m *manifest.Manifest) { m.SDK.Target = 27 }, []verdict{{Fail, "application"}}},
		{"old target, nothing set, but a config exists we can't read", func(m *manifest.Manifest) {
			m.SDK.Target = 27
			m.NetworkSecurityConf = true
		}, nil},
		{"old target, explicitly off", func(m *manifest.Manifest) { m.SDK.Target = 21; m.CleartextTraffic = manifest.False }, nil},
		{"target 28 is where the default flips", func(m *manifest.Manifest) { m.SDK.Target = 28 }, nil},
		{"unreadable flag", func(m *manifest.Manifest) { m.CleartextTraffic = manifest.Unknown }, []verdict{{Indeterminate, "application"}}},
		{"unreadable target, nothing set", func(m *manifest.Manifest) { m.SDK.Target = manifest.SDKUnknown }, []verdict{{Indeterminate, "application"}}},
	}
	for _, c := range cases {
		m := base()
		c.edit(m)
		got := run("cleartext-allowed", m)
		if len(got) != len(c.wants) || (len(got) == 1 && got[0] != c.wants[0]) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.wants)
		}
	}
}

func TestSharedUserID(t *testing.T) {
	m := base()
	m.SharedUserID = "com.example.shared"
	expect(t, "shared-user-id", m, verdict{Fail, "application"})
}

func TestTargetSDKFloor(t *testing.T) {
	m := base()
	m.SDK.Target = 33
	expect(t, "target-sdk-below-floor", m, verdict{Fail, "application"})
	m.SDK.Target = 34
	expect(t, "target-sdk-below-floor", m)
	m.SDK.Target = manifest.SDKUnknown
	expect(t, "target-sdk-below-floor", m, verdict{Indeterminate, "application"})

	m.SDK.Target = 30
	if got := ruleByID("target-sdk-below-floor").Check(m, Config{MinTargetSDK: 30}); len(got) != 0 {
		t.Errorf("a floor of 30 must accept target 30, got %v", got)
	}
}

func TestExportedServices(t *testing.T) {
	m := base()
	m.Components = []manifest.Component{
		svc("Open", manifest.True, ""),
		svc("Guarded", manifest.True, "com.example.permission.SYNC"),
		svc("Private", manifest.False, ""),
		svc("ImplicitlyExported", manifest.Unset, "", "com.example.ACTION"),
		svc("NoFilterNoFlag", manifest.Unset, ""),
		svc("Unreadable", manifest.Unknown, ""),
		{Kind: "service", Name: "Off", FullName: "com.example.Off", Exported: manifest.True, Enabled: manifest.False},
		{Kind: "receiver", Name: "R", FullName: "com.example.R", Exported: manifest.True}, // a different rule's business
	}
	expect(t, "exported-service-unprotected", m,
		verdict{Fail, "service com.example.Open"},
		verdict{Fail, "service com.example.ImplicitlyExported"},
		verdict{Indeterminate, "service com.example.Unreadable"},
	)
}

func TestExportedReceiversExemptSystemOnlyBroadcasts(t *testing.T) {
	recv := func(name string, actions ...string) manifest.Component {
		c := svc(name, manifest.True, "", actions...)
		c.Kind = "receiver"
		return c
	}
	m := base()
	m.Components = []manifest.Component{
		recv("Boot", "android.intent.action.BOOT_COMPLETED"),
		recv("BootAndMore", "android.intent.action.BOOT_COMPLETED", "android.intent.action.MY_PACKAGE_REPLACED"),
		recv("Mixed", "android.intent.action.BOOT_COMPLETED", "com.example.CUSTOM"),
		recv("Custom", "com.example.CUSTOM"),
		recv("NoFilter"),
	}
	expect(t, "exported-receiver-unprotected", m,
		verdict{Fail, "receiver com.example.Mixed"},
		verdict{Fail, "receiver com.example.Custom"},
		verdict{Fail, "receiver com.example.NoFilter"},
	)
}

func TestProtectedBroadcastListIsLoaded(t *testing.T) {
	if len(protectedBroadcasts) < 500 {
		t.Fatalf("only %d protected broadcasts loaded", len(protectedBroadcasts))
	}
	for _, a := range []string{"android.intent.action.BOOT_COMPLETED", "android.intent.action.TIME_SET"} {
		if !protectedBroadcasts[a] {
			t.Errorf("%s should be protected", a)
		}
	}
	for _, a := range []string{"android.intent.action.VIEW", "android.intent.action.SEND", "com.example.CUSTOM"} {
		if protectedBroadcasts[a] {
			t.Errorf("%s must not be treated as protected", a)
		}
	}
}

func provider(name string, exported manifest.Tri, mutate func(*manifest.Component)) manifest.Component {
	c := manifest.Component{Kind: "provider", Name: name, FullName: "com.example." + name, Exported: exported, Authorities: "com.example." + strings.ToLower(name)}
	if mutate != nil {
		mutate(&c)
	}
	return c
}

func TestExportedProviders(t *testing.T) {
	m := base()
	m.Components = []manifest.Component{
		provider("Open", manifest.True, nil),
		provider("Private", manifest.False, nil),
		provider("Guarded", manifest.True, func(c *manifest.Component) { c.Permission = "p" }),
		provider("BothSides", manifest.True, func(c *manifest.Component) { c.ReadPermission, c.WritePermission = "r", "w" }),
		provider("ReadOnlyGuard", manifest.True, func(c *manifest.Component) { c.ReadPermission = "r" }),
		provider("Paths", manifest.True, func(c *manifest.Component) { c.PathPerms = 2 }),
	}
	expect(t, "exported-provider-unprotected", m,
		verdict{Fail, "provider com.example.Open"},
		verdict{Fail, "provider com.example.ReadOnlyGuard"},
		verdict{Indeterminate, "provider com.example.Paths"},
	)
	got := ruleByID("exported-provider-unprotected").Check(m, DefaultConfig())
	if !strings.Contains(got[0].Message, "content://com.example.open") {
		t.Errorf("the message should name the authority: %q", got[0].Message)
	}
	if !strings.Contains(got[1].Message, "writes don't") {
		t.Errorf("a read-only guard should say writes are open: %q", got[1].Message)
	}
}

func TestBlanketURIGrantNeedsExportAndNoPatterns(t *testing.T) {
	m := base()
	grant := func(c *manifest.Component) { c.GrantURI = manifest.True }
	m.Components = []manifest.Component{
		provider("FileProviderStyle", manifest.False, grant), // the standard, correct setup
		provider("ExportedBlanket", manifest.True, grant),
		provider("ExportedWithPatterns", manifest.True, func(c *manifest.Component) { grant(c); c.GrantURIRules = 2 }),
		provider("ExportedNoGrant", manifest.True, nil),
	}
	expect(t, "provider-blanket-uri-grant", m, verdict{Fail, "provider com.example.ExportedBlanket"})
}

func TestWeakCustomPermission(t *testing.T) {
	m := base()
	m.Permissions = []manifest.Permission{
		{Name: "com.example.perm.WEAK"}, // protectionLevel absent: normal
		{Name: "com.example.perm.NORMAL", LevelSet: true, ProtectionLevel: 0},
		{Name: "com.example.perm.SIG", LevelSet: true, ProtectionLevel: 2},
		{Name: "com.example.perm.SIGPRIV", LevelSet: true, ProtectionLevel: 2 | 0x10},
	}
	m.Components = []manifest.Component{
		svc("A", manifest.True, "com.example.perm.WEAK"),
		svc("B", manifest.True, "com.example.perm.NORMAL"),
		svc("C", manifest.True, "com.example.perm.SIG"),
		svc("D", manifest.True, "com.example.perm.SIGPRIV"),
		svc("E", manifest.False, "com.example.perm.WEAK"), // not exported: the permission is moot
		svc("F", manifest.True, "android.permission.BIND_JOB_SERVICE"),
		provider("G", manifest.True, func(c *manifest.Component) { c.WritePermission = "com.example.perm.WEAK" }),
	}
	expect(t, "weak-custom-permission", m,
		verdict{Fail, "service com.example.A"},
		verdict{Fail, "service com.example.B"},
		verdict{Fail, "provider com.example.G"},
	)
}

func TestWeblinkVerificationIsAskedOncePerApp(t *testing.T) {
	link := func(verify manifest.Tri) manifest.Filter {
		return manifest.Filter{
			Actions:    []string{"android.intent.action.VIEW"},
			Categories: []string{"android.intent.category.BROWSABLE"},
			Schemes:    []string{"https"},
			AutoVerify: verify,
		}
	}
	activity := func(name string, filters ...manifest.Filter) manifest.Component {
		return manifest.Component{Kind: "activity", Name: name, FullName: "com.example." + name, Filters: filters}
	}

	m := base()
	m.Components = []manifest.Component{activity("A", link(manifest.Unset)), activity("B", link(manifest.False))}
	expect(t, "weblink-not-verified", m, verdict{Fail, "activity com.example.A"})

	// One verified filter anywhere is enough, as Android verifies every web-link host then.
	m.Components = []manifest.Component{activity("A", link(manifest.Unset)), activity("B", link(manifest.True))}
	expect(t, "weblink-not-verified", m)

	// A custom scheme isn't a web link.
	custom := manifest.Filter{Actions: []string{"android.intent.action.VIEW"}, Categories: []string{"android.intent.category.BROWSABLE"}, Schemes: []string{"myapp"}}
	m.Components = []manifest.Component{activity("A", custom)}
	expect(t, "weblink-not-verified", m)

	m.Components = []manifest.Component{activity("A", link(manifest.Unknown))}
	expect(t, "weblink-not-verified", m, verdict{Indeterminate, "activity com.example.A"})
}

func TestACleanManifestHasNoFindings(t *testing.T) {
	if got := RunAll(base(), DefaultConfig()); len(got) != 0 {
		t.Errorf("base manifest produced findings: %+v", got)
	}
}

func TestSeverityOrderingAndParsing(t *testing.T) {
	if !Critical.AtLeast(High) || Low.AtLeast(Medium) || !Medium.AtLeast(Medium) {
		t.Error("severity ordering is wrong")
	}
	if s, ok := ParseSeverity("high"); !ok || s != High {
		t.Errorf("ParseSeverity(high) = %v, %v", s, ok)
	}
	if _, ok := ParseSeverity("severe"); ok {
		t.Error("an unknown severity must be refused")
	}
}

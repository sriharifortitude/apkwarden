package manifest_test

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/sriharifortitude/apkwarden/internal/apk"
	"github.com/sriharifortitude/apkwarden/internal/axml"
	"github.com/sriharifortitude/apkwarden/internal/axmltest"
	"github.com/sriharifortitude/apkwarden/internal/manifest"
)

const (
	idName        = 0x01010003
	idExported    = 0x01010010
	idDebuggable  = 0x0101000f
	idBackup      = 0x01010280
	idMinSDK      = 0x0101020c
	idTargetSDK   = 0x01010270
	idProtLevel   = 0x01010009
	idPermission  = 0x01010006
	idScheme      = 0x01010027
	idAutoVerify  = 0x010104ee
	idCleartext   = 0x010104ec
	idGrantURI    = 0x0101001b
	idAuthorities = 0x01010018
)

func parse(t *testing.T, root *axmltest.El, opt axmltest.Options) *manifest.Manifest {
	t.Helper()
	doc, err := axml.Parse(axmltest.Encode(root, opt))
	if err != nil {
		t.Fatal(err)
	}
	m, err := manifest.Parse(doc)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func name(v string) axmltest.Attr { return axmltest.Str("name", idName, v) }

func app(attrs []axmltest.Attr, children ...*axmltest.El) *axmltest.El {
	return &axmltest.El{Name: "application", Attrs: attrs, Children: children}
}

func manifestEl(children ...*axmltest.El) *axmltest.El {
	return &axmltest.El{
		Name:     "manifest",
		Attrs:    []axmltest.Attr{{Name: "package", Type: 0x03, Raw: "com.example"}},
		Children: children,
	}
}

func TestApplicationFlagsAndTheThreeStates(t *testing.T) {
	m := parse(t, manifestEl(app([]axmltest.Attr{
		axmltest.Bool("debuggable", idDebuggable, true),
		axmltest.Bool("allowBackup", idBackup, false),
		axmltest.Ref("usesCleartextTraffic", idCleartext, 0x7f050001), // @bool/...
	})), axmltest.Options{})
	if m.Debuggable != manifest.True || m.AllowBackup != manifest.False {
		t.Errorf("debuggable=%v allowBackup=%v", m.Debuggable, m.AllowBackup)
	}
	if m.CleartextTraffic != manifest.Unknown {
		t.Errorf("a resource reference must be Unknown, got %v", m.CleartextTraffic)
	}
	if m.TestOnly != manifest.Unset {
		t.Errorf("absent attribute must be Unset, got %v", m.TestOnly)
	}
}

func TestObfuscatedManifestParsesTheSame(t *testing.T) {
	root := manifestEl(
		&axmltest.El{Name: "uses-sdk", Attrs: []axmltest.Attr{axmltest.Int("minSdkVersion", idMinSDK, 24), axmltest.Int("targetSdkVersion", idTargetSDK, 34)}},
		app([]axmltest.Attr{axmltest.Bool("debuggable", idDebuggable, true)},
			&axmltest.El{Name: "service", Attrs: []axmltest.Attr{name(".Sync"), axmltest.Bool("exported", idExported, true)}}),
	)
	plain := parse(t, root, axmltest.Options{})
	blanked := parse(t, root, axmltest.Options{Obfuscate: true, UTF8: true})
	if !reflect.DeepEqual(plain, blanked) {
		t.Errorf("blanked attribute names changed the result:\n plain   %+v\n blanked %+v", plain, blanked)
	}
	if blanked.Debuggable != manifest.True || blanked.SDK.Target != 34 || len(blanked.Components) != 1 {
		t.Errorf("blanked manifest lost data: %+v", blanked)
	}
}

func TestComponentNamesAreQualifiedAgainstThePackage(t *testing.T) {
	m := parse(t, manifestEl(app(nil,
		&axmltest.El{Name: "service", Attrs: []axmltest.Attr{name(".SyncService")}},
		&axmltest.El{Name: "receiver", Attrs: []axmltest.Attr{name("BootReceiver")}},
		&axmltest.El{Name: "activity", Attrs: []axmltest.Attr{name("org.other.Main")}},
	)), axmltest.Options{})
	var got []string
	for _, c := range m.Components {
		got = append(got, c.FullName)
	}
	want := []string{"com.example.SyncService", "com.example.BootReceiver", "org.other.Main"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestEffectiveExport(t *testing.T) {
	filter := &axmltest.El{Name: "intent-filter"}
	cases := []struct {
		name     string
		attrs    []axmltest.Attr
		children []*axmltest.El
		exported bool
		known    bool
	}{
		{"explicit true", []axmltest.Attr{axmltest.Bool("exported", idExported, true)}, nil, true, true},
		{"explicit false beats a filter", []axmltest.Attr{axmltest.Bool("exported", idExported, false)}, []*axmltest.El{filter}, false, true},
		{"filter and no attribute: exported by default", nil, []*axmltest.El{filter}, true, true},
		{"nothing: private", nil, nil, false, true},
		{"reference: can't be known", []axmltest.Attr{axmltest.Ref("exported", idExported, 0x7f050002)}, nil, false, false},
	}
	for _, c := range cases {
		el := &axmltest.El{Name: "service", Attrs: append([]axmltest.Attr{name(".S")}, c.attrs...), Children: c.children}
		m := parse(t, manifestEl(app(nil, el)), axmltest.Options{})
		gotExp, gotKnown := m.Components[0].EffectivelyExported()
		if gotExp != c.exported || gotKnown != c.known {
			t.Errorf("%s: got (%v, %v), want (%v, %v)", c.name, gotExp, gotKnown, c.exported, c.known)
		}
	}
}

func TestIntentFiltersAreRead(t *testing.T) {
	launcher := &axmltest.El{Name: "intent-filter", Children: []*axmltest.El{
		{Name: "action", Attrs: []axmltest.Attr{name("android.intent.action.MAIN")}},
		{Name: "category", Attrs: []axmltest.Attr{name("android.intent.category.LAUNCHER")}},
	}}
	web := &axmltest.El{Name: "intent-filter", Attrs: []axmltest.Attr{axmltest.Bool("autoVerify", idAutoVerify, true)}, Children: []*axmltest.El{
		{Name: "action", Attrs: []axmltest.Attr{name("android.intent.action.VIEW")}},
		{Name: "category", Attrs: []axmltest.Attr{name("android.intent.category.BROWSABLE")}},
		{Name: "data", Attrs: []axmltest.Attr{axmltest.Str("scheme", idScheme, "https")}},
	}}
	m := parse(t, manifestEl(app(nil, &axmltest.El{Name: "activity", Attrs: []axmltest.Attr{name(".Main")}, Children: []*axmltest.El{launcher, web}})), axmltest.Options{})
	f := m.Components[0].Filters
	if len(f) != 2 || !f[0].IsLauncher() || f[0].IsWebLink() {
		t.Fatalf("launcher filter misread: %+v", f)
	}
	if !f[1].IsWebLink() || f[1].IsLauncher() || f[1].AutoVerify != manifest.True {
		t.Errorf("web link filter misread: %+v", f[1])
	}
}

func TestPermissionProtectionLevels(t *testing.T) {
	perm := func(n string, level *int) *axmltest.El {
		el := &axmltest.El{Name: "permission", Attrs: []axmltest.Attr{name(n)}}
		if level != nil {
			el.Attrs = append(el.Attrs, axmltest.Int("protectionLevel", idProtLevel, *level))
		}
		return el
	}
	sig, sigPriv, dang := 2, 2|0x10, 1
	m := parse(t, manifestEl(perm("a.NONE", nil), perm("a.SIG", &sig), perm("a.SIGPRIV", &sigPriv), perm("a.DANGER", &dang)), axmltest.Options{})
	got := map[string]int{}
	for _, p := range m.Permissions {
		got[p.Name] = p.Base()
	}
	want := map[string]int{"a.NONE": 0, "a.SIG": 2, "a.SIGPRIV": 2, "a.DANGER": 1}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if m.Permissions[0].LevelSet {
		t.Errorf("an absent protectionLevel must not read as set")
	}
}

func TestTargetSDKDefaults(t *testing.T) {
	sdk := func(attrs ...axmltest.Attr) manifest.SDK {
		return parse(t, manifestEl(&axmltest.El{Name: "uses-sdk", Attrs: attrs}), axmltest.Options{}).SDK
	}
	if got := sdk(axmltest.Int("minSdkVersion", idMinSDK, 21)); got.Target != 21 {
		t.Errorf("target without targetSdkVersion should be minSdkVersion, got %+v", got)
	}
	if got := parse(t, manifestEl(), axmltest.Options{}).SDK; got.Target != 1 {
		t.Errorf("no uses-sdk at all targets API 1, got %+v", got)
	}
	codename := sdk(axmltest.Int("minSdkVersion", idMinSDK, 24), axmltest.Str("targetSdkVersion", idTargetSDK, "VanillaIceCream"))
	if codename.Target != manifest.SDKUnknown {
		t.Errorf("a codename target is not a number, got %+v", codename)
	}
}

func TestRootMustBeManifest(t *testing.T) {
	doc, err := axml.Parse(axmltest.Encode(&axmltest.El{Name: "resources"}, axmltest.Options{}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manifest.Parse(doc); err == nil || !strings.Contains(err.Error(), "<resources>") {
		t.Errorf("err = %v", err)
	}
}

// --- against Android's source and real apps -----------------------------

// TestAttrIDsMatchAndroidSource compares the table with the IDs extracted
// verbatim from AOSP's public-final.xml (testdata/android-attr-ids.txt).
func TestAttrIDsMatchAndroidSource(t *testing.T) {
	f, err := os.Open(filepath.Join("..", "..", "testdata", "android-attr-ids.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	want := map[string]uint32{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		id, err := strconv.ParseUint(strings.TrimPrefix(parts[1], "0x"), 16, 32)
		if err != nil {
			t.Fatalf("%q: %v", line, err)
		}
		want[parts[0]] = uint32(id)
	}
	if got := manifest.AttrIDs(); !reflect.DeepEqual(got, want) {
		t.Errorf("attribute ID table differs from AOSP:\n got  %v\n want %v", got, want)
	}
}

type expected struct {
	Package        string   `json:"package"`
	VersionName    string   `json:"versionName"`
	MinSDK         int      `json:"minSdk"`
	TargetSDK      int      `json:"targetSdk"`
	UsesPermission []string `json:"usesPermission"`
}

func realAPKs(t *testing.T) (dir string, want map[string]expected) {
	t.Helper()
	dir = os.Getenv("APKWARDEN_APKS")
	if dir == "" {
		t.Skip("APKWARDEN_APKS not set; run testdata/fetch-apks.sh to enable the real-APK tests")
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "fdroid-index-expected.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	return dir, want
}

func loadReal(t *testing.T, path string) (*axml.Document, *manifest.Manifest) {
	t.Helper()
	data, err := apk.ReadManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := axml.Parse(data)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	m, err := manifest.Parse(doc)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return doc, m
}

// The expected values were not produced by this code: they are the
// package, SDK levels and permissions F-Droid's own indexer published for
// each of these exact files (testdata/fdroid-index-expected.json).
func TestRealAPKsAgreeWithFDroidsIndex(t *testing.T) {
	dir, want := realAPKs(t)
	for file, exp := range want {
		_, m := loadReal(t, filepath.Join(dir, file))
		if m.Package != exp.Package {
			t.Errorf("%s: package %q, F-Droid says %q", file, m.Package, exp.Package)
		}
		if m.SDK.Min != exp.MinSDK || m.SDK.Target != exp.TargetSDK {
			t.Errorf("%s: SDK min/target %d/%d, F-Droid says %d/%d", file, m.SDK.Min, m.SDK.Target, exp.MinSDK, exp.TargetSDK)
		}
		got := append([]string(nil), m.UsesPermission...)
		sort.Strings(got)
		if !reflect.DeepEqual(got, exp.UsesPermission) {
			t.Errorf("%s: permissions differ from F-Droid's list\n got  %v\n want %v", file, got, exp.UsesPermission)
		}
		if len(m.Components) == 0 {
			t.Errorf("%s: no components decoded", file)
		}
	}
}

// Every attribute with both a name string and a resource ID in a real
// manifest must agree with the table, so an ID typo is caught against the
// files Android itself runs.
func TestAttrIDsAgreeWithRealManifests(t *testing.T) {
	dir, want := realAPKs(t)
	table := manifest.AttrIDs()
	seen := 0
	for file := range want {
		doc, _ := loadReal(t, filepath.Join(dir, file))
		var walk func(*axml.Element)
		walk = func(e *axml.Element) {
			for _, a := range e.Attrs {
				if id, ok := table[a.Name]; ok && a.IsAndroid() {
					seen++
					if a.ResourceID != id {
						t.Errorf("%s: android:%s is %#x in the APK, %#x in the table", file, a.Name, a.ResourceID, id)
					}
				}
			}
			for _, c := range e.Children {
				walk(c)
			}
		}
		walk(doc.Root)
	}
	if seen < 100 {
		t.Errorf("only %d table attributes seen across the real manifests; the check isn't exercising much", seen)
	}
}

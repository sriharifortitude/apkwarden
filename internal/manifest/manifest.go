// Package manifest turns a decoded AndroidManifest.xml tree into the typed
// facts the rules reason about.
package manifest

import (
	"strings"

	"github.com/sriharifortitude/apkwarden/internal/axml"
)

// Tri is a boolean attribute that can also be absent or unknowable.
//
// An attribute written as a resource reference ("@bool/debug_build") holds
// a resource ID, and its value lives in resources.arsc, which isn't read.
// Calling that false would hide a real finding and calling it true would
// invent one, so it's its own state and the rules report it as such.
type Tri uint8

const (
	Unset   Tri = iota // attribute not present
	True               // present and true
	False              // present and false
	Unknown            // present, but a reference or a type this can't read
)

func (t Tri) String() string {
	return [...]string{"unset", "true", "false", "unknown"}[t]
}

// SDK is the uses-sdk element. Zero means the attribute is absent, and
// SDKUnknown means it is present as something that isn't a plain integer
// (a codename such as "UpsideDownCake", or a reference).
type SDK struct {
	Min, Target int
}

const SDKUnknown = -1

// Filter is one intent-filter.
type Filter struct {
	Actions    []string
	Categories []string
	Schemes    []string
	AutoVerify Tri
}

func (f Filter) has(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// IsLauncher is the filter that makes an activity the app's icon in the launcher.
func (f Filter) IsLauncher() bool {
	return f.has(f.Actions, "android.intent.action.MAIN") && f.has(f.Categories, "android.intent.category.LAUNCHER")
}

// IsWebLink is a filter that opens http(s) URLs from a browser or another app.
func (f Filter) IsWebLink() bool {
	if !f.has(f.Actions, "android.intent.action.VIEW") || !f.has(f.Categories, "android.intent.category.BROWSABLE") {
		return false
	}
	return f.has(f.Schemes, "http") || f.has(f.Schemes, "https")
}

// Component is an activity, activity-alias, service, receiver or provider.
type Component struct {
	Kind            string
	Name            string // as written
	FullName        string // resolved against the package
	Exported        Tri
	Enabled         Tri
	Permission      string
	ReadPermission  string
	WritePermission string
	GrantURI        Tri // provider android:grantUriPermissions
	Authorities     string
	Filters         []Filter
	PathPerms       int // <path-permission> children
	GrantURIRules   int // <grant-uri-permission> children
}

// Permission is a <permission> declared by the app.
type Permission struct {
	Name            string
	ProtectionLevel int  // raw value; only the low four bits are the base level
	LevelSet        bool // false: attribute absent, so "normal"
}

// Base returns the base protection level: 0 normal, 1 dangerous,
// 2 signature, 3 signatureOrSystem (deprecated). The other bits are flags
// such as privileged and development that widen who can hold a signature
// permission, and don't change the base.
func (p Permission) Base() int { return p.ProtectionLevel & 0xF }

// Manifest is everything the rules read.
type Manifest struct {
	Package        string
	SharedUserID   string
	SDK            SDK
	UsesPermission []string
	Permissions    []Permission
	Components     []Component

	// <application> attributes.
	Debuggable          Tri
	TestOnly            Tri
	AllowBackup         Tri
	CleartextTraffic    Tri
	NetworkSecurityConf bool // attribute present (its target is in resources.arsc)
	FullBackupContent   bool
	DataExtractionRules bool
}

// Parse extracts a Manifest from a decoded document.
func Parse(doc *axml.Document) (*Manifest, error) {
	root := doc.Root
	if root.Name != "manifest" {
		return nil, &NotAManifestError{Root: root.Name}
	}
	m := &Manifest{}
	// "package" is the one unnamespaced attribute on <manifest>.
	for _, a := range root.Attrs {
		if a.Namespace == "" && a.Name == "package" {
			m.Package = a.Raw
		}
	}
	m.SharedUserID = str(root, "sharedUserId")

	for _, el := range root.Children {
		switch el.Name {
		case "uses-sdk":
			m.SDK = SDK{Min: intAttr(el, "minSdkVersion"), Target: intAttr(el, "targetSdkVersion")}
		case "uses-permission", "uses-permission-sdk-23":
			if n := str(el, "name"); n != "" {
				m.UsesPermission = append(m.UsesPermission, n)
			}
		case "permission":
			p := Permission{Name: str(el, "name")}
			if a, ok := get(el, "protectionLevel"); ok {
				p.LevelSet = true
				p.ProtectionLevel = int(a.Data)
			}
			m.Permissions = append(m.Permissions, p)
		case "application":
			m.application(el)
		}
	}
	// With no targetSdkVersion, Android treats the app as targeting its
	// minSdkVersion (and 1 if that's absent too).
	if m.SDK.Target == 0 {
		if m.SDK.Min > 0 {
			m.SDK.Target = m.SDK.Min
		} else if m.SDK.Min == 0 {
			m.SDK.Target = 1
		}
	}
	return m, nil
}

// NotAManifestError is returned when the root element isn't <manifest>.
type NotAManifestError struct{ Root string }

func (e *NotAManifestError) Error() string {
	return "the root element is <" + e.Root + ">, not <manifest>"
}

func (m *Manifest) application(app *axml.Element) {
	m.Debuggable = boolAttr(app, "debuggable")
	m.TestOnly = boolAttr(app, "testOnly")
	m.AllowBackup = boolAttr(app, "allowBackup")
	m.CleartextTraffic = boolAttr(app, "usesCleartextTraffic")
	_, m.NetworkSecurityConf = get(app, "networkSecurityConfig")
	_, m.FullBackupContent = get(app, "fullBackupContent")
	_, m.DataExtractionRules = get(app, "dataExtractionRules")

	for _, el := range app.Children {
		switch el.Name {
		case "activity", "activity-alias", "service", "receiver", "provider":
			m.Components = append(m.Components, m.component(el))
		}
	}
}

func (m *Manifest) component(el *axml.Element) Component {
	c := Component{
		Kind:            el.Name,
		Name:            str(el, "name"),
		Exported:        boolAttr(el, "exported"),
		Enabled:         boolAttr(el, "enabled"),
		Permission:      str(el, "permission"),
		ReadPermission:  str(el, "readPermission"),
		WritePermission: str(el, "writePermission"),
		GrantURI:        boolAttr(el, "grantUriPermissions"),
		Authorities:     str(el, "authorities"),
	}
	c.FullName = m.qualify(c.Name)
	for _, ch := range el.Children {
		switch ch.Name {
		case "intent-filter":
			f := Filter{AutoVerify: boolAttr(ch, "autoVerify")}
			for _, x := range ch.Children {
				switch x.Name {
				case "action":
					f.Actions = append(f.Actions, str(x, "name"))
				case "category":
					f.Categories = append(f.Categories, str(x, "name"))
				case "data":
					if s := str(x, "scheme"); s != "" {
						f.Schemes = append(f.Schemes, s)
					}
				}
			}
			c.Filters = append(c.Filters, f)
		case "path-permission":
			c.PathPerms++
		case "grant-uri-permission":
			c.GrantURIRules++
		}
	}
	return c
}

// qualify resolves a component's android:name the way Android does: a
// leading dot, or a bare class name with no dot, is relative to the package.
func (m *Manifest) qualify(name string) string {
	switch {
	case name == "":
		return ""
	case strings.HasPrefix(name, "."):
		return m.Package + name
	case !strings.Contains(name, "."):
		return m.Package + "." + name
	}
	return name
}

// Exported reports whether other apps can start or bind to the component,
// and says why in a form fit for a message.
//
// An explicit android:exported wins. Without one, a component is exported
// if it has an intent filter, and not otherwise. That default is what
// Android applies to apps targeting API 30 and below; an app targeting 31
// or higher with a filter and no android:exported isn't installable, so for
// it the question doesn't arise, and the rules report that case separately.
func (c Component) EffectivelyExported() (exported bool, known bool) {
	switch c.Exported {
	case True:
		return true, true
	case False:
		return false, true
	case Unknown:
		return false, false
	}
	return len(c.Filters) > 0, true
}

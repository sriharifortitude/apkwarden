package rules

import (
	_ "embed"
	"strconv"
	"strings"

	"github.com/sriharifortitude/apkwarden/internal/manifest"
)

func init() {
	register(exportedProvider{})
	register(exportedService{})
	register(exportedReceiver{})
	register(providerBlanketURIGrant{})
	register(weakCustomPermission{})
	register(weblinkNotVerified{})
}

// The broadcasts only the system can send, from AOSP's own manifest.
// Android refuses to deliver one sent by any other app, even with the
// receiver named explicitly, so a receiver that listens for nothing else
// is not reachable by another app however it is exported.
//
//go:embed protected-broadcasts.txt
var protectedBroadcastsFile string

var protectedBroadcasts = func() map[string]bool {
	m := map[string]bool{}
	for _, line := range strings.Split(protectedBroadcastsFile, "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			m[line] = true
		}
	}
	return m
}()

// reach says whether other apps can call a component.
type reach int

const (
	unreachable reach = iota
	reachable
	unknownReach
)

func reachOf(c manifest.Component) reach {
	if c.Enabled == manifest.False {
		return unreachable // a disabled component can't be started by anyone
	}
	exported, known := c.EffectivelyExported()
	switch {
	case !known:
		return unknownReach
	case exported:
		return reachable
	}
	return unreachable
}

// --- exported provider --------------------------------------------------------

type exportedProvider struct{}

func (exportedProvider) ID() string         { return "exported-provider-unprotected" }
func (exportedProvider) Severity() Severity { return High }
func (exportedProvider) Description() string {
	return "a content provider other apps can query, with no permission guarding reads and writes"
}

func (r exportedProvider) Check(m *manifest.Manifest, _ Config) []Finding {
	const ref = "MASVS-PLATFORM-1"
	var out []Finding
	for _, c := range m.Components {
		if c.Kind != "provider" {
			continue
		}
		loc := componentLocation(c)
		switch reachOf(c) {
		case unknownReach:
			out = append(out, newFinding(r, loc, Indeterminate, "android:exported is a resource reference, so whether other apps can reach this provider isn't in the manifest", "set it to a literal", ref))
			continue
		case unreachable:
			continue
		}
		reads, writes := c.Permission != "" || c.ReadPermission != "", c.Permission != "" || c.WritePermission != ""
		switch {
		case reads && writes:
			continue
		case c.PathPerms > 0:
			out = append(out, newFinding(r, loc, Indeterminate,
				"exported with "+plural(c.PathPerms, "path-permission rule")+" but no provider-wide permission: those paths are guarded and the rest of the provider may not be; which paths each rule covers isn't analysed",
				"add a provider-level android:permission so any path without its own rule is guarded too", ref))
		default:
			what := "no permission guards reads or writes"
			if reads && !writes {
				what = "reads need a permission but writes don't"
			} else if writes && !reads {
				what = "writes need a permission but reads don't"
			}
			out = append(out, newFinding(r, loc, Fail,
				"exported to every app on the device, and "+what+authoritiesNote(c),
				`set android:exported="false", or require a signature-level permission with android:permission`, ref))
		}
	}
	return out
}

func authoritiesNote(c manifest.Component) string {
	if c.Authorities == "" {
		return ""
	}
	return " (content://" + strings.SplitN(c.Authorities, ";", 2)[0] + ")"
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return strconv.Itoa(n) + " " + noun + "s"
}

// --- exported service ---------------------------------------------------------

type exportedService struct{}

func (exportedService) ID() string         { return "exported-service-unprotected" }
func (exportedService) Severity() Severity { return High }
func (exportedService) Description() string {
	return "a service any app on the device can start or bind to, with no permission required"
}

func (r exportedService) Check(m *manifest.Manifest, _ Config) []Finding {
	return unprotectedByKind(r, m, "service", "start or bind to")
}

// --- exported receiver --------------------------------------------------------

type exportedReceiver struct{}

func (exportedReceiver) ID() string         { return "exported-receiver-unprotected" }
func (exportedReceiver) Severity() Severity { return Medium }
func (exportedReceiver) Description() string {
	return "a broadcast receiver any app on the device can send to, with no permission required"
}

func (r exportedReceiver) Check(m *manifest.Manifest, _ Config) []Finding {
	return unprotectedByKind(r, m, "receiver", "send broadcasts to")
}

func unprotectedByKind(r Rule, m *manifest.Manifest, kind, verb string) []Finding {
	const ref = "MASVS-PLATFORM-1"
	var out []Finding
	for _, c := range m.Components {
		if c.Kind != kind {
			continue
		}
		loc := componentLocation(c)
		switch reachOf(c) {
		case unknownReach:
			out = append(out, newFinding(r, loc, Indeterminate, "android:exported is a resource reference, so whether other apps can reach this "+kind+" isn't in the manifest", "set it to a literal", ref))
			continue
		case unreachable:
			continue
		}
		if c.Permission != "" {
			continue
		}
		if kind == "receiver" && onlySystemBroadcasts(c) {
			continue
		}
		out = append(out, newFinding(r, loc, Fail,
			"exported, so every app on the device can "+verb+" it, and no android:permission is required"+filterNote(c),
			`set android:exported="false" if only this app needs it, or require a signature-level permission with android:permission`, ref))
	}
	return out
}

// onlySystemBroadcasts: the receiver has intent filters and every action in
// them is a protected broadcast.
func onlySystemBroadcasts(c manifest.Component) bool {
	actions := 0
	for _, f := range c.Filters {
		for _, a := range f.Actions {
			actions++
			if !protectedBroadcasts[a] {
				return false
			}
		}
	}
	return actions > 0
}

func filterNote(c manifest.Component) string {
	var actions []string
	for _, f := range c.Filters {
		actions = append(actions, f.Actions...)
		if len(actions) >= 3 {
			break
		}
	}
	switch {
	case len(actions) > 0:
		return " (listens for " + strings.Join(actions[:min(len(actions), 3)], ", ") + ")"
	case c.Exported == manifest.True:
		return " (explicitly exported, no intent filter)"
	}
	return ""
}

// --- provider blanket URI grants ------------------------------------------------

type providerBlanketURIGrant struct{}

func (providerBlanketURIGrant) ID() string         { return "provider-blanket-uri-grant" }
func (providerBlanketURIGrant) Severity() Severity { return High }
func (providerBlanketURIGrant) Description() string {
	return "an exported provider that lets any caller be granted access to every URI it serves"
}

func (r providerBlanketURIGrant) Check(m *manifest.Manifest, _ Config) []Finding {
	var out []Finding
	for _, c := range m.Components {
		// A non-exported provider with grantUriPermissions="true" is the
		// normal FileProvider setup: only URIs the app itself hands out in
		// an intent are opened up. It's the combination with an exported
		// provider that has no such control.
		if c.Kind != "provider" || c.GrantURI != manifest.True || c.GrantURIRules > 0 || reachOf(c) != reachable {
			continue
		}
		out = append(out, newFinding(r, componentLocation(c), Fail,
			`android:grantUriPermissions="true" with no <grant-uri-permission> patterns on a provider that is also exported: a caller can be granted temporary access to any URI the provider serves`+authoritiesNote(c),
			"list only the paths that may be granted with <grant-uri-permission>, or make the provider non-exported", "MASVS-PLATFORM-1"))
	}
	return out
}

// --- weak custom permission ------------------------------------------------------

type weakCustomPermission struct{}

func (weakCustomPermission) ID() string         { return "weak-custom-permission" }
func (weakCustomPermission) Severity() Severity { return High }
func (weakCustomPermission) Description() string {
	return "an exported component guarded by a custom permission any app can obtain, which is no guard"
}

func (r weakCustomPermission) Check(m *manifest.Manifest, _ Config) []Finding {
	weak := map[string]bool{}
	for _, p := range m.Permissions {
		// "normal" is also what an absent protectionLevel means.
		if p.Name != "" && p.Base() == 0 {
			weak[p.Name] = true
		}
	}
	if len(weak) == 0 {
		return nil
	}
	var out []Finding
	for _, c := range m.Components {
		if reachOf(c) != reachable {
			continue
		}
		for _, used := range []string{c.Permission, c.ReadPermission, c.WritePermission} {
			if used != "" && weak[used] {
				out = append(out, newFinding(r, componentLocation(c), Fail,
					"protected by "+used+", which this app declares with protectionLevel normal: any app can list it in its manifest and be granted it at install time without asking the user",
					`declare the permission with android:protectionLevel="signature" so only apps signed with your key can hold it`, "MASVS-PLATFORM-1"))
				break
			}
		}
	}
	return out
}

// --- web links not verified ---------------------------------------------------------

type weblinkNotVerified struct{}

func (weblinkNotVerified) ID() string         { return "weblink-not-verified" }
func (weblinkNotVerified) Severity() Severity { return Low }
func (weblinkNotVerified) Description() string {
	return "the app claims http(s) links but never asks Android to verify it owns them, so another app can claim the same links"
}

func (r weblinkNotVerified) Check(m *manifest.Manifest, _ Config) []Finding {
	// Android verifies the hosts of every web-link filter in the app when at
	// least one of them sets android:autoVerify="true", so the question is
	// asked once for the whole manifest, not per filter.
	var holders []string
	for _, c := range m.Components {
		for _, f := range c.Filters {
			if !f.IsWebLink() {
				continue
			}
			switch f.AutoVerify {
			case manifest.True:
				return nil
			case manifest.Unknown:
				return []Finding{newFinding(r, componentLocation(c), Indeterminate, "android:autoVerify on a web-link filter is a resource reference", "set it to a literal", "MASVS-PLATFORM-1")}
			}
			holders = append(holders, componentLocation(c))
		}
	}
	if len(holders) == 0 {
		return nil
	}
	return []Finding{newFinding(r, holders[0], Fail,
		"opens http(s) links ("+plural(len(holders), "browsable filter")+" in the app) and none sets android:autoVerify=\"true\": without a verified Digital Asset Links association, another app can register the same links and Android may offer it, or open it, instead",
		`add android:autoVerify="true" to the filter and publish /.well-known/assetlinks.json on each host`, "MASVS-PLATFORM-1")}
}

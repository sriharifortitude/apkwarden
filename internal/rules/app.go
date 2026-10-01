package rules

import (
	"strconv"

	"github.com/sriharifortitude/apkwarden/internal/manifest"
)

func init() {
	register(debuggable{})
	register(testOnly{})
	register(backupAllowed{})
	register(cleartextAllowed{})
	register(sharedUserID{})
	register(targetSDKBelowFloor{})
}

// --- debuggable -------------------------------------------------------------

type debuggable struct{}

func (debuggable) ID() string         { return "debuggable" }
func (debuggable) Severity() Severity { return Critical }
func (debuggable) Description() string {
	return "the app is built debuggable, so anyone with the APK can attach a debugger and read or change its memory and private files"
}

func (r debuggable) Check(m *manifest.Manifest, _ Config) []Finding {
	switch m.Debuggable {
	case manifest.True:
		return []Finding{newFinding(r, appLocation, Fail,
			"android:debuggable is true: `adb run-as` opens the app's private data directory and a debugger can attach, on a device that isn't rooted",
			`remove android:debuggable, or set it to false; release build types do this by default, so look for a manifest override or a debuggable release variant`,
			"")}
	case manifest.Unknown:
		return []Finding{newFinding(r, appLocation, Indeterminate,
			"android:debuggable is a resource reference, whose value is not in the manifest",
			"set it to a literal, or check the resolved value in the built APK with `aapt2 dump xmltree`", "")}
	}
	return nil
}

// --- test-only --------------------------------------------------------------

type testOnly struct{}

func (testOnly) ID() string         { return "test-only" }
func (testOnly) Severity() Severity { return Medium }
func (testOnly) Description() string {
	return "the app is marked testOnly, which Android refuses to install normally and which signals a debug or CI build that was shipped"
}

func (r testOnly) Check(m *manifest.Manifest, _ Config) []Finding {
	switch m.TestOnly {
	case manifest.True:
		return []Finding{newFinding(r, appLocation, Fail,
			"android:testOnly is true: this build was meant for test devices, not distribution",
			"build the release variant; an IDE run-configuration APK carries this flag", "")}
	case manifest.Unknown:
		return []Finding{newFinding(r, appLocation, Indeterminate, "android:testOnly is a resource reference", "set it to a literal", "")}
	}
	return nil
}

// --- backup-allowed ---------------------------------------------------------

type backupAllowed struct{}

func (backupAllowed) ID() string         { return "backup-allowed" }
func (backupAllowed) Severity() Severity { return Medium }
func (backupAllowed) Description() string {
	return "the app's private data can be copied off the device by adb backup or cloud backup, and nothing limits which files"
}

func (r backupAllowed) Check(m *manifest.Manifest, _ Config) []Finding {
	const ref = "MASVS-STORAGE-2"
	if m.AllowBackup == manifest.Unknown {
		return []Finding{newFinding(r, appLocation, Indeterminate, "android:allowBackup is a resource reference", "set it to a literal", ref)}
	}
	if m.AllowBackup == manifest.False {
		return nil
	}
	// Backup is on, explicitly or by default. A backup-rules file means
	// someone decided what goes in it: fullBackupContent up to Android 11,
	// dataExtractionRules from Android 12. Their contents are in
	// resources.arsc and aren't inspected, which is why this stops here.
	if m.FullBackupContent || m.DataExtractionRules {
		return nil
	}
	how := "by default (the attribute is absent)"
	if m.AllowBackup == manifest.True {
		how = "explicitly"
	}
	return []Finding{newFinding(r, appLocation, Fail,
		"backup is allowed "+how+" and no backup rules file (fullBackupContent or dataExtractionRules) limits what is backed up",
		`set android:allowBackup="false", or add android:dataExtractionRules and android:fullBackupContent that exclude tokens, databases and caches`,
		ref)}
}

// --- cleartext-allowed ------------------------------------------------------

type cleartextAllowed struct{}

func (cleartextAllowed) ID() string         { return "cleartext-allowed" }
func (cleartextAllowed) Severity() Severity { return High }
func (cleartextAllowed) Description() string {
	return "the app is allowed to use plain http:// connections, which anyone on the network path can read or alter"
}

// Android 9 (API 28) turned cleartext traffic off by default for apps
// targeting it. Below that, an app with no setting allows it.
const cleartextDefaultOffFrom = 28

func (r cleartextAllowed) Check(m *manifest.Manifest, _ Config) []Finding {
	const ref = "MASVS-NETWORK-1"
	switch m.CleartextTraffic {
	case manifest.Unknown:
		return []Finding{newFinding(r, appLocation, Indeterminate, "android:usesCleartextTraffic is a resource reference", "set it to a literal", ref)}
	case manifest.True:
		if m.NetworkSecurityConf {
			// From API 24, a network security config takes precedence and
			// this attribute is ignored. The config's contents aren't read.
			return []Finding{newFinding(r, appLocation, Indeterminate,
				"android:usesCleartextTraffic is true, but a network security config is present and takes precedence on Android 7+; its rules are not inspected",
				"check the config's <base-config> and <domain-config> cleartextTrafficPermitted values", ref)}
		}
		return []Finding{newFinding(r, appLocation, Fail,
			"android:usesCleartextTraffic is true: every connection may use http://",
			`remove it or set it to false, and use https:// everywhere; if one host really needs http, allow just that domain in a network security config`, ref)}
	case manifest.Unset:
		if m.NetworkSecurityConf {
			return nil // governed by a config this tool doesn't read
		}
		switch {
		case m.SDK.Target == manifest.SDKUnknown:
			return []Finding{newFinding(r, appLocation, Indeterminate,
				"no android:usesCleartextTraffic, and targetSdkVersion isn't a number, so the platform default for cleartext can't be determined", "set targetSdkVersion to an API level", ref)}
		case m.SDK.Target < cleartextDefaultOffFrom:
			return []Finding{newFinding(r, appLocation, Fail,
				"targetSdkVersion is "+strconv.Itoa(m.SDK.Target)+" and android:usesCleartextTraffic is not set: below API 28 that means plain http:// is allowed",
				`raise targetSdkVersion to 28 or higher, or set android:usesCleartextTraffic="false"`, ref)}
		}
	}
	return nil
}

// --- shared-user-id ---------------------------------------------------------

type sharedUserID struct{}

func (sharedUserID) ID() string         { return "shared-user-id" }
func (sharedUserID) Severity() Severity { return Low }
func (sharedUserID) Description() string {
	return "the app shares a Linux user ID with others, so they can read each other's files and use each other's permissions"
}

func (r sharedUserID) Check(m *manifest.Manifest, _ Config) []Finding {
	if m.SharedUserID == "" {
		return nil
	}
	return []Finding{newFinding(r, appLocation, Fail,
		"android:sharedUserId is "+strconv.Quote(m.SharedUserID)+": every app signed with the same key that declares it runs as the same Linux user, with access to the same private files. Deprecated since Android 10",
		"remove it; share data through a content provider or a bound service with a signature permission", "")}
}

// --- target-sdk-below-floor ---------------------------------------------------

type targetSDKBelowFloor struct{}

func (targetSDKBelowFloor) ID() string         { return "target-sdk-below-floor" }
func (targetSDKBelowFloor) Severity() Severity { return Medium }
func (targetSDKBelowFloor) Description() string {
	return "the app targets an old Android version, so newer platform protections (restricted storage, background limits, explicit exports) are switched off for it"
}

func (r targetSDKBelowFloor) Check(m *manifest.Manifest, cfg Config) []Finding {
	const ref = "MASVS-CODE-1"
	switch {
	case m.SDK.Target == manifest.SDKUnknown:
		return []Finding{newFinding(r, appLocation, Indeterminate, "targetSdkVersion isn't a plain number (a preview codename or a reference)", "set it to the API level", ref)}
	case m.SDK.Target < cfg.MinTargetSDK:
		return []Finding{newFinding(r, appLocation, Fail,
			"targetSdkVersion is "+strconv.Itoa(m.SDK.Target)+", below the floor of "+strconv.Itoa(cfg.MinTargetSDK)+": Android applies the compatibility behaviour of that older version to this app",
			"raise targetSdkVersion and fix what the newer behaviour changes; --min-target-sdk sets the floor (the default is a judgement, not a store rule)", ref)}
	}
	return nil
}

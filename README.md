# apkwarden

[![CI](https://github.com/sriharifortitude/apkwarden/actions/workflows/ci.yml/badge.svg)](https://github.com/sriharifortitude/apkwarden/actions/workflows/ci.yml)

Reads the `AndroidManifest.xml` inside a built APK and reports insecure
settings: debuggable builds, exported components with no permission,
backups with no rules, cleartext traffic, and a few more. Twelve checks,
no Android SDK, no Java, no device. A single Go binary that decodes
Android's binary XML format itself. MIT.

It's the mobile counterpart to
[tfwarden](https://github.com/sriharifortitude/tfwarden) (Terraform),
[kubeshield](https://github.com/sriharifortitude/kubeshield) (Kubernetes
manifests) and [apilint](https://github.com/sriharifortitude/apilint)
(OpenAPI): read a configuration artifact, apply rules, make the result a
CI gate with accepted risks recorded as expiring waivers.

Here it is on a real app, [AntennaPod](https://f-droid.org/packages/de.danoeh.antennapod/)
3.12.0 from F-Droid, byte-for-byte the file F-Droid's index lists
(`testdata/apks.sha256`):

<!-- antennapod:start -->
```
de.danoeh.antennapod  targetSdk 36, minSdk 23, 37 components

FAIL     HIGH     exported-service-unprotected  service de.danoeh.antennapod.playback.service.Media3PlaybackService
         exported, so every app on the device can start or bind to it, and no android:permission is required (listens for androidx.media3.session.MediaSessionService, androidx.media3.session.MediaLibraryService, de.danoeh.antennapod.intents.PLAYBACK_SERVICE_MEDIA3)
         fix: set android:exported="false" if only this app needs it, or require a signature-level permission with android:permission

FAIL     MEDIUM   backup-allowed  application
         backup is allowed explicitly and no backup rules file (fullBackupContent or dataExtractionRules) limits what is backed up
         fix: set android:allowBackup="false", or add android:dataExtractionRules and android:fullBackupContent that exclude tokens, databases and caches

FAIL     MEDIUM   exported-receiver-unprotected  receiver androidx.media3.session.MediaButtonReceiver
         exported, so every app on the device can send broadcasts to it, and no android:permission is required (listens for android.intent.action.MEDIA_BUTTON)
         fix: set android:exported="false" if only this app needs it, or require a signature-level permission with android:permission

FAIL     MEDIUM   exported-receiver-unprotected  receiver de.danoeh.antennapod.net.download.service.feed.FeedUpdateReceiver
         exported, so every app on the device can send broadcasts to it, and no android:permission is required (explicitly exported, no intent filter)
         fix: set android:exported="false" if only this app needs it, or require a signature-level permission with android:permission

FAIL     MEDIUM   exported-receiver-unprotected  receiver de.danoeh.antennapod.ui.widget.PlayerWidget
         exported, so every app on the device can send broadcasts to it, and no android:permission is required (listens for android.appwidget.action.APPWIDGET_UPDATE, de.danoeh.antennapod.FORCE_WIDGET_UPDATE, de.danoeh.antennapod.STOP_WIDGET_UPDATE)
         fix: set android:exported="false" if only this app needs it, or require a signature-level permission with android:permission

?        HIGH     cleartext-allowed  application
         android:usesCleartextTraffic is true, but a network security config is present and takes precedence on Android 7+; its rules are not inspected
         fix: check the config's <base-config> and <domain-config> cleartextTrafficPermitted values

6 findings: 1 failing at high or above, 0 waived, 0 expired waivers, 1 indeterminate
```
<!-- antennapod:end -->

One reviewer's reading of why three of those components are exported
(`examples/antennapod-waivers.yaml`: a reason and an expiry for each, naming
one rule at one exact component) separates what's accepted from what still
needs a person (headlines only, from the same scan):

<!-- waived:start -->
```
FAIL     MEDIUM   backup-allowed  application
FAIL     MEDIUM   exported-receiver-unprotected  receiver de.danoeh.antennapod.net.download.service.feed.FeedUpdateReceiver
?        HIGH     cleartext-allowed  application
waived   HIGH     exported-service-unprotected  service de.danoeh.antennapod.playback.service.Media3PlaybackService
waived   MEDIUM   exported-receiver-unprotected  receiver androidx.media3.session.MediaButtonReceiver
waived   MEDIUM   exported-receiver-unprotected  receiver de.danoeh.antennapod.ui.widget.PlayerWidget
6 findings: 0 failing at high or above, 3 waived, 0 expired waivers, 1 indeterminate
```
<!-- waived:end -->

The findings are checked against the raw manifest, not only against the
tool's own logic. AntennaPod's `allowBackup` is `true` with no
`fullBackupContent` or `dataExtractionRules` attribute, its
`usesCleartextTraffic` is `true` with a `networkSecurityConfig` present, and
`FeedUpdateReceiver` is `exported="true"` with no filter and no permission:
each was read directly from the decoded attributes. Whether any of it
matters for AntennaPod is the maintainers' call. apkwarden says what the
manifest declares.

## The rules

<!-- rules:start -->
```
debuggable                     CRITICAL the app is built debuggable, so anyone with the APK can attach a debugger and read or change its memory and private files
test-only                      MEDIUM   the app is marked testOnly, which Android refuses to install normally and which signals a debug or CI build that was shipped
backup-allowed                 MEDIUM   the app's private data can be copied off the device by adb backup or cloud backup, and nothing limits which files
cleartext-allowed              HIGH     the app is allowed to use plain http:// connections, which anyone on the network path can read or alter
shared-user-id                 LOW      the app shares a Linux user ID with others, so they can read each other's files and use each other's permissions
target-sdk-below-floor         MEDIUM   the app targets an old Android version, so newer platform protections (restricted storage, background limits, explicit exports) are switched off for it
exported-provider-unprotected  HIGH     a content provider other apps can query, with no permission guarding reads and writes
exported-service-unprotected   HIGH     a service any app on the device can start or bind to, with no permission required
exported-receiver-unprotected  MEDIUM   a broadcast receiver any app on the device can send to, with no permission required
provider-blanket-uri-grant     HIGH     an exported provider that lets any caller be granted access to every URI it serves
weak-custom-permission         HIGH     an exported component guarded by a custom permission any app can obtain, which is no guard
weblink-not-verified           LOW      the app claims http(s) links but never asks Android to verify it owns them, so another app can claim the same links
```
<!-- rules:end -->

Severities are about what an attacker with the APK, or an app on the same
phone, gets. `target-sdk-below-floor` takes `--min-target-sdk`, because the
right floor is a decision about your own release process (the default, 34, is
a judgement and not a store requirement). The OWASP MASVS control groups in
the output (`MASVS-PLATFORM-1`, `-NETWORK-1`, `-STORAGE-2`, `-CODE-1`) are
the group each rule belongs to, not a claim of conformance.

Exported-component rules model what Android does, not a simple flag check:
a component with an intent filter and no `android:exported` is exported on
apps targeting Android 11 or lower; a disabled component isn't reachable; a
receiver that listens only for protected system broadcasts (such as
`BOOT_COMPLETED`) can't be reached by another app however it's exported, so
it isn't flagged, using the 636 protected broadcasts declared in Android's own
manifest ([ADR 3](docs/adr/0003-model-android-not-a-flag.md)); a provider with
only `<path-permission>` rules is reported as indeterminate, not as safe or
unsafe.

## Indeterminate is a result

An attribute can be a resource reference, such as
`android:debuggable="@bool/is_debug"`, whose value is in `resources.arsc`, which
apkwarden doesn't read. Calling that false hides a real problem, and calling it
true invents one. So it's reported as `?`, shown in the output and the JSON,
and never fails a build by itself, because nobody can fix what the manifest
doesn't say. The same goes for a `usesCleartextTraffic="true"` overridden by a
network security config whose contents aren't read
([ADR 2](docs/adr/0002-unknown-is-not-false.md)).

## Why it decodes the binary format itself

The manifest inside an APK is Android's compiled binary XML. Every other tool
reaches it through apktool or `aapt2`, which means Java or the Android build
tools. The format is small and documented in AOSP, so
[`internal/axml`](internal/axml/axml.go) reads it directly: string pools in
both encodings, the attribute resource-ID table, namespaces, elements.
[ADR 1](docs/adr/0001-decode-the-binary-manifest-ourselves.md) has the
reasoning. What makes that safe:

- **An APK is hostile input.** Every offset is bounds-checked and string
  counts, attribute counts and nesting depth are capped. The decoder is fuzzed
  on its own, and so is the whole path (zip, decoder, manifest model, every
  rule): several million inputs each run, no panics. A test caught that
  removing one bounds check changed no result, and now plants a string that
  overruns its pool to cover it. The zip reader refuses a manifest entry
  declaring more than 16 MB, since that size is the file's to choose.
- **It's checked against sources it didn't write.** For the three real apps,
  package name, min and target SDK, and the *complete* permission list match what
  F-Droid's own indexer published for each file. Every framework attribute ID
  matches Android's `public-final.xml` and the IDs inside the real manifests.
- **Obfuscated manifests work.** Hardening tools blank attribute-name strings
  and leave only resource IDs, since that's what Android itself looks up. The
  test encoder builds such a manifest and gets the same result.

## Usage

```bash
go install github.com/sriharifortitude/apkwarden/cmd/apkwarden@v0.1.0

apkwarden scan app-release.apk
apkwarden scan --waivers waivers.yaml --fail-on medium app-release.apk
apkwarden scan --format sarif app-release.apk > apkwarden.sarif   # GitHub code scanning
apkwarden rules
```

Exit codes: `0` nothing failing at `--fail-on` (default `high`), `1` something
is, `2` the input couldn't be read. A waiver needs `rule`, `location` (exactly
as printed), `reason` and `expires`; an expired waiver stops suppressing, so the
finding fails again; an unknown key is an error, so a misspelled `expires` can't
become a waiver that never expires; a waiver that matches nothing is reported.
Waived findings stay in the JSON report with their reasons, and are left out of
SARIF.

Give it the APK, not a source-tree `AndroidManifest.xml`: the source file is
plain text and misses what the build merges in from libraries (a library's
exported services land in the app's manifest), so it would be misleading to
scan. It says so.

## What it does not do

- **Doesn't read `resources.arsc`.** A resource reference is indeterminate,
  and a network security config isn't opened, so a cleartext setting it
  controls isn't judged. This is the largest gap.
- **The manifest only.** Nothing in the DEX code (hardcoded keys, WebView
  settings, weak crypto), no native libraries, no signing check, no
  runtime behaviour. A clean result is a clean manifest, not a secure app.
- **No app bundles.** `.aab` has the manifest in protobuf form, and split APKs
  are read one at a time.
- **No exploit proof.** An exported service is reachable; whether anything
  harmful happens on a call depends on its code.
- **The targetSdk floor is a judgement**, and the protected-broadcast list
  is Android's current one: an older device protects fewer broadcasts.
- **Three real apps.** The decoder is verified against those, plus synthetic
  and fuzzed input. NewPipe was meant to be a fourth but F-Droid's server
  returned errors that day, so nothing was claimed about it.

## Testing

```bash
go test ./...                       # unit, synthetic-APK and CLI tests; the real-APK tests skip
./testdata/fetch-apks.sh            # downloads 3 APKs from F-Droid, refusing any whose SHA-256 differs
APKWARDEN_APKS=.apks go test ./...  # adds the real-APK tests
go test ./cmd/apkwarden -fuzz FuzzWholePipeline -fuzztime 60s
```

The tests plant bugs in the rules (an ignored permission, a wrong API cutoff,
a skipped backup-rules check) and each is caught by more than one test. CI
runs `go vet`, `staticcheck`, the race detector, fetches the three APKs
(cached after the first run), and diffs the example output above against the
real tool's. It also scans the full history with
[credsweep](https://github.com/sriharifortitude/credsweep).

## Licence

[MIT](LICENSE).

# ADR 3: the exported-component rules model Android, not a flag

## Status
Accepted

## Context
"Exported component with no permission" sounds like one check: look for
`android:exported="true"`. A flag check gets three cases wrong, each of which
follows from how Android itself treats the attribute.

1. **The default depends on the filter.** A component with no
   `android:exported` is exported if it has an intent filter and private
   otherwise, for apps targeting Android 11 or lower. A flag-only check
   misses every implicitly exported component.
2. **Some exported receivers can't be reached.** A receiver that listens
   only for protected system broadcasts (`BOOT_COMPLETED`, `TIME_SET` and
   so on) is safe however it's exported: Android refuses to deliver one of
   those broadcasts from any app but the system, even to a receiver named
   explicitly. A flag check reports them as exposed when they aren't.
   Receivers listening for anything else, including a mix of one system
   action and one custom one, are still flagged.
3. **Providers have two sides.** A provider needs a permission for reads
   and one for writes. A provider guarded on only one of them is reported
   with the unguarded side named, and one with only `<path-permission>`
   rules is indeterminate: those paths are guarded, the rest may not be, and
   which paths each rule covers isn't analysed.

## Decision
- Reachability follows Android's rules: explicit `exported` wins; otherwise
  an intent filter means exported; `enabled="false"` means unreachable.
- The protected-broadcast list isn't written from memory. It's the 636
  `<protected-broadcast>` entries from AOSP's
  `frameworks/base/core/res/AndroidManifest.xml`, embedded with its source
  URL and fetch date (`internal/rules/protected-broadcasts.txt`). A test
  checks that `BOOT_COMPLETED` is in it and `VIEW` and `SEND` aren't.
- A custom permission counts as weak only if this app declares it with
  protection level `normal` (or none, which means normal). Any app can hold a
  normal permission without the user being asked, so guarding a component with
  one isn't a guard. Platform and other apps' permissions aren't judged: this
  tool can't see their level.
- Web links are checked once per app, not per filter. Android's App Links
  documentation describes `autoVerify="true"` on one filter as enough for the
  system to verify the app's web-link hosts, and the rule follows that
  reading, so a per-filter check would flag filters that are covered. This is
  the one rule whose behaviour comes from documentation and not from a
  decoded file or a source list, and it is Low severity for that reason too.
- A non-exported provider with `grantUriPermissions="true"` is the standard
  FileProvider setup and isn't flagged; the blanket-grant rule needs the
  provider to be exported and to have no `<grant-uri-permission>` patterns.

## Consequences
- What's left is real exposure, which the app may still have a reason for.
  On AntennaPod, three of the six findings are media-button, widget and
  media-session components that Android's own mechanisms deliver to; the
  README waives those with reasons and an expiry. On KDE Connect the open
  finding that stands out is `com.android.mms.transaction.TransactionService`,
  exported with no filter and no permission, which is worth a person's look
  rather than a waiver.
- The protected-broadcast list reflects current Android. An older
  device protects fewer broadcasts, so a receiver exempted here could be
  reachable there.
- A provider using only path permissions needs a person to read it.

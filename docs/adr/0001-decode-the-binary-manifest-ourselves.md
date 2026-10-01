# ADR 1: decode Android's binary XML directly

## Status
Accepted

## Context
The `AndroidManifest.xml` in a built APK isn't text. It's Android's compiled
binary XML (AXML): little-endian chunks holding a string pool, a table of
attribute resource IDs, and a stream of element events. Reading it normally
means apktool (Java) or `aapt2 dump` (the Android build tools), so a scanner
built on either needs a JVM or an SDK on every machine and CI runner that
uses it. That's a heavy requirement for something meant to be a CI gate on
a mobile build.

The format is small and documented in AOSP's `ResourceTypes.h`. The part a
manifest needs is a few hundred lines.

## Decision
`internal/axml` decodes it directly, with no dependency beyond the standard
library: both string-pool encodings (UTF-8 and UTF-16, each with its
one-or-two-unit length prefix), the resource-ID table, namespaces,
elements and typed attribute values. The result is one static binary.

Because the input is an APK from anywhere, the decoder is written to
distrust it. Every read is bounds-checked, string, attribute and element
counts and nesting depth are capped, and an invalid file returns an error with
a byte offset and never panics. It's held to that by a fuzz test over the
decoder and a second over the whole path (zip, decoder, manifest model, all
rules).

A decoder written by one person from a spec could still be wrong, so it's
checked against things it didn't produce:
- the package name, min and target SDK, and the complete permission list of
  three real apps match what F-Droid's own indexer published for those exact
  files (SHA-256 pinned);
- every framework attribute ID in its table matches Android's
  `public-final.xml` and the IDs inside those real manifests;
- a separate test encoder builds files the decoder must round-trip,
  including malformed ones, and every truncation of a valid file must be
  refused.

## Consequences
- No JVM, no SDK, no `aapt2`. `go install` and a path to an APK.
- Only the manifest is read. `resources.arsc`, which holds the values behind
  `@bool/...` references and the network security config, is a larger format
  and isn't decoded. That's the biggest gap, and ADR 2 is how it's handled
  without guessing.
- A format change in a future Android release could break it. Unknown chunk
  types are skipped as the platform does, and a manifest the decoder can't
  read is an exit code 2 with the offset, not a clean report.
- It was verified against three real apps from one source. Other build
  tools' quirks are untested, and the README says so.

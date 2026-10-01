# ADR 2: a value the manifest doesn't contain is "indeterminate"

## Status
Accepted

## Context
Most manifest attributes are literals: `android:debuggable="true"`. But any
of them can be written as a reference to a resource, such as
`android:debuggable="@bool/is_debug"`, whose value sits in `resources.arsc`
and differs by build type or configuration. apkwarden doesn't read that
file (ADR 1). A boolean attribute therefore has four possible states, not
two: absent, true, false, and "present but its value isn't here."

The shortcuts both go wrong in a way that matters for a CI gate. Treating a
reference as false makes a debuggable release build pass. Treating it as true
fails a build over something that may be fine, and trains the team to
ignore the tool.

A related case: `android:usesCleartextTraffic="true"` is ignored on Android 7+
when the app has a network security config, which takes precedence. The
config's contents are in another resource file, so with one present the
attribute proves nothing either way. AntennaPod has exactly this: the
attribute is `true` and a config is present.

## Decision
Booleans are a three-way type, `unset | true | false | unknown`, and every
rule has two non-pass outcomes, `fail` and `indeterminate`. An
indeterminate finding is printed, kept in the JSON, and emitted as a SARIF
`note`, so it's visible. It never fails a build on its own, because nobody
can fix what the manifest doesn't say. The message says what is unknown and
how to find out (`aapt2 dump xmltree`, or opening the config).

A rule stays silent when the manifest gives it nothing to say: no
`usesCleartextTraffic` on an app with a network security config produces no
finding, since reporting every such app (most apps) would be noise. That's
listed under what the tool doesn't do.

## Consequences
- A clean report means the manifest declares nothing wrong, not that the
  app is secure.
- Teams that want unknowns to block can read the JSON (`outcome:
  "indeterminate"`), and the exit code stays simple.
- tfwarden makes the same call for Terraform values that aren't known until
  apply. The reason carries over: a scanner that reports pass or fail on
  data it doesn't have is worse than none.

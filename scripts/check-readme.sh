#!/usr/bin/env bash
# Re-runs the commands behind the README's example blocks against the real
# APKs and diffs the output, byte for byte. Needs `apkwarden` on PATH and
# APKWARDEN_APKS pointing at the directory testdata/fetch-apks.sh filled.
#
#   ./scripts/check-readme.sh            fail if a block is out of date
#   ./scripts/check-readme.sh --update   rewrite the blocks from real output
set -euo pipefail
cd "$(dirname "$0")/.."
: "${APKWARDEN_APKS:?set APKWARDEN_APKS to the directory fetch-apks.sh filled}"
apks="$APKWARDEN_APKS"
today=2026-10-01

# name | command. Exit codes are ignored: the examples fail on purpose.
blocks=(
  "antennapod|apkwarden scan --today $today $apks/de.danoeh.antennapod_3120095.apk"
  "waived|apkwarden scan --waivers examples/antennapod-waivers.yaml --today $today $apks/de.danoeh.antennapod_3120095.apk | grep -E '^(FAIL|waived|EXPIRED|[?]) |findings:'"
  "rules|apkwarden rules"
)

output_of() { bash -c "${1#*|}" 2>&1 | tr -d '\r' || true; }

block_in_readme() {  # the fenced block between <!-- name:start --> and <!-- name:end -->
  awk -v s="<!-- $1:start -->" -v e="<!-- $1:end -->" '$0==s{f=1;next} $0==e{f=0} f' README.md | sed '1d;$d'
}

status=0
for entry in "${blocks[@]}"; do
  name=${entry%%|*}
  actual=$(output_of "$entry")
  if [ "${1:-}" = "--update" ]; then
    body=$(mktemp); out=$(mktemp)
    printf '%s
' "$actual" > "$body"
    awk -v s="<!-- $name:start -->" -v e="<!-- $name:end -->" -v bodyfile="$body" '
      $0 == s { print; print "```"; while ((getline line < bodyfile) > 0) print line; print "```"; skip = 1; next }
      $0 == e { skip = 0 }
      !skip   { print }' README.md > "$out"
    mv "$out" README.md; rm -f "$body"
    echo "$name: updated"
  elif diff <(block_in_readme "$name") <(printf '%s\n' "$actual") >/dev/null; then
    echo "$name: matches"
  else
    echo "README block '$name' is out of date:" >&2
    diff <(block_in_readme "$name") <(printf '%s\n' "$actual") >&2 || true
    status=1
  fi
done
exit $status

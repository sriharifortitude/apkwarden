#!/usr/bin/env bash
# Downloads the real APKs the integration tests run against, from F-Droid,
# and refuses any whose SHA-256 differs from apks.sha256 (those hashes are
# the ones F-Droid's own index publishes for each file).
#
#   ./testdata/fetch-apks.sh [dir]     default dir: $APKWARDEN_APKS or ./.apks
#   export APKWARDEN_APKS=<dir>        then: go test ./...
#
# Without the directory, the tests that need real APKs skip themselves.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
dir="${1:-${APKWARDEN_APKS:-$here/../.apks}}"
mkdir -p "$dir"
while read -r sha file; do
  [ -z "$file" ] && continue
  if [ -f "$dir/$file" ] && [ "$(sha256sum "$dir/$file" | cut -d' ' -f1)" = "$sha" ]; then
    echo "have $file"; continue
  fi
  # A fresh file every time: resuming a partial download once produced a
  # corrupt file here, when two processes appended to it.
  rm -f "$dir/$file"
  for attempt in 1 2 3; do
    curl -sfL --retry 2 -o "$dir/$file" "https://f-droid.org/repo/$file" && break
    echo "attempt $attempt failed for $file" >&2; sleep 5
  done
  got="$(sha256sum "$dir/$file" | cut -d' ' -f1)"
  [ "$got" = "$sha" ] || { echo "$file: sha256 $got, expected $sha" >&2; rm -f "$dir/$file"; exit 1; }
  echo "ok   $file"
done < "$here/apks.sha256"
echo "$dir"

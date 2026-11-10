#!/usr/bin/env bash
# Print the body of the dated CHANGELOG.md section for a version.
# Usage: changelog-section.sh <version> [changelog]
# Exits non-zero when the section is missing, undated or empty.
set -euo pipefail

version="${1:?usage: changelog-section.sh <version> [changelog]}"
changelog="${2:-CHANGELOG.md}"

heading="$(grep -E -m1 -- "^## \[${version//./\\.}\]" "$changelog" || true)"
if [[ -z "$heading" ]]; then
  echo "error: $changelog has no section for $version" >&2
  exit 1
fi
if ! [[ "$heading" =~ ^##\ \[.+\]\ -\ [0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
  echo "error: section for $version is not dated: '$heading'" >&2
  exit 1
fi

body="$(awk -v h="$heading" '
  $0 == h { found = 1; next }
  found && /^## / { exit }
  found { print }
' "$changelog")"
if [[ -z "${body//[[:space:]]/}" ]]; then
  echo "error: section for $version is empty" >&2
  exit 1
fi
printf '%s\n' "$body"

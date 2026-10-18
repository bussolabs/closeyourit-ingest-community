#!/usr/bin/env bash
# Refuse gateway deployment until the reviewed Rails prerequisite is running.
set -euo pipefail
expected="${1:-}"
if [[ ! "$expected" =~ ^[0-9a-f]{40}$ ]]; then
  echo "A full lowercase Rails commit SHA is required" >&2
  exit 1
fi
jq -e -s --arg sha "$expected" '
  length == 1 and (.[0] | type == "object" and
    .app == "closeyourit-rails" and .environment == "production" and .sha == $sha)
' >/dev/null
echo "Reviewed Rails release verified"

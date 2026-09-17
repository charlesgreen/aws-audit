#!/usr/bin/env bash
# Thin wrapper around the Go collector (cmd/aws-audit).
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
if [[ -x "${DIR}/bin/aws-audit" ]]; then
  exec "${DIR}/bin/aws-audit" "$@"
fi
exec go run "${DIR}/cmd/aws-audit" "$@"

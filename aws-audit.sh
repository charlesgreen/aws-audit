#!/usr/bin/env bash
# Optional local helper: exec ./bin/aws-audit or go run ./cmd/aws-audit.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
if [[ -x "${DIR}/bin/aws-audit" ]]; then
  exec "${DIR}/bin/aws-audit" "$@"
fi
exec go run "${DIR}/cmd/aws-audit" "$@"

#!/usr/bin/env bash
# Thin wrapper around the Go summarizer (cmd/aws-audit-summarize).
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
if [[ -x "${DIR}/bin/aws-audit-summarize" ]]; then
  exec "${DIR}/bin/aws-audit-summarize" "$@"
fi
exec go run "${DIR}/cmd/aws-audit-summarize" "$@"

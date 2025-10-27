#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 <profile> <output.svg> [binary]" >&2
  exit 1
}

if [[ $# -lt 2 || $# -gt 3 ]]; then
  usage
fi

PROFILE=$1
OUTPUT=$2
BINARY=${3:-}

if [[ ! -f "$PROFILE" ]]; then
  echo "Profile file not found: $PROFILE" >&2
  exit 2
fi

FLAMEGRAPH_TOOL=${FLAMEGRAPH_PL:-flamegraph.pl}
if [[ "$FLAMEGRAPH_TOOL" == */* ]]; then
  if [[ ! -x "$FLAMEGRAPH_TOOL" ]]; then
    echo "FlameGraph script not executable: $FLAMEGRAPH_TOOL" >&2
    exit 3
  fi
elif ! command -v "$FLAMEGRAPH_TOOL" >/dev/null 2>&1; then
  echo "flamegraph.pl not found in PATH (set FLAMEGRAPH_PL to override)" >&2
  exit 3
fi

if ! command -v go >/dev/null 2>&1; then
  echo "Go toolchain is required but 'go' was not found in PATH" >&2
  exit 4
fi

PPROF_ARGS=(-raw)
if [[ -n "$BINARY" ]]; then
  if [[ ! -f "$BINARY" ]]; then
    echo "Binary not found: $BINARY" >&2
    exit 5
  fi
  PPROF_ARGS+=("$BINARY" "$PROFILE")
else
  PPROF_ARGS+=("$PROFILE")
fi

TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

go tool pprof "${PPROF_ARGS[@]}" >"$TMP"
"$FLAMEGRAPH_TOOL" --title "$(basename "$PROFILE")" <"$TMP" >"$OUTPUT"

echo "Flame graph written to $OUTPUT"

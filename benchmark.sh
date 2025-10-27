#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$SCRIPT_DIR"
BIN_DIR="$ROOT_DIR/bin"
BINARY="${1:-}"

if [[ -x "$BINARY" ]]; then
  shift || true
else
  BINARY="$BIN_DIR/nitro"
fi

if [[ ! -x "$BINARY" ]]; then
  mkdir -p "$BIN_DIR"
  echo "[benchmark] Building nitr0g3n binary at $BINARY"
  go build -o "$BINARY" ./cmd/nitro
fi

PYTHON_BIN=${PYTHON_BIN:-python3}

ARGS=()
ARGS+=("--binary" "$BINARY")
ARGS+=("--generate-graphs")
ARGS+=("$@")

"$PYTHON_BIN" "$ROOT_DIR/benchmark/run_benchmarks.py" "${ARGS[@]}"

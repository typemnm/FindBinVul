#!/usr/bin/env bash
set -euo pipefail

# Always run from the repository root (directory containing this script)
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

# Use venv python if available, otherwise fallback to system python3
PY_BIN="python3"
if [[ -x "$ROOT_DIR/venv/bin/python" ]]; then
  PY_BIN="$ROOT_DIR/venv/bin/python"
elif [[ -x "$ROOT_DIR/.venv/bin/python" ]]; then
  PY_BIN="$ROOT_DIR/.venv/bin/python"
fi

# Basic sanity checks
if [[ ! -f "$ROOT_DIR/runner/run.py" ]]; then
  echo "ERROR: runner/run.py not found (cwd=$PWD)"
  exit 1
fi
if [[ ! -f "$ROOT_DIR/runner/__init__.py" ]]; then
  echo "ERROR: runner/__init__.py not found. Create it (can be empty)."
  exit 1
fi
if [[ ! -f "$ROOT_DIR/triage/__init__.py" ]]; then
  echo "ERROR: triage/__init__.py not found. Create it (can be empty)."
  exit 1
fi

TARGET="${TARGET:-$ROOT_DIR/target/build/tlv_target}"
CORPUS="${CORPUS:-$ROOT_DIR/corpus}"
RUNS_DIR="${RUNS_DIR:-$ROOT_DIR/storage/runs}"
GLOBAL_DEDUP="${GLOBAL_DEDUP:-$ROOT_DIR/storage/dedup/index.json}"

ITERATIONS="${ITERATIONS:-20000}"
TIMEOUT_MS="${TIMEOUT_MS:-200}"
MUTATIONS="${MUTATIONS:-20}"
MAX_INPUT_SIZE="${MAX_INPUT_SIZE:-4096}"

KEEP_DUPLICATES="${KEEP_DUPLICATES:-1}"  # 1=true, 0=false
RNG_SEED="${RNG_SEED:-}"                 # optional

if [[ ! -x "$TARGET" ]]; then
  echo "ERROR: target binary not found or not executable: $TARGET"
  echo "Hint: build it first, or set TARGET=/path/to/binary"
  exit 1
fi
if [[ ! -d "$CORPUS" ]]; then
  echo "ERROR: corpus directory not found: $CORPUS"
  exit 1
fi

CMD=(
  "$PY_BIN" -m runner.run
  --target "$TARGET"
  --corpus "$CORPUS"
  --runs-dir "$RUNS_DIR"
  --global-dedup "$GLOBAL_DEDUP"
  --iterations "$ITERATIONS"
  --timeout-ms "$TIMEOUT_MS"
  --mutations "$MUTATIONS"
  --max-input-size "$MAX_INPUT_SIZE"
)

if [[ -n "$RNG_SEED" ]]; then
  CMD+=(--seed "$RNG_SEED")
fi
if [[ "$KEEP_DUPLICATES" == "1" ]]; then
  CMD+=(--keep-duplicates)
fi

echo "[run.sh] cwd=$PWD"
echo "[run.sh] python=$PY_BIN"
echo "[run.sh] target=$TARGET"
echo "[run.sh] corpus=$CORPUS"
echo "[run.sh] runs_dir=$RUNS_DIR"
echo "[run.sh] global_dedup=$GLOBAL_DEDUP"
echo "[run.sh] iterations=$ITERATIONS timeout_ms=$TIMEOUT_MS mutations=$MUTATIONS max_input_size=$MAX_INPUT_SIZE keep_duplicates=$KEEP_DUPLICATES seed=${RNG_SEED:-<none>}"
echo "[run.sh] cmd: ${CMD[*]}"
exec "${CMD[@]}"
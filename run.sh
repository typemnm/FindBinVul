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

ITERATIONS="${ITERATIONS:-3000}"
TIMEOUT_MS="${TIMEOUT_MS:-500}"
MUTATIONS="${MUTATIONS:-20}"
MAX_INPUT_SIZE="${MAX_INPUT_SIZE:-4096}"
MUTATOR="${MUTATOR:-adaptive}"

PROFILE="${PROFILE:-conservative}"
EXTRA_ARGS=()

usage() {
  cat <<'EOF'
Usage:
  ./run.sh [--profile conservative|aggressive] [extra runner args]
  ./run.sh [conservative|aggressive] [extra runner args]

Examples:
  ./run.sh
  ./run.sh aggressive
  ./run.sh --profile conservative --seed 3001
  ./run.sh --profile aggressive --iterations 5000 --timeout-ms 600

Notes:
  - Default profile is conservative.
  - Extra runner args are appended last, so they override preset values.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --profile)
      if [[ $# -lt 2 ]]; then
        echo "ERROR: --profile requires a value"
        exit 1
      fi
      PROFILE="$2"
      shift 2
      ;;
    conservative|aggressive)
      PROFILE="$1"
      shift
      ;;
    --)
      shift
      EXTRA_ARGS+=("$@")
      break
      ;;
    *)
      EXTRA_ARGS+=("$1")
      shift
      ;;
  esac
done

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
  --mutator "$MUTATOR"
  --max-input-size "$MAX_INPUT_SIZE"
)

PRESET_ARGS=()
case "$PROFILE" in
  conservative)
    PRESET_ARGS=(
      --boost-seeds "seed_11.bin:4.0,seed_12.bin:4.0,seed_13.bin:4.0,seed_14.bin:2.0"
      --seed-tiers "seed_11.bin:attack,seed_12.bin:attack,seed_13.bin:attack,seed_14.bin:bridge"
      --tier-budget "attack:0.5,bridge:0.3,background:0.2"
      --tier-window 100
      --timeout-tier-max-ratio 0.15
      --structured-seeds "seed_14.bin"
      --structured-mutations 10
      --structured-min-mutations 8
      --structured-max-mutations 16
      --structured-step 2
      --structured-window 80
      --prune-short-window 500
      --prune-long-window 1500
      --deprioritize-penalty 0.5
      --timeout-cov-threshold 15
    )
    ;;
  aggressive)
    PRESET_ARGS=(
      --boost-seeds "seed_11.bin:4.0,seed_12.bin:4.0,seed_13.bin:4.0,seed_14.bin:2.5"
      --seed-tiers "seed_11.bin:attack,seed_12.bin:attack,seed_13.bin:attack,seed_14.bin:bridge"
      --tier-budget "attack:0.45,bridge:0.35,background:0.20"
      --tier-window 80
      --timeout-tier-max-ratio 0.20
      --structured-seeds "seed_14.bin"
      --structured-mutations 10
      --structured-min-mutations 8
      --structured-max-mutations 18
      --structured-step 2
      --structured-window 60
      --prune-short-window 400
      --prune-long-window 1200
      --deprioritize-penalty 0.4
      --timeout-cov-threshold 12
    )
    ;;
  *)
    echo "ERROR: unknown profile '$PROFILE' (expected: conservative or aggressive)"
    exit 1
    ;;
esac

CMD+=("${PRESET_ARGS[@]}")

if [[ -n "$RNG_SEED" ]]; then
  CMD+=(--seed "$RNG_SEED")
fi
if [[ "$KEEP_DUPLICATES" == "1" ]]; then
  CMD+=(--keep-duplicates)
fi
if [[ ${#EXTRA_ARGS[@]} -gt 0 ]]; then
  CMD+=("${EXTRA_ARGS[@]}")
fi

echo "[run.sh] cwd=$PWD"
echo "[run.sh] python=$PY_BIN"
echo "[run.sh] profile=$PROFILE"
echo "[run.sh] target=$TARGET"
echo "[run.sh] corpus=$CORPUS"
echo "[run.sh] runs_dir=$RUNS_DIR"
echo "[run.sh] global_dedup=$GLOBAL_DEDUP"
echo "[run.sh] base iterations=$ITERATIONS timeout_ms=$TIMEOUT_MS mutations=$MUTATIONS mutator=$MUTATOR max_input_size=$MAX_INPUT_SIZE keep_duplicates=$KEEP_DUPLICATES seed=${RNG_SEED:-<none>}"
if [[ ${#EXTRA_ARGS[@]} -gt 0 ]]; then
  echo "[run.sh] override args: ${EXTRA_ARGS[*]}"
fi
echo "[run.sh] cmd: ${CMD[*]}"
exec "${CMD[@]}"
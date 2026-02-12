from __future__ import annotations

import argparse
import json
import os
import random
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from runner.mutate import mutate
from triage.crash_tag import extract_crash_tag
from triage.dedup import GlobalDedupIndex, dedup_key_for, sha256_bytes

MAX_INPUT_SIZE_DEFAULT = 4096

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def make_run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

def pick_seed(paths: list[Path], rnd: random.Random) -> Path:
    return rnd.choice(paths)

def is_crash(returncode: int, timeout: bool) -> bool:
    if timeout:
        return True
    if returncode < 0:  # signal
        return True
    return returncode != 0

def write_json_atomic(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(path)

def load_index(path: Path, run_id: str, created_at: str, target_path: str) -> dict:
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return {"run_id": run_id, "created_at": created_at, "target_path": target_path, "crashes": []}

def main() -> None:
    ap = argparse.ArgumentParser(description="File-based fuzz runner with global dedup.")
    ap.add_argument("--target", required=True, help="Target binary path")
    ap.add_argument("--corpus", default="corpus", help="Corpus directory (default: corpus)")
    ap.add_argument("--runs-dir", default="storage/runs", help="Runs directory (default: storage/runs)")
    ap.add_argument("--global-dedup", default="storage/dedup/index.json", help="Global dedup index path")
    ap.add_argument("--iterations", type=int, default=10000)
    ap.add_argument("--timeout-ms", type=int, default=200)
    ap.add_argument("--mutations", type=int, default=20, help="Mutation rounds per input (default: 20)")
    ap.add_argument("--seed", type=int, default=None, help="RNG seed for reproducibility")
    ap.add_argument("--max-input-size", type=int, default=MAX_INPUT_SIZE_DEFAULT)
    ap.add_argument("--keep-duplicates", action="store_true", help="Store duplicate crashes as well")
    args = ap.parse_args()

    target_path = str(Path(args.target))
    corpus_dir = Path(args.corpus)
    runs_dir = Path(args.runs_dir)

    seed_paths = sorted([p for p in corpus_dir.glob("*.bin") if p.is_file()])
    if not seed_paths:
        raise SystemExit(f"No seed .bin files found in {corpus_dir}")

    rnd = random.Random(args.seed)

    run_id = make_run_id()
    created_at = utc_now_iso()
    run_root = runs_dir / run_id
    crashes_root = run_root / "crashes"
    queue_root = run_root / "queue"
    run_root.mkdir(parents=True, exist_ok=True)
    crashes_root.mkdir(parents=True, exist_ok=True)
    queue_root.mkdir(parents=True, exist_ok=True)

    run_json = {
        "run_id": run_id,
        "created_at": created_at,
        "target_path": target_path,
        "corpus": str(corpus_dir),
        "iterations": args.iterations,
        "timeout_ms": args.timeout_ms,
        "mutations": args.mutations,
        "rng_seed": args.seed,
        "max_input_size": args.max_input_size,
    }
    write_json_atomic(run_root / "run.json", run_json)

    dedup = GlobalDedupIndex(Path(args.global_dedup))
    dedup.load()

    index_path = run_root / "index.json"
    index = load_index(index_path, run_id, created_at, target_path)

    crash_seq = 0
    for i in range(args.iterations):
        seed_path = pick_seed(seed_paths, rnd)
        seed_data = seed_path.read_bytes()

        mutated = mutate(seed_data, rnd, rounds=args.mutations, max_size=args.max_input_size)

        # Optionally keep a sample of queue inputs for debugging
        if i % 200 == 0:
            (queue_root / f"q_{i:06d}.bin").write_bytes(mutated)

        # Write input to a stable temp path under run dir
        inp_path = run_root / "current_input.bin"
        inp_path.write_bytes(mutated)

        cmd = [target_path, str(inp_path)]
        start = time.time()
        timeout = False
        try:
            proc = subprocess.run(
                cmd,
                cwd=".",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=args.timeout_ms / 1000.0,
            )
            rc = proc.returncode
            out_b = proc.stdout
            err_b = proc.stderr
        except subprocess.TimeoutExpired as e:
            timeout = True
            rc = -9  # synthetic; treat as killed
            out_b = e.stdout or b""
            err_b = e.stderr or b""

        elapsed_ms = int((time.time() - start) * 1000)

        out_t = out_b.decode("utf-8", errors="replace")
        err_t = err_b.decode("utf-8", errors="replace")

        crash_tag = extract_crash_tag(err_t)
        if not is_crash(rc, timeout) and not crash_tag:
            continue

        crash_seq += 1
        crash_id = f"{crash_seq:08d}"
        crash_dir = crashes_root / crash_id
        crash_dir.mkdir(parents=True, exist_ok=True)

        # Persist artifacts
        (crash_dir / "input.bin").write_bytes(mutated)
        (crash_dir / "stdout.txt").write_text(out_t, encoding="utf-8")
        (crash_dir / "stderr.txt").write_text(err_t, encoding="utf-8")

        dkey = dedup_key_for(crash_tag, err_t)

        # global index uses path relative to repo root for portability
        crash_rel = str(crash_dir).replace("\\", "/")

        hit = dedup.register(dkey, crash_rel)
        dedup.save()

        status = "new" if hit.is_new else "duplicate"
        if (not hit.is_new) and (not args.keep_duplicates):
            # If not keeping duplicates, remove the crash directory we just created,
            # but still increment dedup counts.
            shutil.rmtree(crash_dir, ignore_errors=True)
        else:
            meta = {
                "run_id": run_id,
                "crash_id": crash_id,
                "created_at": utc_now_iso(),
                "input": {
                    "path": "input.bin",
                    "sha256": sha256_bytes(mutated),
                    "size": len(mutated),
                    "seed_source": str(seed_path),
                },
                "exec": {
                    "target_path": target_path,
                    "args": cmd,
                    "cwd": ".",
                    "time_ms": elapsed_ms,
                    "timeout": timeout,
                    "returncode": rc,
                    "exit_code": (rc if rc >= 0 else None),
                    "signal": (-rc if rc < 0 else None),
                },
                "triage": {
                    "crash_tag": crash_tag,
                    "dedup_key": dkey,
                    "status": status,
                    "representative": hit.representative,
                },
            }
            write_json_atomic(crash_dir / "meta.json", meta)

            index["crashes"].append(
                {
                    "crash_id": crash_id,
                    "created_at": meta["created_at"],
                    "crash_tag": crash_tag,
                    "dedup_key": dkey,
                    "input_sha256": meta["input"]["sha256"],
                    "status": status,
                    "representative": hit.representative,
                }
            )
            write_json_atomic(index_path, index)

    # cleanup
    try:
        inp_path.unlink(missing_ok=True)  # py3.8+: missing_ok, but you target 3.10+ anyway
    except Exception:
        pass

    print(f"Run complete: {run_id}. Crashes recorded: {len(index.get('crashes', []))}")

if __name__ == "__main__":
    main()
#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

RUN_ID_RE = re.compile(r"Run complete:\s+([0-9_]+)\.")


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def run_one_arm(
    root: Path,
    *,
    arm: str,
    trial: int,
    seed: int,
    target: Path,
    corpus: Path,
    iterations: int,
    timeout_ms: int,
    mutations: int,
    max_input_size: int,
    keep_duplicates: bool,
    output_root: Path,
) -> dict:
    runs_dir = output_root / "runs" / arm
    dedup_path = output_root / "dedup" / f"{arm}_trial{trial:03d}.json"
    runs_dir.mkdir(parents=True, exist_ok=True)
    dedup_path.parent.mkdir(parents=True, exist_ok=True)
    if dedup_path.exists():
        dedup_path.unlink()

    cmd = [
        sys.executable,
        "-m",
        "runner.run",
        "--target",
        str(target),
        "--corpus",
        str(corpus),
        "--runs-dir",
        str(runs_dir),
        "--global-dedup",
        str(dedup_path),
        "--iterations",
        str(iterations),
        "--timeout-ms",
        str(timeout_ms),
        "--mutations",
        str(mutations),
        "--mutator",
        arm,
        "--max-input-size",
        str(max_input_size),
        "--seed",
        str(seed),
    ]
    if keep_duplicates:
        cmd.append("--keep-duplicates")

    t0 = time.time()
    proc = subprocess.run(cmd, cwd=str(root), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    elapsed_s = round(time.time() - t0, 3)

    if proc.returncode != 0:
        raise RuntimeError(
            f"arm={arm} trial={trial} failed rc={proc.returncode}\n"
            f"stdout:\n{proc.stdout}\n\n"
            f"stderr:\n{proc.stderr}"
        )

    m = RUN_ID_RE.search(proc.stdout)
    if not m:
        raise RuntimeError(
            f"arm={arm} trial={trial}: could not parse run_id from output\n{proc.stdout}"
        )
    run_id = m.group(1)

    index_path = runs_dir / run_id / "index.json"
    run_json_path = runs_dir / run_id / "run.json"
    crashes: list[dict] = []
    run_meta: dict = {}
    if index_path.exists():
        idx = json.loads(index_path.read_text(encoding="utf-8"))
        crashes = idx.get("crashes", [])
    if run_json_path.exists():
        run_meta = json.loads(run_json_path.read_text(encoding="utf-8"))

    total = len(crashes)
    new_count = sum(1 for c in crashes if c.get("status") == "new")
    dup_count = sum(1 for c in crashes if c.get("status") == "duplicate")
    unique_keys = len({c.get("dedup_key") for c in crashes if c.get("dedup_key")})

    tag_counts: dict[str, int] = {}
    for c in crashes:
        tag = c.get("crash_tag") or "<none>"
        tag_counts[tag] = tag_counts.get(tag, 0) + 1

    return {
        "arm": arm,
        "trial": trial,
        "seed": seed,
        "run_id": run_id,
        "elapsed_s": elapsed_s,
        "total_crashes": total,
        "new_crashes": new_count,
        "duplicate_crashes": dup_count,
        "unique_dedup_keys": unique_keys,
        "t03_hits": int(run_meta.get("t03_hit_count", 0)),
        "first_new_key_iter": run_meta.get("first_new_key_iter"),
        "first_new_cov_iter": run_meta.get("first_new_cov_iter"),
        "first_t03_iter": run_meta.get("first_t03_iter"),
        "timeout_pick_ratio": float(run_meta.get("timeout_pick_ratio", 0.0)),
        "timeout_bucket_size": int(run_meta.get("timeout_bucket_size", 0)),
        "timeout_saved_count": int(run_meta.get("timeout_saved_count", 0)),
        "signal_counts": run_meta.get("signal_counts", {}),
        "tag_counts": dict(sorted(tag_counts.items(), key=lambda kv: (-kv[1], kv[0]))),
        "runs_dir": str(runs_dir),
        "index_path": str(index_path),
        "run_json_path": str(run_json_path),
    }


def aggregate(arm_results: list[dict]) -> dict:
    n = len(arm_results)
    if n == 0:
        return {
            "trials": 0,
            "avg_elapsed_s": 0.0,
            "avg_total_crashes": 0.0,
            "avg_new_crashes": 0.0,
            "avg_unique_dedup_keys": 0.0,
            "avg_t03_hits": 0.0,
            "avg_first_new_key_iter": None,
            "avg_timeout_pick_ratio": 0.0,
            "avg_timeout_bucket_size": 0.0,
            "sum_timeout_saved_count": 0,
            "sum_total_crashes": 0,
            "sum_new_crashes": 0,
            "sum_unique_dedup_keys": 0,
            "sum_t03_hits": 0,
        }

    sum_elapsed = sum(r["elapsed_s"] for r in arm_results)
    sum_total = sum(r["total_crashes"] for r in arm_results)
    sum_new = sum(r["new_crashes"] for r in arm_results)
    sum_unique = sum(r["unique_dedup_keys"] for r in arm_results)
    sum_t03 = sum(int(r.get("t03_hits", 0)) for r in arm_results)
    sum_timeout_pick_ratio = sum(float(r.get("timeout_pick_ratio", 0.0)) for r in arm_results)
    sum_timeout_bucket_size = sum(int(r.get("timeout_bucket_size", 0)) for r in arm_results)
    sum_timeout_saved_count = sum(int(r.get("timeout_saved_count", 0)) for r in arm_results)
    first_new_key_iters = [r["first_new_key_iter"] for r in arm_results if r.get("first_new_key_iter") is not None]

    return {
        "trials": n,
        "avg_elapsed_s": round(sum_elapsed / n, 3),
        "avg_total_crashes": round(sum_total / n, 3),
        "avg_new_crashes": round(sum_new / n, 3),
        "avg_unique_dedup_keys": round(sum_unique / n, 3),
        "avg_t03_hits": round(sum_t03 / n, 3),
        "avg_first_new_key_iter": (
            round(sum(first_new_key_iters) / len(first_new_key_iters), 3) if first_new_key_iters else None
        ),
        "avg_timeout_pick_ratio": round(sum_timeout_pick_ratio / n, 4),
        "avg_timeout_bucket_size": round(sum_timeout_bucket_size / n, 3),
        "sum_timeout_saved_count": sum_timeout_saved_count,
        "sum_total_crashes": sum_total,
        "sum_new_crashes": sum_new,
        "sum_unique_dedup_keys": sum_unique,
        "sum_t03_hits": sum_t03,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Run A/B mutator experiments (uniform vs adaptive).")
    ap.add_argument("--target", default="target/build/tlv_target", help="Target binary path")
    ap.add_argument("--corpus", default="corpus", help="Corpus directory")
    ap.add_argument("--iterations", type=int, default=5000)
    ap.add_argument("--timeout-ms", type=int, default=200)
    ap.add_argument("--mutations", type=int, default=20)
    ap.add_argument("--max-input-size", type=int, default=4096)
    ap.add_argument("--trials", type=int, default=3, help="Number of paired trials")
    ap.add_argument("--seed-start", type=int, default=1000)
    ap.add_argument("--output-root", default=None, help="Output root (default: storage/ab/<timestamp>)")
    ap.add_argument(
        "--no-keep-duplicates",
        action="store_true",
        help="Disable --keep-duplicates for each run",
    )
    args = ap.parse_args()

    root = Path(__file__).resolve().parent.parent
    target = (root / args.target).resolve() if not Path(args.target).is_absolute() else Path(args.target)
    corpus = (root / args.corpus).resolve() if not Path(args.corpus).is_absolute() else Path(args.corpus)

    if not target.exists():
        raise SystemExit(f"Target not found: {target}")
    if not corpus.exists():
        raise SystemExit(f"Corpus not found: {corpus}")
    if args.trials < 1:
        raise SystemExit("--trials must be >= 1")

    if args.output_root:
        output_root = Path(args.output_root)
        if not output_root.is_absolute():
            output_root = root / output_root
    else:
        output_root = root / "storage" / "ab" / utc_stamp()

    keep_duplicates = not args.no_keep_duplicates

    print(f"[ab] root={root}")
    print(f"[ab] output={output_root}")
    print(
        f"[ab] trials={args.trials} iterations={args.iterations} mutations={args.mutations} "
        f"timeout_ms={args.timeout_ms} seed_start={args.seed_start} keep_duplicates={keep_duplicates}"
    )

    results: list[dict] = []
    for i in range(args.trials):
        trial = i + 1
        seed = args.seed_start + i

        for arm in ("uniform", "adaptive"):
            print(f"[ab] trial={trial}/{args.trials} arm={arm} seed={seed} ...")
            res = run_one_arm(
                root,
                arm=arm,
                trial=trial,
                seed=seed,
                target=target,
                corpus=corpus,
                iterations=args.iterations,
                timeout_ms=args.timeout_ms,
                mutations=args.mutations,
                max_input_size=args.max_input_size,
                keep_duplicates=keep_duplicates,
                output_root=output_root,
            )
            results.append(res)
            print(
                f"[ab] done arm={arm} trial={trial} run_id={res['run_id']} "
                f"new={res['new_crashes']} total={res['total_crashes']} unique={res['unique_dedup_keys']} "
                f"time={res['elapsed_s']}s"
            )

    by_arm: dict[str, list[dict]] = {"uniform": [], "adaptive": []}
    for r in results:
        by_arm[r["arm"]].append(r)

    summary = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "config": {
            "target": str(target),
            "corpus": str(corpus),
            "iterations": args.iterations,
            "timeout_ms": args.timeout_ms,
            "mutations": args.mutations,
            "max_input_size": args.max_input_size,
            "trials": args.trials,
            "seed_start": args.seed_start,
            "keep_duplicates": keep_duplicates,
            "python": sys.executable,
        },
        "arms": {
            "uniform": aggregate(by_arm["uniform"]),
            "adaptive": aggregate(by_arm["adaptive"]),
        },
        "results": results,
    }

    output_root.mkdir(parents=True, exist_ok=True)
    summary_path = output_root / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")

    print("\n[ab] Aggregate")
    for arm in ("uniform", "adaptive"):
        agg = summary["arms"][arm]
        print(
            f"  - {arm:8s} avg_new={agg['avg_new_crashes']:<6} "
            f"avg_total={agg['avg_total_crashes']:<6} "
            f"avg_unique={agg['avg_unique_dedup_keys']:<6} "
            f"avg_t03={agg['avg_t03_hits']:<6} "
            f"avg_timeout_ratio={agg['avg_timeout_pick_ratio']:<6} "
            f"avg_timeout_bucket={agg['avg_timeout_bucket_size']:<6} "
            f"timeout_saved_sum={agg['sum_timeout_saved_count']:<4} "
            f"avg_time={agg['avg_elapsed_s']}s"
        )

    un = summary["arms"]["uniform"]["avg_new_crashes"]
    ad = summary["arms"]["adaptive"]["avg_new_crashes"]
    if un > 0:
        gain = round(((ad - un) / un) * 100.0, 2)
        print(f"[ab] adaptive avg_new delta vs uniform: {gain:+.2f}%")
    else:
        print("[ab] adaptive avg_new delta vs uniform: baseline is zero (N/A)")

    print(f"[ab] summary: {summary_path}")


if __name__ == "__main__":
    main()

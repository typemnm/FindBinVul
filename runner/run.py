from __future__ import annotations

import argparse
import json
import random
import re
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, TypedDict

from runner.mutate import AdaptiveMutator, UniformMutator, tlv_shape_signature
from triage.asan import parse_asan_output
from triage.crash_tag import extract_crash_tag
from triage.dedup import GlobalDedupIndex, dedup_key_for, sha256_bytes, sha256_text

MAX_INPUT_SIZE_DEFAULT = 4096
_COV_SIG_RE = re.compile(r"^COV_SIG=([0-9a-fA-F]{8,16})\s*$", re.MULTILINE)
_COV_UNIQUE_RE = re.compile(r"^COV_UNIQUE=(\d+)\s*$", re.MULTILINE)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def make_run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


class SeedMeta(TypedDict):
    tier: str
    score: float
    protected: bool
    structured: bool
    structured_base: int
    structured_rounds: int
    recent_new_key: int
    recent_exec: int
    last_new_key_iter: Optional[int]
    status: str


def _clamp_float(v: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, v))


def parse_seed_tiers(spec: str) -> dict[str, str]:
    out: dict[str, str] = {}
    allowed = {"attack", "bridge", "background", "timeout"}
    for item in (s.strip() for s in spec.split(",") if s.strip()):
        parts = item.rsplit(":", 1)
        if len(parts) != 2:
            print(f"[warn] ignoring malformed --seed-tiers entry: {item}")
            continue
        seed_name = parts[0].strip()
        tier = parts[1].strip().lower()
        if tier not in allowed:
            print(f"[warn] ignoring unknown tier '{tier}' in --seed-tiers entry: {item}")
            continue
        out[seed_name] = tier
    return out


def parse_tier_budget(spec: str) -> dict[str, float]:
    defaults = {"attack": 0.5, "bridge": 0.3, "background": 0.2}
    if not spec.strip():
        return defaults

    raw = {"attack": 0.0, "bridge": 0.0, "background": 0.0}
    for item in (s.strip() for s in spec.split(",") if s.strip()):
        parts = item.rsplit(":", 1)
        if len(parts) != 2:
            print(f"[warn] ignoring malformed --tier-budget entry: {item}")
            continue
        tier = parts[0].strip().lower()
        if tier not in raw:
            print(f"[warn] ignoring unknown tier in --tier-budget entry: {item}")
            continue
        try:
            val = float(parts[1].strip())
        except ValueError:
            print(f"[warn] ignoring non-numeric budget value in entry: {item}")
            continue
        if val < 0:
            val = 0.0
        raw[tier] = val

    total = sum(raw.values())
    if total <= 0:
        print("[warn] invalid --tier-budget sum; falling back to defaults")
        return defaults
    return {k: v / total for k, v in raw.items()}


class SeedPool:
    def __init__(
        self,
        paths: list[Path],
        rnd: random.Random,
        *,
        mutation_overrides: Optional[dict[str, int]] = None,
        score_boosts: Optional[dict[str, float]] = None,
        seed_tiers: Optional[dict[str, str]] = None,
        tier_budget: Optional[dict[str, float]] = None,
        tier_window: int = 100,
        timeout_tier_max_ratio: float = 0.15,
        structured_min_mutations: int = 8,
        structured_max_mutations: int = 16,
        structured_step: int = 2,
        structured_window: int = 80,
        prune_short_window: int = 500,
        prune_long_window: int = 1500,
        deprioritize_penalty: float = 0.5,
        allow_prune_protected: bool = False,
        prune_min_score: float = 1.05,
        prune_signal: str = "new_key",
    ):
        self.paths = list(paths)
        self.rnd = rnd
        self._path_by_key: dict[str, Path] = {str(p): p for p in self.paths}
        self.meta: dict[str, SeedMeta] = {}
        self._seed_tier_override = seed_tiers or {}
        self._tier_budget = tier_budget or {"attack": 0.5, "bridge": 0.3, "background": 0.2}
        self._tier_window = max(10, tier_window)
        self._timeout_tier_max_ratio = _clamp_float(timeout_tier_max_ratio, 0.0, 0.5)

        self._structured_min = max(1, structured_min_mutations)
        self._structured_max = max(self._structured_min, structured_max_mutations)
        self._structured_step = max(1, structured_step)
        self._structured_window = max(10, structured_window)

        self._prune_short_window = max(100, prune_short_window)
        self._prune_long_window = max(self._prune_short_window, prune_long_window)
        self._deprioritize_penalty = _clamp_float(deprioritize_penalty, 0.1, 1.0)
        self._allow_prune_protected = allow_prune_protected
        self._prune_min_score = prune_min_score

        self._window_idx = -1
        self._window_quota: dict[str, int] = {"attack": 0, "bridge": 0, "background": 0, "timeout": 0}
        self._quota_remaining: dict[str, int] = {"attack": 0, "bridge": 0, "background": 0, "timeout": 0}
        self._tier_pick_counts: dict[str, int] = {"attack": 0, "bridge": 0, "background": 0, "timeout": 0}
        self._total_picks = 0
        self._timeout_picks = 0
        self._timeout_keys: set[str] = set()

        self._deprioritized_seeds: set[str] = set()
        self._pruned_seeds: list[str] = []

        # Per-seed signal contribution tracking (for pruning)
        self._contributed: set[str] = set()
        # Per-seed mutation round overrides (structured seed protection)
        self._mutation_overrides: dict[str, int] = {}
        self._struct_last_eval: dict[str, int] = {}
        # Signal level required to mark a seed as "contributing" (exempt from pruning)
        self._prune_signal = prune_signal

        if mutation_overrides:
            for name, rounds in mutation_overrides.items():
                # Accept both full paths and bare filenames
                for p in self.paths:
                    if p.name == name or str(p) == name:
                        self._mutation_overrides[str(p)] = rounds

        boosts_by_key: dict[str, float] = {}
        if score_boosts:
            for name, boost in score_boosts.items():
                for p in self.paths:
                    if p.name == name or str(p) == name:
                        boosts_by_key[str(p)] = boost

        for p in self.paths:
            key = str(p)
            tier = self._classify_tier(p)
            is_structured = key in self._mutation_overrides
            base_rounds = self._mutation_overrides.get(key, self._structured_min)
            base_rounds = max(self._structured_min, min(self._structured_max, base_rounds))
            score = boosts_by_key.get(key, 1.0)
            self.meta[key] = {
                "tier": tier,
                "score": score,
                "protected": (tier == "attack") or is_structured,
                "structured": is_structured,
                "structured_base": base_rounds,
                "structured_rounds": base_rounds,
                "recent_new_key": 0,
                "recent_exec": 0,
                "last_new_key_iter": None,
                "status": "active",
            }
            if tier == "timeout":
                self._timeout_keys.add(key)

    def _classify_tier(self, path: Path) -> str:
        for candidate in (path.name, str(path)):
            if candidate in self._seed_tier_override:
                return self._seed_tier_override[candidate]

        n = path.name
        if n.startswith("timeout_"):
            return "timeout"
        if n in {"seed_11.bin", "seed_12.bin", "seed_13.bin"}:
            return "attack"
        if n in {"seed_09.bin", "seed_10.bin", "seed_14.bin"}:
            return "bridge"
        return "background"

    def _keys_in_tier(self, tier: str) -> list[str]:
        if tier == "timeout":
            return [k for k in self._timeout_keys if k in self.meta and k in self._path_by_key]
        return [k for k, m in self.meta.items() if m["tier"] == tier and k in self._path_by_key and k not in self._timeout_keys]

    def _refresh_tier_quota(self, iteration: int) -> None:
        widx = iteration // self._tier_window
        if widx == self._window_idx:
            return
        self._window_idx = widx

        timeout_quota = int(round(self._tier_window * self._timeout_tier_max_ratio))
        timeout_quota = max(0, min(self._tier_window, timeout_quota))
        normal_slots = max(0, self._tier_window - timeout_quota)

        tiers = ("attack", "bridge", "background")
        raw = {t: normal_slots * self._tier_budget.get(t, 0.0) for t in tiers}
        quota = {t: int(raw[t]) for t in tiers}
        rem = normal_slots - sum(quota.values())
        order = sorted(tiers, key=lambda t: raw[t] - quota[t], reverse=True)
        for i in range(rem):
            quota[order[i % len(order)]] += 1

        quota["timeout"] = timeout_quota
        self._window_quota = quota
        self._quota_remaining = dict(quota)

    def _pick_tier(self, iteration: int) -> str:
        self._refresh_tier_quota(iteration)

        available = [t for t in ("attack", "bridge", "background", "timeout") if self._keys_in_tier(t)]
        if not available:
            return "background"

        timeout_ratio = (self._timeout_picks / self._total_picks) if self._total_picks > 0 else 0.0
        if "timeout" in available and timeout_ratio >= self._timeout_tier_max_ratio:
            non_timeout = [t for t in available if t != "timeout"]
            if non_timeout:
                available = non_timeout

        with_quota = [t for t in available if self._quota_remaining.get(t, 0) > 0]
        candidates = with_quota if with_quota else available
        weights = [max(1, self._quota_remaining.get(t, 0)) for t in candidates]
        return self.rnd.choices(candidates, weights=weights, k=1)[0]

    def _pick_key_within_tier(self, tier: str) -> str:
        keys = self._keys_in_tier(tier)
        if not keys:
            # Fallback: any live key
            keys = [k for k in self._path_by_key.keys() if k in self.meta]
        if len(keys) == 1:
            return keys[0]

        base_scores: list[float] = []
        for k in keys:
            m = self.meta[k]
            penalty = self._deprioritize_penalty if m["status"] == "deprioritized" else 1.0
            base_scores.append(max(0.05, m["score"] * penalty))
        max_score = max(base_scores)
        weights = [max(0.05, s / max_score) for s in base_scores]
        return self.rnd.choices(keys, weights=weights, k=1)[0]

    def get_mutation_rounds(self, path: Path, default: int) -> int:
        key = str(path)
        m = self.meta.get(key)
        if not m:
            return default
        if m["structured"]:
            rounds = m["structured_rounds"]
            return max(self._structured_min, min(min(default, self._structured_max), rounds))
        return default

    def pick(self, iteration: int) -> Path:
        tier = self._pick_tier(iteration)
        key = self._pick_key_within_tier(tier)

        if self._quota_remaining.get(tier, 0) > 0:
            self._quota_remaining[tier] -= 1
        self._tier_pick_counts[tier] += 1
        self._total_picks += 1
        if tier == "timeout":
            self._timeout_picks += 1
        return self._path_by_key[key]

    def update(self, path: Path, signal: str, iteration: int) -> None:
        key = str(path)
        if key not in self.meta:
            return

        m = self.meta[key]
        cur = m["score"]
        if signal == "new_key":
            nxt = cur * 1.30 + 0.20
            self._contributed.add(key)
            m["recent_new_key"] += 1
            m["last_new_key_iter"] = iteration
            m["status"] = "active"
            if m["structured"]:
                m["structured_rounds"] = m["structured_base"]
                self._struct_last_eval[key] = iteration
        elif signal == "new_cov":
            nxt = cur * 1.10 + 0.05
            if self._prune_signal == "new_cov":
                self._contributed.add(key)
        elif signal == "existing_key":
            nxt = cur * 1.02
        else:  # no_crash
            nxt = cur * 0.998

        m["recent_exec"] += 1
        m["score"] = min(100.0, max(0.05, nxt))

        # Structured rounds controller (Phase 2)
        if m["structured"] and signal != "new_key":
            last_eval = self._struct_last_eval.get(key)
            if last_eval is None or (iteration - last_eval) >= self._structured_window:
                last_new_key = m["last_new_key_iter"]
                no_new_key_long_enough = (
                    last_new_key is None or (iteration - last_new_key) >= self._structured_window
                )
                if no_new_key_long_enough:
                    m["structured_rounds"] = min(
                        self._structured_max,
                        m["structured_rounds"] + self._structured_step,
                    )
                self._struct_last_eval[key] = iteration

        # Deprioritize if no new_key within short window.
        last_new_key = m["last_new_key_iter"]
        if signal != "new_key" and m["recent_exec"] > 0:
            if last_new_key is None or (iteration - last_new_key) >= self._prune_short_window:
                m["status"] = "deprioritized"
                self._deprioritized_seeds.add(Path(key).name)

    def decay(self, factor: float = 0.5) -> None:
        """Halve non-structured seed scores to restore selection diversity.

        Structured seeds (with mutation_overrides) are exempt: decaying them
        disrupts AdaptiveMutator weight convergence on T03 paths.
        """
        for k, m in self.meta.items():
            if not m["structured"]:
                m["score"] = max(0.05, m["score"] * factor)

    def add(self, path: Path, initial_score: float = 3.0) -> None:
        """Add a new seed to the pool at runtime (e.g. a saved timeout seed)."""
        key = str(path)
        if path not in self.paths:
            self.paths.append(path)
            self._path_by_key[key] = path
            # Phase 3: runtime-added timeout seeds always go to dedicated timeout bucket.
            tier = "timeout"
            self.meta[key] = {
                "tier": tier,
                "score": initial_score,
                "protected": tier == "attack",
                "structured": False,
                "structured_base": self._structured_min,
                "structured_rounds": self._structured_min,
                "recent_new_key": 0,
                "recent_exec": 0,
                "last_new_key_iter": None,
                "status": "active",
            }
            self._timeout_keys.add(key)

    def prune(self, min_score: float) -> list[Path]:
        """Remove seeds that never generated a qualifying signal and whose score
        is still below min_score. Structured seeds are never pruned."""
        removed: list[Path] = []
        surviving: list[Path] = []
        for p in self.paths:
            key = str(p)
            m = self.meta.get(key)
            if m is None:
                continue
            is_structured = m["structured"]
            contributed = key in self._contributed
            score = m["score"]
            if not is_structured and not contributed and score < min_score:
                removed.append(p)
                self.meta.pop(key, None)
                self._path_by_key.pop(key, None)
                self._pruned_seeds.append(p.name)
                self._timeout_keys.discard(key)
            else:
                surviving.append(p)
        self.paths = surviving
        return removed

    def prune_by_window(self, iteration: int) -> list[Path]:
        removed: list[Path] = []
        survivors: list[Path] = []
        for p in self.paths:
            key = str(p)
            m = self.meta.get(key)
            if m is None:
                continue

            protected = m["protected"] and (not self._allow_prune_protected)
            if protected:
                survivors.append(p)
                continue

            last_new_key = m["last_new_key_iter"]
            no_new_key_long = last_new_key is None or (iteration - last_new_key) >= self._prune_long_window
            low_score = m["score"] < self._prune_min_score
            if m["recent_exec"] > 0 and no_new_key_long and low_score:
                removed.append(p)
                self.meta.pop(key, None)
                self._path_by_key.pop(key, None)
                self._contributed.discard(key)
                self._pruned_seeds.append(p.name)
                self._timeout_keys.discard(key)
            else:
                survivors.append(p)

        self.paths = survivors
        return removed

    def snapshot_top(self, n: int = 8) -> list[dict]:
        ranked = sorted(
            ((k, m["score"]) for k, m in self.meta.items()),
            key=lambda kv: kv[1],
            reverse=True,
        )[:n]
        return [{"seed": k, "score": round(v, 4)} for k, v in ranked]

    def tier_pick_counts(self) -> dict[str, int]:
        return dict(self._tier_pick_counts)

    def tier_pick_ratio(self) -> dict[str, float]:
        if self._total_picks <= 0:
            return {"attack": 0.0, "bridge": 0.0, "background": 0.0, "timeout": 0.0}
        return {
            k: round(v / self._total_picks, 4)
            for k, v in self._tier_pick_counts.items()
        }

    def timeout_pick_ratio(self) -> float:
        if self._total_picks <= 0:
            return 0.0
        return round(self._timeout_picks / self._total_picks, 4)

    def timeout_bucket_size(self) -> int:
        return len([k for k in self._timeout_keys if k in self.meta and k in self._path_by_key])

    def deprioritized_seeds(self) -> list[str]:
        return sorted(self._deprioritized_seeds)

    def pruned_seeds(self) -> list[str]:
        return list(self._pruned_seeds)

    def structured_rounds_histogram(self) -> dict[str, int]:
        hist: dict[str, int] = {}
        for m in self.meta.values():
            if m["structured"]:
                k = str(m["structured_rounds"])
                hist[k] = hist.get(k, 0) + 1
        return hist

    def seed_last_new_key_iter(self) -> dict[str, Optional[int]]:
        out: dict[str, Optional[int]] = {}
        for k, m in self.meta.items():
            out[Path(k).name] = m["last_new_key_iter"]
        return out

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


def parse_cov_markers(stderr_text: str) -> tuple[Optional[str], Optional[int]]:
    sig_match = _COV_SIG_RE.search(stderr_text)
    uniq_match = _COV_UNIQUE_RE.search(stderr_text)
    sig = sig_match.group(1).lower() if sig_match else None
    uniq = int(uniq_match.group(1)) if uniq_match else None
    return sig, uniq

def main() -> None:
    ap = argparse.ArgumentParser(description="File-based fuzz runner with global dedup.")
    ap.add_argument("--target", required=True, help="Target binary path")
    ap.add_argument("--corpus", default="corpus", help="Corpus directory (default: corpus)")
    ap.add_argument("--runs-dir", default="storage/runs", help="Runs directory (default: storage/runs)")
    ap.add_argument("--global-dedup", default="storage/dedup/index.json", help="Global dedup index path")
    ap.add_argument("--iterations", type=int, default=10000)
    ap.add_argument("--timeout-ms", type=int, default=500,
                    help="Per-input timeout in ms (default: 500)")
    ap.add_argument("--mutations", type=int, default=20, help="Mutation rounds per input (default: 20)")
    ap.add_argument(
        "--mutator",
        choices=["adaptive", "uniform"],
        default="adaptive",
        help="Mutator strategy (default: adaptive)",
    )
    ap.add_argument("--seed", type=int, default=None, help="RNG seed for reproducibility")
    ap.add_argument("--max-input-size", type=int, default=MAX_INPUT_SIZE_DEFAULT)
    ap.add_argument("--keep-duplicates", action="store_true", help="Store duplicate crashes as well")
    # Structured seed protection
    ap.add_argument("--structured-seeds", default="",
                    help="Comma-separated seed filenames to protect with fewer mutations (e.g. seed_14.bin,seed_15.bin)")
    ap.add_argument("--structured-mutations", type=int, default=8,
                    help="Base mutation rounds for structured seeds; auto-increases on no-signal (default: 8)")
    # Score decay
    ap.add_argument("--score-decay-interval", type=int, default=0,
                    help="Decay non-structured seed scores every N iters (0=auto=iterations//2, -1=off, default: 0)")
    # Corpus pruning
    ap.add_argument("--prune-after", type=int, default=0,
                    help="Remove low-scoring non-contributing seeds after N iterations (0=off)")
    ap.add_argument("--prune-min-score", type=float, default=1.05,
                    help="Seeds below this score with no signal contribution are pruned (default: 1.05)")
    ap.add_argument("--prune-signal", choices=["new_key", "new_cov"], default="new_key",
                    help="Signal required to mark seed as contributing and exempt from pruning (default: new_key)")
    # Initial score boosts for high-value seeds
    ap.add_argument("--boost-seeds", default="",
                    help="Comma-separated seed:score pairs for initial score boost (e.g. seed_11.bin:4.0,seed_12.bin:4.0)")
    # Timeout seed preservation
    ap.add_argument("--timeout-cov-threshold", type=int, default=20,
                    help="Save timeout inputs with COV_UNIQUE >= threshold to corpus (0=off, default: 20)")
    # Tier scheduling (Phase 1)
    ap.add_argument("--seed-tiers", default="",
                    help="Comma-separated seed:tier overrides (tier=attack|bridge|background|timeout)")
    ap.add_argument("--tier-budget", default="attack:0.5,bridge:0.3,background:0.2",
                    help="Comma-separated tier ratios for non-timeout tiers")
    ap.add_argument("--tier-window", type=int, default=100,
                    help="Tier quota recompute window (default: 100)")
    ap.add_argument("--timeout-tier-max-ratio", type=float, default=0.15,
                    help="Max overall pick ratio for timeout tier (default: 0.15)")
    # Structured adaptive control (Phase 2)
    ap.add_argument("--structured-min-mutations", type=int, default=8,
                    help="Min mutation rounds for structured seeds (default: 8)")
    ap.add_argument("--structured-max-mutations", type=int, default=16,
                    help="Max mutation rounds for structured seeds (default: 16)")
    ap.add_argument("--structured-step", type=int, default=2,
                    help="Mutation round increase step for structured seeds (default: 2)")
    ap.add_argument("--structured-window", type=int, default=80,
                    help="Window for structured no-new_key evaluation (default: 80)")
    # Window prune/deprioritize (Phase 2)
    ap.add_argument("--prune-short-window", type=int, default=500,
                    help="No-new_key short window for deprioritization (default: 500)")
    ap.add_argument("--prune-long-window", type=int, default=1500,
                    help="No-new_key long window for pruning candidates (default: 1500)")
    ap.add_argument("--deprioritize-penalty", type=float, default=0.5,
                    help="Weight multiplier for deprioritized seeds (default: 0.5)")
    ap.add_argument("--allow-prune-protected", action="store_true",
                    help="Allow pruning protected seeds (attack/structured)")
    args = ap.parse_args()

    target_path = str(Path(args.target))
    corpus_dir = Path(args.corpus)
    runs_dir = Path(args.runs_dir)

    seed_paths = sorted([p for p in corpus_dir.glob("*.bin") if p.is_file()])
    if not seed_paths:
        raise SystemExit(f"No seed .bin files found in {corpus_dir}")

    rnd = random.Random(args.seed)
    if args.mutator == "adaptive":
        mutator = AdaptiveMutator(rnd, max_size=args.max_input_size)
    else:
        mutator = UniformMutator(rnd, max_size=args.max_input_size)

    # Build per-seed mutation round overrides for structured seeds
    structured_seed_names = [s.strip() for s in args.structured_seeds.split(",") if s.strip()]
    mutation_overrides = {name: args.structured_mutations for name in structured_seed_names}

    # Parse initial score boosts: "seed_11.bin:4.0,seed_12.bin:4.0"
    score_boosts: dict[str, float] = {}
    for item in (s.strip() for s in args.boost_seeds.split(",") if s.strip()):
        parts = item.rsplit(":", 1)
        if len(parts) == 2:
            try:
                score_boosts[parts[0].strip()] = float(parts[1].strip())
            except ValueError:
                pass

    seed_tier_overrides = parse_seed_tiers(args.seed_tiers)
    tier_budget = parse_tier_budget(args.tier_budget)

    if args.structured_min_mutations > args.structured_max_mutations:
        print("[warn] swapping structured min/max mutations due to invalid range")
        args.structured_min_mutations, args.structured_max_mutations = (
            args.structured_max_mutations,
            args.structured_min_mutations,
        )

    if args.prune_long_window < args.prune_short_window:
        print("[warn] prune-long-window < prune-short-window; using prune-long-window=prune-short-window")
        args.prune_long_window = args.prune_short_window

    # Compute effective score decay interval
    # 0 = auto (iterations // 2), -1 = off, >0 = explicit
    if args.score_decay_interval == 0:
        effective_decay_interval = max(500, args.iterations // 2)
    elif args.score_decay_interval < 0:
        effective_decay_interval = 0  # disabled
    else:
        effective_decay_interval = args.score_decay_interval

    seed_pool = SeedPool(
        seed_paths, rnd,
        mutation_overrides=mutation_overrides if mutation_overrides else None,
        score_boosts=score_boosts if score_boosts else None,
        seed_tiers=seed_tier_overrides if seed_tier_overrides else None,
        tier_budget=tier_budget,
        tier_window=args.tier_window,
        timeout_tier_max_ratio=args.timeout_tier_max_ratio,
        structured_min_mutations=args.structured_min_mutations,
        structured_max_mutations=args.structured_max_mutations,
        structured_step=args.structured_step,
        structured_window=args.structured_window,
        prune_short_window=args.prune_short_window,
        prune_long_window=args.prune_long_window,
        deprioritize_penalty=args.deprioritize_penalty,
        allow_prune_protected=args.allow_prune_protected,
        prune_min_score=args.prune_min_score,
        prune_signal=args.prune_signal,
    )

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
        "mutator": args.mutator,
        "rng_seed": args.seed,
        "max_input_size": args.max_input_size,
        "structured_seeds": structured_seed_names,
        "structured_mutations": args.structured_mutations,
        "score_decay_interval": effective_decay_interval,
        "prune_after": args.prune_after,
        "prune_signal": args.prune_signal,
        "boost_seeds": score_boosts,
        "timeout_cov_threshold": args.timeout_cov_threshold,
        "seed_tiers": seed_tier_overrides,
        "tier_budget": tier_budget,
        "tier_window": args.tier_window,
        "timeout_tier_max_ratio": args.timeout_tier_max_ratio,
        "structured_min_mutations": args.structured_min_mutations,
        "structured_max_mutations": args.structured_max_mutations,
        "structured_step": args.structured_step,
        "structured_window": args.structured_window,
        "prune_short_window": args.prune_short_window,
        "prune_long_window": args.prune_long_window,
        "deprioritize_penalty": args.deprioritize_penalty,
        "allow_prune_protected": args.allow_prune_protected,
    }
    write_json_atomic(run_root / "run.json", run_json)

    dedup = GlobalDedupIndex(Path(args.global_dedup))
    dedup.load()

    index_path = run_root / "index.json"
    index = load_index(index_path, run_id, created_at, target_path)

    crash_seq = 0
    seen_cov_signatures: set[str] = set()
    signal_counts = {"new_key": 0, "new_cov": 0, "existing_key": 0, "no_crash": 0}
    first_new_key_iter: Optional[int] = None
    first_new_cov_iter: Optional[int] = None
    t03_hit_count = 0
    first_t03_iter: Optional[int] = None
    timeout_saved_count = 0
    for i in range(args.iterations):
        seed_path = seed_pool.pick(i)
        seed_data = seed_path.read_bytes()

        mutation_rounds = seed_pool.get_mutation_rounds(seed_path, args.mutations)
        mutated, mutation_trace = mutator.mutate(seed_data, rounds=mutation_rounds)

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

        # Prefer target-reported coverage markers. Fallback to shape/exec proxy.
        target_cov_sig, target_cov_unique = parse_cov_markers(err_t)
        if target_cov_sig is not None:
            cov_sig = f"target:{target_cov_sig}"
        else:
            shape_sig = tlv_shape_signature(mutated)
            exec_sig = sha256_text(
                "|".join(
                    [
                        str(rc),
                        str(int(timeout)),
                        str(len(out_b)),
                        str(len(err_b)),
                        str(min(10000, elapsed_ms // 4)),
                    ]
                )
            )
            cov_sig = f"proxy:{shape_sig}|exec:{exec_sig}"
        is_new_cov = cov_sig not in seen_cov_signatures
        if is_new_cov:
            seen_cov_signatures.add(cov_sig)
            if first_new_cov_iter is None:
                first_new_cov_iter = i

        crash_tag = extract_crash_tag(err_t)
        has_crash = is_crash(rc, timeout) or crash_tag
        
        if has_crash:
            crash_seq += 1
            crash_id = f"{crash_seq:08d}"
            crash_dir = crashes_root / crash_id
            crash_dir.mkdir(parents=True, exist_ok=True)

            # Persist artifacts
            (crash_dir / "input.bin").write_bytes(mutated)
            (crash_dir / "stdout.txt").write_text(out_t, encoding="utf-8")
            (crash_dir / "stderr.txt").write_text(err_t, encoding="utf-8")

            # Parse ASan output for improved dedup
            asan_info = parse_asan_output(err_t)

            # Dedup priority: crash_tag > stack_hash > stderr_hash
            if crash_tag:
                dkey = f"tag:{crash_tag}"
            elif asan_info["stack_hash"]:
                dkey = f"stack:{asan_info['stack_hash']}"
            else:
                dkey = dedup_key_for(None, err_t)

            # global index uses path relative to repo root for portability
            crash_rel = str(crash_dir).replace("\\", "/")

            hit = dedup.register(dkey, crash_rel)
            dedup.save()
            feedback_signal = "new_key" if hit.is_new else ("new_cov" if is_new_cov else "existing_key")
            if hit.is_new and first_new_key_iter is None:
                first_new_key_iter = i
            if crash_tag == "T03_NESTED_STRESS":
                t03_hit_count += 1
                if first_t03_iter is None:
                    first_t03_iter = i
        else:
            feedback_signal = "new_cov" if is_new_cov else "no_crash"
        
        mutator.feedback(mutation_trace, feedback_signal)
        seed_pool.update(seed_path, feedback_signal, i)
        signal_counts[feedback_signal] += 1

        # --- Timeout seed preservation ---
        # Save timeout inputs with high COV_UNIQUE to corpus for future exploration.
        if (
            timeout
            and args.timeout_cov_threshold > 0
            and target_cov_unique is not None
            and target_cov_unique >= args.timeout_cov_threshold
        ):
            ts_name = f"timeout_{sha256_bytes(mutated)[:8]}.bin"
            ts_path = corpus_dir / ts_name
            if not ts_path.exists():
                ts_path.write_bytes(mutated)
                seed_pool.add(ts_path, initial_score=1.5)
                timeout_saved_count += 1

        # --- Periodic score decay ---
        if effective_decay_interval > 0 and (i + 1) % effective_decay_interval == 0:
            seed_pool.decay(factor=0.5)

        # --- Corpus pruning (one-shot at prune_after) ---
        if args.prune_after > 0 and i + 1 == args.prune_after:
            removed = seed_pool.prune(min_score=args.prune_min_score)
            if removed:
                pruned_names = [p.name for p in removed]
                # Record pruning event in run summary (appended later)
                run_json.setdefault("pruned_seeds", []).extend(pruned_names)

        # --- Window-based pruning (Phase 2) ---
        if (i + 1) % 100 == 0:
            removed = seed_pool.prune_by_window(i)
            if removed:
                pruned_names = [p.name for p in removed]
                run_json.setdefault("pruned_seeds", []).extend(pruned_names)

        if has_crash:
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
                        "mutation_trace": mutation_trace,
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
                        "coverage_sig": target_cov_sig,
                        "coverage_unique": target_cov_unique,
                        "asan_bug_type": asan_info.get("bug_type"),
                        "asan_stack_hash": asan_info.get("stack_hash"),
                        "asan_stack_frames": asan_info.get("stack_frames"),
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
                        "asan_bug_type": asan_info.get("bug_type"),
                        "asan_stack_hash": asan_info.get("stack_hash"),
                    }
                )
                write_json_atomic(index_path, index)

    # cleanup
    try:
        inp_path.unlink(missing_ok=True)  # py3.8+: missing_ok, but you target 3.10+ anyway
    except Exception:
        pass

    run_summary = dict(run_json)
    run_summary["signal_counts"] = signal_counts
    run_summary["coverage_proxy_unique"] = len(seen_cov_signatures)
    run_summary["first_new_key_iter"] = first_new_key_iter
    run_summary["first_new_cov_iter"] = first_new_cov_iter
    run_summary["t03_hit_count"] = t03_hit_count
    run_summary["first_t03_iter"] = first_t03_iter
    run_summary["top_seeds"] = seed_pool.snapshot_top()
    run_summary["tier_pick_counts"] = seed_pool.tier_pick_counts()
    run_summary["tier_pick_ratio"] = seed_pool.tier_pick_ratio()
    run_summary["timeout_pick_ratio"] = seed_pool.timeout_pick_ratio()
    run_summary["timeout_bucket_size"] = seed_pool.timeout_bucket_size()
    run_summary["timeout_saved_count"] = timeout_saved_count
    run_summary["deprioritized_seeds"] = seed_pool.deprioritized_seeds()
    run_summary["pruned_seeds"] = seed_pool.pruned_seeds()
    run_summary["structured_rounds_histogram"] = seed_pool.structured_rounds_histogram()
    run_summary["seed_last_new_key_iter"] = seed_pool.seed_last_new_key_iter()
    write_json_atomic(run_root / "run.json", run_summary)

    print(f"Run complete: {run_id}. Crashes recorded: {len(index.get('crashes', []))}")

if __name__ == "__main__":
    main()
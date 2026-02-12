"""
Crash reproduction and analysis.
Generates reproduction scripts and minimal info for each crash.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Optional

from triage.asan import parse_asan_output
from triage.minimize import minimize_file


def generate_repro_script(
    crash_dir: Path,
    target_path: str,
    script_name: str = "repro.sh",
) -> Path:
    """
    Generate a reproduction shell script for a crash.
    
    Creates a simple bash script that executes the target with the crash input.
    """
    input_file = crash_dir / "input.bin"
    if not input_file.exists():
        raise FileNotFoundError(f"Input file not found: {input_file}")
    
    script_path = crash_dir / script_name
    
    # Get absolute paths
    abs_input = input_file.resolve()
    abs_target = Path(target_path).resolve()
    
    script_content = f"""#!/bin/bash
# Reproduction script for crash
# Generated automatically

TARGET="{abs_target}"
INPUT="{abs_input}"

if [[ ! -x "$TARGET" ]]; then
  echo "ERROR: target not found or not executable: $TARGET"
  exit 1
fi

if [[ ! -f "$INPUT" ]]; then
  echo "ERROR: input file not found: $INPUT"
  exit 1
fi

echo "[*] Running: $TARGET $INPUT"
"$TARGET" "$INPUT"
EXIT_CODE=$?
echo "[*] Exit code: $EXIT_CODE"
exit $EXIT_CODE
"""
    
    script_path.write_text(script_content, encoding="utf-8")
    script_path.chmod(0o755)
    
    return script_path


def analyze_crash(crash_dir: Path, target_path: str) -> dict:
    """
    Analyze a crash directory and extract/generate useful info.
    
    Returns dict with:
    - crash_dir: path to crash
    - meta: existing meta.json
    - stderr_parsed: ASan parsing results
    - minimized_input: minimized input (if present)
    - repro_script: path to repro script
    """
    meta_path = crash_dir / "meta.json"
    if not meta_path.exists():
        raise FileNotFoundError(f"meta.json not found: {meta_path}")
    
    stderr_path = crash_dir / "stderr.txt"
    if not stderr_path.exists():
        raise FileNotFoundError(f"stderr.txt not found: {stderr_path}")
    
    # Load metadata
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    
    # Parse stderr
    stderr_text = stderr_path.read_text(encoding="utf-8", errors="replace")
    parsed = parse_asan_output(stderr_text)
    
    # Check for minimized input
    minimized_path = crash_dir / "minimized.bin"
    has_minimized = minimized_path.exists()
    
    # Generate repro script
    repro_script = generate_repro_script(crash_dir, target_path)
    
    return {
        "crash_dir": str(crash_dir),
        "crash_id": meta.get("crash_id"),
        "meta": meta,
        "stderr_parsed": parsed,
        "has_minimized": has_minimized,
        "repro_script": str(repro_script),
    }


def generate_repro_for_run(
    run_dir: Path,
    target_path: str,
    minimize: bool = False,
    timeout_ms: int = 200,
    verbose: bool = False,
) -> None:
    """
    Generate repro info for all crashes in a run directory.
    
    Optionally minimize each input.
    """
    crashes_dir = run_dir / "crashes"
    if not crashes_dir.exists():
        print(f"No crashes directory in {run_dir}")
        return
    
    crash_dirs = sorted([d for d in crashes_dir.iterdir() if d.is_dir()])
    
    for crash_dir in crash_dirs:
        try:
            if verbose:
                print(f"[repro] Analyzing {crash_dir.name}...")
            
            # Generate repro script
            generate_repro_script(crash_dir, target_path)
            
            # Optionally minimize
            if minimize:
                input_path = crash_dir / "input.bin"
                minimized_path = crash_dir / "minimized.bin"
                
                if not minimized_path.exists() and input_path.exists():
                    if verbose:
                        print(f"[repro] Minimizing {crash_dir.name}...")
                    
                    try:
                        minimize_file(
                            target_path,
                            input_path,
                            minimized_path,
                            timeout_ms=timeout_ms,
                            verbose=verbose,
                        )
                    except Exception as e:
                        if verbose:
                            print(f"[repro] Minimization failed: {e}")
            
            if verbose:
                print(f"[repro] Done: {crash_dir.name}")
        
        except Exception as e:
            print(f"[repro] ERROR in {crash_dir.name}: {e}")


def create_crash_summary(crash_dir: Path, target_path: str) -> dict:
    """
    Create a human-readable summary of a crash.
    """
    info = analyze_crash(crash_dir, target_path)
    meta = info["meta"]
    parsed = info["stderr_parsed"]
    
    return {
        "crash_id": meta.get("crash_id"),
        "created_at": meta.get("created_at"),
        "seed_source": meta.get("input", {}).get("seed_source"),
        "input_size": meta.get("input", {}).get("size"),
        "crash_tag": meta.get("triage", {}).get("crash_tag"),
        "asan_bug_type": parsed.get("bug_type"),
        "asan_stack_frames": parsed.get("stack_frames", [])[:3],
        "timeout": meta.get("exec", {}).get("timeout"),
        "returncode": meta.get("exec", {}).get("returncode"),
        "repro_command": f"{target_path} {crash_dir}/input.bin",
    }

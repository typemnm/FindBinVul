"""
Input minimization using delta debugging.
Reduces crash-inducing inputs to minimal size.
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path
from typing import Optional, Callable


def run_target(target_path: str, input_path: str, timeout_ms: int = 200) -> bool:
    """
    Run target with input and return True if it crashes.
    
    Returns:
        True if returncode != 0 or timeout
        False if returncode == 0
    """
    try:
        proc = subprocess.run(
            [target_path, input_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_ms / 1000.0,
        )
        return proc.returncode != 0
    except subprocess.TimeoutExpired:
        return True
    except Exception:
        return False


def minimize_delta(
    target_path: str,
    input_data: bytes,
    timeout_ms: int = 200,
    max_iterations: int = 1000,
    temp_dir: Optional[Path] = None,
) -> bytes:
    """
    Minimize input using delta debugging (bytewise deletion).
    
    Args:
        target_path: Path to target binary
        input_data: Original crash-inducing input
        timeout_ms: Timeout for each execution
        max_iterations: Max iterations to prevent infinite loops
        temp_dir: Directory for temp files (default: /tmp)
    
    Returns:
        Minimized input that still crashes
    """
    if not input_data:
        return input_data
    
    if temp_dir is None:
        import tempfile
        temp_dir = Path(tempfile.gettempdir())
    
    temp_dir = Path(temp_dir)
    temp_file = temp_dir / "minimize_temp.bin"
    
    current = bytearray(input_data)
    iteration = 0
    
    while iteration < max_iterations:
        iteration += 1
        made_progress = False
        
        # Try to delete each byte position
        i = 0
        while i < len(current):
            # Create variant without byte at position i
            variant = current[:i] + current[i + 1 :]
            
            # Test if variant still crashes
            temp_file.write_bytes(bytes(variant))
            if run_target(target_path, str(temp_file), timeout_ms):
                # Crashed! Use this smaller version
                current = variant
                made_progress = True
                # Don't increment i; try deleting from same position again
            else:
                # Didn't crash, move to next byte
                i += 1
        
        if not made_progress:
            # No more progress possible
            break
    
    temp_file.unlink(missing_ok=True)
    return bytes(current)


def minimize_with_callback(
    target_path: str,
    input_data: bytes,
    callback: Optional[Callable[[bytes, int], None]] = None,
    timeout_ms: int = 200,
    max_iterations: int = 1000,
    temp_dir: Optional[Path] = None,
) -> bytes:
    """
    Same as minimize_delta, but with progress callback.
    
    Callback is called with (current_data, iteration_num) after each successful reduction.
    """
    if not input_data:
        return input_data
    
    if temp_dir is None:
        import tempfile
        temp_dir = Path(tempfile.gettempdir())
    
    temp_dir = Path(temp_dir)
    temp_file = temp_dir / "minimize_temp.bin"
    
    current = bytearray(input_data)
    iteration = 0
    
    while iteration < max_iterations:
        iteration += 1
        made_progress = False
        
        i = 0
        while i < len(current):
            variant = current[:i] + current[i + 1 :]
            
            temp_file.write_bytes(bytes(variant))
            if run_target(target_path, str(temp_file), timeout_ms):
                current = variant
                made_progress = True
                
                if callback:
                    callback(bytes(current), iteration)
            else:
                i += 1
        
        if not made_progress:
            break
    
    temp_file.unlink(missing_ok=True)
    return bytes(current)


def minimize_file(
    target_path: str,
    input_path: Path,
    output_path: Path,
    timeout_ms: int = 200,
    verbose: bool = False,
) -> None:
    """
    Minimize a file and write result to output_path.
    """
    input_data = input_path.read_bytes()
    original_size = len(input_data)
    
    start_time = time.time()
    
    def progress_callback(data: bytes, iteration: int) -> None:
        if verbose:
            print(f"[minimize] iteration {iteration}: size={len(data)} bytes")
    
    minimized = minimize_with_callback(
        target_path,
        input_data,
        callback=progress_callback if verbose else None,
        timeout_ms=timeout_ms,
    )
    
    elapsed = time.time() - start_time
    
    output_path.write_bytes(minimized)
    
    if verbose:
        print(f"[minimize] done: {original_size} → {len(minimized)} bytes ({elapsed:.2f}s)")

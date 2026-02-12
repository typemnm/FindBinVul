"""
ASan log parsing and classification.
Extracts bug type, stack traces, and generates stack-based dedup keys.
"""

from __future__ import annotations

import hashlib
import re
from typing import Optional

# Pattern to extract ERROR line and bug type
_ASAN_ERROR_RE = re.compile(
    r"ERROR: AddressSanitizer: ([a-z0-9\-]+)",
    re.IGNORECASE
)

# Pattern to extract stack frames
# Format: #0 0x12345678 in func_name /path/to/file.c:123
_STACK_FRAME_RE = re.compile(
    r"^\s*#(?P<num>\d+)\s+0x[0-9a-f]+\s+in\s+(?P<func>\S+)\s+(?P<file>\S+):(?P<line>\d+)",
    re.MULTILINE | re.IGNORECASE
)

# Simplified frame (just file:line for robustness against ASLR/PIE)
_SIMPLE_FRAME_RE = re.compile(
    r"^\s*#(?P<num>\d+)\s+.*?\s+(?P<file>[a-zA-Z0-9_\-./]+):(?P<line>\d+)",
    re.MULTILINE
)


def extract_bug_type(stderr_text: str) -> Optional[str]:
    """
    Extract the ASan bug type from stderr.
    
    Example: "ERROR: AddressSanitizer: heap-buffer-overflow" → "heap-buffer-overflow"
    
    Returns None if no match found.
    """
    m = _ASAN_ERROR_RE.search(stderr_text)
    if not m:
        return None
    return m.group(1).lower()


def extract_stack_frames(stderr_text: str, top_n: int = 5) -> list[str]:
    """
    Extract all stack frames from ASan output.
    
    Each frame is returned as "function file:line" string.
    Limited to top_n frames.
    """
    frames = []
    
    # Try the full pattern first (with function name)
    for match in _STACK_FRAME_RE.finditer(stderr_text):
        func = match.group("func")
        file = match.group("file")
        line = match.group("line")
        
        # Normalize file path (remove ./ prefix and full paths)
        file = file.split("/")[-1] if "/" in file else file
        
        frame = f"{func} {file}:{line}"
        frames.append(frame)
        
        if len(frames) >= top_n:
            break
    
    # Fallback to simpler pattern if not enough frames found
    if len(frames) < top_n:
        frames = []
        for match in _SIMPLE_FRAME_RE.finditer(stderr_text):
            file = match.group("file")
            line = match.group("line")
            
            # Normalize file path
            file = file.split("/")[-1] if "/" in file else file
            
            frame = f"{file}:{line}"
            frames.append(frame)
            
            if len(frames) >= top_n:
                break
    
    return frames[:top_n]


def compute_stack_hash(stderr_text: str, top_n: int = 3) -> Optional[str]:
    """
    Compute a hash of the top N stack frames.
    
    Returns None if no stack frames found.
    """
    frames = extract_stack_frames(stderr_text, top_n=top_n)
    if not frames:
        return None
    
    # Join top frames and hash
    stack_str = " | ".join(frames)
    hash_val = hashlib.sha256(stack_str.encode("utf-8", errors="replace")).hexdigest()
    return hash_val


def parse_asan_output(stderr_text: str) -> dict:
    """
    Comprehensive ASan log parsing.
    
    Returns dict with:
    - bug_type: str or None
    - stack_frames: list[str]
    - stack_hash: str or None
    """
    bug_type = extract_bug_type(stderr_text)
    stack_frames = extract_stack_frames(stderr_text, top_n=5)
    stack_hash = compute_stack_hash(stderr_text, top_n=3)
    
    return {
        "bug_type": bug_type,
        "stack_frames": stack_frames,
        "stack_hash": stack_hash,
    }

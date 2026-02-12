from __future__ import annotations

import re

_ADDR_RE = re.compile(r"0x[0-9a-fA-F]+")
_COLON_NUM_RE = re.compile(r":\d+")

def normalize_stderr(stderr_text: str, *, max_lines: int = 300) -> str:
    """
    Normalize stderr to reduce non-determinism (addresses, line numbers),
    for fallback dedup hashing when CRASH_TAG is missing.
    """
    lines = stderr_text.splitlines()
    lines = lines[:max_lines]
    text = "\n".join(lines)

    text = _ADDR_RE.sub("0xADDR", text)
    text = _COLON_NUM_RE.sub(":N", text)

    return text
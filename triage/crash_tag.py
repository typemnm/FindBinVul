from __future__ import annotations

import re
from typing import Optional

_TAG_RE = re.compile(r"^CRASH_TAG=(?P<tag>[A-Za-z0-9_.:-]+)\s*$", re.MULTILINE)

def extract_crash_tag(stderr_text: str) -> Optional[str]:
    """
    Extract first CRASH_TAG=... line from stderr.
    Returns None if not found.
    """
    m = _TAG_RE.search(stderr_text)
    if not m:
        return None
    return m.group("tag")
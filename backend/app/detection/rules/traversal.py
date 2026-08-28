"""Directory traversal indicators. Pattern match only."""

from __future__ import annotations

from typing import Any, Optional

from app.detection.rules.common import evidence, find_token, haystacks, hit

TOKENS = [
    "../",
    "..\\",
    "%2e%2e",
    "%252e%252e",
    "..;/",
    "/etc/passwd",
    "..%2f",
    "%2e%2e/",
    "....//",
]


def detect(event: dict[str, Any]) -> Optional[dict]:
    h = haystacks(event)
    tok = find_token(h["low"], TOKENS)
    if not tok:
        return None
    kind = "encoded_traversal" if "%" in tok else "path_traversal"
    return hit(
        "Directory Traversal",
        [evidence(kind, "Traversal sequence in path/query", tok)],
        severity="high",
        risk=72,
    )

"""XXE indicators in query/body. Pattern match only."""

from __future__ import annotations

from typing import Any, Optional

from app.detection.rules.common import evidence, find_token, haystacks, hit

TOKENS = [
    "<!doctype",
    "<!entity",
    "system \"file:",
    "system 'file:",
    "application/xml",
]


def detect(event: dict[str, Any]) -> Optional[dict]:
    h = haystacks(event)
    tok = find_token(h["low"], TOKENS)
    if not tok:
        return None
    return hit(
        "XML External Entity Injection (XXE)",
        [evidence("xxe_token", "DTD/ENTITY or file:// SYSTEM reference in query/body", tok)],
        severity="high",
        risk=74,
    )

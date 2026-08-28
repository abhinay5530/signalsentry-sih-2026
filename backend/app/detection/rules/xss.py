"""XSS indicators in URL/query. Pattern match only."""

from __future__ import annotations

from typing import Any, Optional

from app.detection.rules.common import evidence, find_regex, find_token, haystacks, hit

TOKENS = [
    "<script",
    "</script>",
    "javascript:",
    "onerror=",
    "onload=",
    "<svg",
    "onmouseover=",
    "document.cookie",
    "%3cscript",
    "<img src=",
]
REGEXES = [r"(?i)<\s*script", r"(?i)on\w+\s*=", r"(?i)javascript\s*:", r"%3c\s*script"]


def detect(event: dict[str, Any]) -> Optional[dict]:
    h = haystacks(event)
    tok = find_token(h["low"], TOKENS) or find_regex(h["low"], REGEXES)
    if not tok:
        return None
    return hit(
        "Cross-Site Scripting (XSS)",
        [evidence("xss_token", "Suspicious XSS markup/handler in URL or query", tok)],
        severity="medium",
        risk=65,
    )

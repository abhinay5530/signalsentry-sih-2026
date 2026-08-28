"""SQL injection indicators in URL/query. Pattern match only."""

from __future__ import annotations

from typing import Any, Optional

from app.detection.rules.common import evidence, find_regex, find_token, haystacks, hit

TOKENS = [
    "union select",
    "' or ",
    '" or ',
    " or 1=1",
    "or 1=1--",
    "sleep(",
    "benchmark(",
    "information_schema",
    "xp_cmdshell",
    "waitfor delay",
    "'; drop ",
    "\" or \"\"=\"",
]
REGEXES = [
    r"(?i)union\s+select",
    r"(?i)\bor\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
    r"(?i)['\"]\s*or\s*['\"]?\d",
    r"--\s*$",
    r"(?i)sleep\s*\(\s*\d+",
]


def detect(event: dict[str, Any]) -> Optional[dict]:
    h = haystacks(event)
    tok = find_token(h["low"], TOKENS) or find_regex(h["low"], REGEXES)
    if not tok:
        return None
    loc = "query" if tok.lower() in (h["query"] + safe_extra(h)).lower() else "url/path"
    return hit(
        "SQL Injection",
        [evidence("sql_token", f"Suspicious SQL token in {loc}", tok)],
        severity="high",
        risk=75,
    )


def safe_extra(h):
    return h.get("decoded") or ""

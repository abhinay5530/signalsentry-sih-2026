"""Command injection indicators. Requires a command-like token, not just ';'."""

from __future__ import annotations

from typing import Any, Optional

from app.detection.rules.common import evidence, find_regex, haystacks, hit

REGEXES = [
    r"(?i);\s*(cat|id|whoami|wget|curl|bash|sh|cmd|powershell|nc|ncat|python)\b",
    r"(?i)&&\s*(cat|id|wget|curl|dir|whoami)\b",
    r"(?i)\|\s*(wget|curl|bash|sh|cat|id|whoami)\b",
    r"(?i)\$\(\s*(id|whoami|cat|wget)",
    r"(?i)`\s*(id|whoami|cat)",
]


def detect(event: dict[str, Any]) -> Optional[dict]:
    h = haystacks(event)
    tok = find_regex(h["low"], REGEXES)
    if not tok:
        return None
    return hit(
        "Command Injection",
        [evidence("cmd_token", "Shell metacharacter combined with command-like token", tok)],
        severity="critical",
        risk=85,
    )

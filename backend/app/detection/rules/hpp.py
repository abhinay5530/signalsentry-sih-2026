"""HTTP Parameter Pollution: duplicate query keys."""

from __future__ import annotations

from typing import Any, Optional
from urllib.parse import parse_qs

from app.detection.rules.common import evidence, hit


def detect(event: dict[str, Any]) -> Optional[dict]:
    query = event.get("query") or ""
    if not query:
        return None
    params = parse_qs(query, keep_blank_values=True)
    dups = {k: v for k, v in params.items() if len(v) > 1}
    mixed = ";" in query and "&" in query
    if not dups and not mixed:
        return None
    key = next(iter(dups)) if dups else "mixed_separators"
    snippet = f"{key}={dups[key]}" if dups else query[:120]
    return hit(
        "HTTP Parameter Pollution (HPP)",
        [evidence("dup_params" if dups else "mixed_separators", "Duplicate keys or mixed &/; separators", snippet)],
        severity="low",
        risk=40,
    )

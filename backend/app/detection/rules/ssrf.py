"""SSRF indicators: callback-style params pointing at loopback/metadata. Pattern match only."""

from __future__ import annotations

from typing import Any, Optional
from urllib.parse import parse_qs, unquote

from app.detection.rules.common import evidence, hit

SSRF_PARAMS = ("url", "dest", "destination", "next", "redirect", "uri", "path", "target", "fetch", "src")
SSRF_TARGETS = (
    "127.0.0.1",
    "localhost",
    "0.0.0.0",
    "169.254.169.254",
    "metadata.google.internal",
    "10.0.0.",
    "192.168.",
    "file://",
    "[::1]",
)


def detect(event: dict[str, Any]) -> Optional[dict]:
    query = event.get("query") or ""
    params = parse_qs(query, keep_blank_values=True)
    for key, vals in params.items():
        if key.lower() not in SSRF_PARAMS:
            continue
        for v in vals:
            dv = unquote(v).lower()
            for t in SSRF_TARGETS:
                if t in dv:
                    return hit(
                        "Server-Side Request Forgery (SSRF)",
                        [
                            evidence(
                                "ssrf_target",
                                f"Parameter '{key}' points at a sensitive/internal target",
                                f"{key}={v[:80]}",
                            )
                        ],
                        severity="high",
                        risk=80,
                    )
    blob = (event.get("url") or "") + " " + query
    if "169.254.169.254" in blob.lower():
        return hit(
            "Server-Side Request Forgery (SSRF)",
            [evidence("ssrf_target", "Cloud metadata IP present in URL", "169.254.169.254")],
            severity="high",
            risk=80,
        )
    return None

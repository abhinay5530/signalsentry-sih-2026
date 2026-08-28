"""LFI/RFI indicators. Pattern match only."""

from __future__ import annotations

from typing import Any, Optional
from urllib.parse import parse_qs, unquote

from app.detection.rules.common import evidence, find_token, haystacks, hit

LFI_TOKENS = [
    "/etc/passwd",
    "php://filter",
    "php://input",
    "file://",
    "win.ini",
    "windows/win.ini",
    "boot.ini",
    "expect://",
    "/proc/self",
]
INCLUDE_PARAMS = ("include", "page", "file", "path", "doc", "template", "view")


def detect(event: dict[str, Any]) -> Optional[dict]:
    h = haystacks(event)
    tok = find_token(h["low"], LFI_TOKENS)
    params = parse_qs(event.get("query") or "", keep_blank_values=True)
    rfi = False
    snippet = tok
    for key, vals in params.items():
        if key.lower() not in INCLUDE_PARAMS:
            continue
        for v in vals:
            dv = unquote(v)
            if dv.lower().startswith("http://") or dv.lower().startswith("https://"):
                rfi = True
                snippet = f"{key}={v[:80]}"
            if any(t in dv.lower() for t in LFI_TOKENS):
                tok = tok or dv[:80]
                snippet = f"{key}={v[:80]}"
    if not tok and not rfi:
        return None
    kind = "rfi_remote_include" if rfi else "lfi_wrapper_or_path"
    return hit(
        "Local File Inclusion / Remote File Inclusion (LFI/RFI)",
        [evidence(kind, "File inclusion wrapper, local path, or remote include URL", snippet)],
        severity="high",
        risk=78,
    )

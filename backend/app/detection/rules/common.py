"""Shared helpers for signature detectors. Matches tokens only — never executes payloads."""

from __future__ import annotations

import re
from typing import Any, Iterable, Optional

from app.ingest.normalize import safe_decode


def haystacks(event: dict[str, Any]) -> dict[str, str]:
    parts = {
        "url": event.get("url") or "",
        "path": event.get("path") or "",
        "query": event.get("query") or "",
        "host": event.get("host") or event.get("tls_sni") or "",
        "body": event.get("body") or "",
        "filename": event.get("filename") or "",
    }
    combined = " ".join(parts.values())
    return {
        **{k: v for k, v in parts.items()},
        "raw": combined,
        "decoded": safe_decode(combined),
        "low": (combined + " " + safe_decode(combined)).lower(),
    }


def find_token(text: str, patterns: Iterable[str]) -> Optional[str]:
    low = text.lower()
    for p in patterns:
        if p.lower() in low:
            return p
    return None


def find_regex(text: str, regexes: Iterable[str], flags=re.I) -> Optional[str]:
    for r in regexes:
        m = re.search(r, text, flags)
        if m:
            return m.group(0)[:120]
    return None


def evidence(code: str, detail: str, snippet: Optional[str] = None) -> dict:
    return {"code": code, "detail": detail, "snippet": snippet}


def hit(
    attack_type: str,
    evidence_list: list,
    severity: str = "medium",
    risk: int = 50,
    detectors: str = "rule",
) -> dict:
    return {
        "attack_type": attack_type,
        "status": "ATTEMPT",
        "severity": severity,
        "risk_score": risk,
        "detectors": detectors,
        "evidence": evidence_list,
        "ml_score": None,
    }

"""Credential stuffing / brute force — weak URL hints only; behavioral module does the heavy lift."""

from __future__ import annotations

from typing import Any, Optional

from app.detection.rules.common import evidence, hit
from app.models import LOGIN_PATH_HINTS


def detect(event: dict[str, Any]) -> Optional[dict]:
    path = (event.get("path") or "").lower()
    query = (event.get("query") or "").lower()
    method = (event.get("http_method") or "").upper()
    loginish = any(h in path for h in LOGIN_PATH_HINTS)
    has_pass = "password=" in query or "passwd=" in query or "pwd=" in query
    if loginish and has_pass and method in ("POST", "GET"):
        return hit(
            "Credential Stuffing / Brute Force",
            [
                evidence(
                    "login_params",
                    "Login-like path with password parameter (single event is not confirmation)",
                    (path + "?" + query)[:120],
                )
            ],
            severity="low",
            risk=35,
        )
    return None

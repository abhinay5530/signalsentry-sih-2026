"""Typosquatting / URL spoofing against a static brand watchlist (not a live feed)."""

from __future__ import annotations

import re
from typing import Any, Optional

from app.detection.rules.common import evidence, hit

WATCHLIST = [
    "google.com",
    "gmail.com",
    "microsoft.com",
    "office.com",
    "sbi.co.in",
    "onlinesbi.sbi",
    "uidai.gov.in",
    "irctc.co.in",
    "paytm.com",
    "hdfcbank.com",
    "icicibank.com",
    "facebook.com",
    "apple.com",
    "amazon.in",
    "gov.in",
]

HOMO = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "@": "a", "$": "s"})


def _lev(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            ins, delete, sub = prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)
            cur.append(min(ins, delete, sub))
        prev = cur
    return prev[-1]


def _norm_host(h: str) -> str:
    h = h.lower().strip(".").translate(HOMO)
    h = re.sub(r"-", "", h)
    return h


def detect(event: dict[str, Any]) -> Optional[dict]:
    host = (event.get("host") or event.get("tls_sni") or "").lower()
    if not host:
        return None
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        return hit(
            "Typosquatting / URL spoofing",
            [evidence("ip_as_hostname", "Hostname is a raw IP address (common in spoofed sites)", host)],
            severity="medium",
            risk=45,
        )
    nh = _norm_host(host)
    for brand in WATCHLIST:
        nb = _norm_host(brand)
        if host == brand or host.endswith("." + brand):
            return None
        dist = _lev(nh, nb)
        # Homoglyphs can normalize to the real brand while the raw host differs
        if nh == nb and host != brand and not host.endswith("." + brand):
            return hit(
                "Typosquatting / URL spoofing",
                [
                    evidence(
                        "homoglyph_host",
                        f"Hostname normalizes to watchlist domain {brand} (static list, not live intel)",
                        host,
                    )
                ],
                severity="high",
                risk=72,
            )
        # Lookalike: small edit distance, not identical, similar length
        if 0 < dist <= 2 and abs(len(nh) - len(nb)) <= 3:
            return hit(
                "Typosquatting / URL spoofing",
                [
                    evidence(
                        "lookalike_host",
                        f"Hostname is edit-distance {dist} from watchlist domain {brand} (static list, not live intel)",
                        host,
                    )
                ],
                severity="high",
                risk=70,
            )
        if brand.split(".")[0] in host and host != brand and not host.endswith("." + brand):
            if any(x in host for x in ("-", "login", "secure", "verify")):
                return hit(
                    "Typosquatting / URL spoofing",
                    [evidence("brand_in_host", f"Brand token from {brand} embedded in unrelated host", host)],
                    severity="medium",
                    risk=55,
                )
    return None

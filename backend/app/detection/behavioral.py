"""Per-source-IP windows: bursts, repeats, auth failures. Complements URL signatures."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

from app.detection.rules.common import evidence, hit
from app.models import LOGIN_PATH_HINTS


def _ts(ev: dict) -> datetime:
    s = ev.get("timestamp") or ""
    try:
        return datetime.fromisoformat(str(s).replace("Z", ""))
    except ValueError:
        return datetime.min


def annotate_frequencies(events: list[dict[str, Any]]) -> None:
    """Fill request_freq_src_1m on each event (1-minute window, same src_ip)."""
    by_ip: dict[str, list[tuple[datetime, int]]] = defaultdict(list)
    for i, ev in enumerate(events):
        by_ip[ev.get("src_ip") or ""].append((_ts(ev), i))
    for ip, pairs in by_ip.items():
        pairs.sort(key=lambda x: x[0])
        j = 0
        for k, (t, idx) in enumerate(pairs):
            while j < k and t - pairs[j][0] > timedelta(minutes=1):
                j += 1
            events[idx]["request_freq_src_1m"] = k - j + 1


def behavioral_hits(events: list[dict[str, Any]]) -> list[tuple[int, dict]]:
    """Return (event_index, detection) extra hits from behavior."""
    annotate_frequencies(events)
    extra: list[tuple[int, dict]] = []
    by_ip: dict[str, list[int]] = defaultdict(list)
    for i, ev in enumerate(events):
        by_ip[ev.get("src_ip") or ""].append(i)

    for ip, idxs in by_ip.items():
        idxs_sorted = sorted(idxs, key=lambda i: _ts(events[i]))
        login_fail = []
        for i in idxs_sorted:
            ev = events[i]
            path = (ev.get("path") or "").lower()
            status = ev.get("http_status")
            loginish = any(h in path for h in LOGIN_PATH_HINTS)
            if loginish and status in (401, 403, 429):
                login_fail.append(i)
            freq = ev.get("request_freq_src_1m") or 0
            if freq >= 40:
                extra.append(
                    (
                        i,
                        hit(
                            "Credential Stuffing / Brute Force",
                            [
                                evidence(
                                    "burst_rate",
                                    f"{freq} requests from {ip} in a 1-minute window (behavioral)",
                                    str(freq),
                                )
                            ],
                            severity="medium",
                            risk=55,
                            detectors="behavior",
                        ),
                    )
                )
        # Auth failure cluster
        if len(login_fail) >= 8:
            extra.append(
                (
                    login_fail[-1],
                    hit(
                        "Credential Stuffing / Brute Force",
                        [
                            evidence(
                                "auth_fail_burst",
                                f"{len(login_fail)} HTTP 401/403/429 on login-like paths from {ip}",
                                str(len(login_fail)),
                            )
                        ],
                        severity="high",
                        risk=70,
                        detectors="behavior",
                    ),
                )
            )
    return extra

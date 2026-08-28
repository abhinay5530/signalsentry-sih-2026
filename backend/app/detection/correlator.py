"""ATTEMPT vs CONFIRMED vs UNKNOWN. Never confirm from a malicious-looking URL alone."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

from app.models import LOGIN_PATH_HINTS, SUCCESS_LOOKS_LIKE_PAGE, UPLOAD_PATH_HINTS

WINDOW = timedelta(minutes=10)
AUTH_FAIL_MIN = 8


def _ts(ev: dict) -> datetime:
    try:
        return datetime.fromisoformat(str(ev.get("timestamp") or "").replace("Z", ""))
    except ValueError:
        return datetime.min


def _sev_score(attack_type: str, status: str, base_risk: int) -> tuple[str, int]:
    critical_types = {
        "Command Injection",
        "Web shell upload indicators",
        "SQL Injection",
        "Local File Inclusion / Remote File Inclusion (LFI/RFI)",
        "Server-Side Request Forgery (SSRF)",
    }
    if status == "CONFIRMED" and attack_type in critical_types:
        return "critical", min(100, base_risk + 25)
    if status == "CONFIRMED":
        return "high", min(100, base_risk + 15)
    if attack_type in ("HTTP Parameter Pollution (HPP)",) and status == "ATTEMPT":
        return "low", max(20, base_risk - 10)
    if attack_type == "Cross-Site Scripting (XSS)" and status == "ATTEMPT":
        return "medium", base_risk
    if status == "UNKNOWN":
        return "low", max(15, base_risk - 20)
    return ("high" if base_risk >= 70 else "medium" if base_risk >= 45 else "low"), base_risk


def correlate(events: list[dict[str, Any]], detections_by_idx: list[list[dict]]) -> None:
    """Mutates detections_by_idx in place: set status, severity, risk, extra evidence."""
    by_pair: dict[tuple[str, str], list[int]] = defaultdict(list)
    for i, ev in enumerate(events):
        by_pair[(ev.get("src_ip") or "", ev.get("dst_ip") or "")].append(i)

    # Precompute login fail-then-success per src
    login_success_after_fails: set[int] = set()
    by_src: dict[str, list[int]] = defaultdict(list)
    for i, ev in enumerate(events):
        by_src[ev.get("src_ip") or ""].append(i)
    for ip, idxs in by_src.items():
        idxs = sorted(idxs, key=lambda i: _ts(events[i]))
        fails = 0
        for i in idxs:
            ev = events[i]
            path = (ev.get("path") or "").lower()
            loginish = any(h in path for h in LOGIN_PATH_HINTS)
            st = ev.get("http_status")
            if loginish and st in (401, 403, 429):
                fails += 1
            elif loginish and st in (200, 201, 204, 302) and fails >= AUTH_FAIL_MIN:
                login_success_after_fails.add(i)

    # Webshell: upload 200 then later GET same path 200
    upload_ok: dict[tuple[str, str], list[tuple[datetime, str]]] = defaultdict(list)
    for i, ev in enumerate(events):
        path = (ev.get("path") or "").lower()
        if ev.get("http_status") in (200, 201) and (
            any(h in path for h in UPLOAD_PATH_HINTS) or (ev.get("filename") or "")
        ):
            upload_ok[(ev.get("src_ip") or "", ev.get("dst_ip") or "")].append((_ts(ev), path))

    webshell_follow: set[int] = set()
    for i, ev in enumerate(events):
        path = (ev.get("path") or "").lower()
        key = (ev.get("src_ip") or "", ev.get("dst_ip") or "")
        t = _ts(ev)
        if ev.get("http_status") in (200, 201) and path:
            fname = (ev.get("filename") or "").lower()
            for ut, up in upload_ok.get(key, []):
                later_upload_path = "/uploads/" in path or "/upload/" in path
                same_name = bool(fname) and fname in path
                if t > ut and (later_upload_path or same_name or path == up):
                    webshell_follow.add(i)
                    break

    for i, ev in enumerate(events):
        dets = detections_by_idx[i]
        if not dets:
            continue
        avail = ev.get("url_availability") or "metadata_only"
        complete = int(ev.get("http_complete") or 0)
        st = ev.get("http_status")
        size = ev.get("response_size") or 0
        t = _ts(ev)
        pair_idxs = by_pair[(ev.get("src_ip") or "", ev.get("dst_ip") or "")]

        for det in dets:
            atype = det["attack_type"]
            evid = list(det.get("evidence") or [])

            # UNKNOWN: incomplete HTTP and no host similarity already handled; weak volume-only
            if complete == 0 and atype not in ("Typosquatting / URL spoofing", "Credential Stuffing / Brute Force"):
                det["status"] = "UNKNOWN"
                evid.append(
                    {
                        "code": "incomplete_http",
                        "detail": f"Application-layer URL/path unavailable ({avail}); not treated as confirmed",
                        "snippet": avail,
                    }
                )
                sev, risk = _sev_score(atype, "UNKNOWN", det.get("risk_score", 30))
                det["severity"], det["risk_score"], det["evidence"] = sev, risk, evid
                continue

            if avail == "tls_sni_only" and atype != "Typosquatting / URL spoofing":
                det["status"] = "UNKNOWN"
                evid.append(
                    {
                        "code": "tls_sni_only",
                        "detail": "Encrypted HTTPS: SNI/host only; path/query not fabricated",
                        "snippet": ev.get("tls_sni"),
                    }
                )
                sev, risk = _sev_score(atype, "UNKNOWN", det.get("risk_score", 30))
                det["severity"], det["risk_score"], det["evidence"] = sev, risk, evid
                continue

            confirmed = False
            reason = None

            # CONFIRMED requires a rule/behavior hit (already true here) PLUS
            # corroborating HTTP outcome — never URL/payload, lone 2xx, lone size, or an unrelated 500.
            if atype in SUCCESS_LOOKS_LIKE_PAGE and st in (200, 201, 204):
                path = (ev.get("path") or "").lower()
                for j in pair_idxs:
                    if j == i:
                        continue
                    other = events[j]
                    if _ts(other) >= t:
                        continue
                    if abs((t - _ts(other)).total_seconds()) > WINDOW.total_seconds():
                        continue
                    if (other.get("path") or "").lower() != path:
                        continue
                    ost = other.get("http_status")
                    if ost not in (401, 403, 404, 500):
                        continue
                    if not any(d.get("attack_type") == atype for d in detections_by_idx[j]):
                        continue
                    confirmed = True
                    reason = {
                        "code": "fail_then_success",
                        "detail": (
                            f"Same attack type and path: earlier HTTP {ost} then HTTP {st} "
                            f"from same src/dst within 10 minutes (HTTP metadata heuristic, not host proof)"
                        ),
                        "snippet": f"{ost}->{st}",
                    }
                    other_size = other.get("response_size") or 0
                    if ost == 500 and size and other_size and size > other_size:
                        reason = {
                            "code": "error_then_data",
                            "detail": (
                                f"Same attack type and path: HTTP 500 then HTTP {st} with larger "
                                f"response_size ({other_size}->{size}); not size-alone confirmation"
                            ),
                            "snippet": str(size),
                        }
                    break

            if atype == "Credential Stuffing / Brute Force" and i in login_success_after_fails:
                confirmed = True
                reason = {
                    "code": "auth_fail_then_200",
                    "detail": f"At least {AUTH_FAIL_MIN} login failures then HTTP {st} on a login-like path",
                    "snippet": str(st),
                }

            if atype == "Web shell upload indicators" and i in webshell_follow and st in (200, 201):
                confirmed = True
                reason = {
                    "code": "upload_then_access",
                    "detail": "Upload-like 2xx followed by later 2xx to the same/upload path",
                    "snippet": ev.get("path"),
                }
            if atype == "Web shell upload indicators" and st in (200, 201) and (ev.get("filename") or "").lower().endswith(
                (".php", ".jsp", ".aspx")
            ):
                # upload success is still ATTEMPT unless follow-on; keep attempt
                pass

            if confirmed and reason:
                det["status"] = "CONFIRMED"
                evid.append(reason)
                evid.append(
                    {
                        "code": "not_url_only",
                        "detail": "Confirmed using corroborating HTTP metadata/sequence, not the URL pattern alone",
                        "snippet": None,
                    }
                )
            else:
                det["status"] = "ATTEMPT"
                if st in (401, 403, 404, 500):
                    evid.append(
                        {
                            "code": "blocked_or_error",
                            "detail": f"HTTP {st} — indicator present but insufficient evidence of successful exploitation",
                            "snippet": str(st),
                        }
                    )
                else:
                    evid.append(
                        {
                            "code": "no_corroboration",
                            "detail": "Suspicious request detected; no same-type fail-then-success, auth sequence, or upload follow-on",
                            "snippet": str(st) if st is not None else None,
                        }
                    )

            sev, risk = _sev_score(atype, det["status"], det.get("risk_score", 40))
            det["severity"] = sev
            det["risk_score"] = risk
            det["evidence"] = evid

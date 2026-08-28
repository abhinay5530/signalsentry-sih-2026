"""Structural URL features for rules, ML, and evidence. No payload execution."""

from __future__ import annotations

import json
import math
import re
from typing import Any
from urllib.parse import parse_qs

from app.ingest.normalize import safe_decode

SQL_HINTS = ("union select", "' or", " or 1=1", "sleep(", "benchmark(", "information_schema", "--", "xp_cmdshell")
XSS_HINTS = ("<script", "javascript:", "onerror=", "onload=", "<svg", "%3cscript")
TRAV_HINTS = ("../", "..\\", "%2e%2e", "..;/", "/etc/passwd")
CMD_HINTS = ("$(", "`", "&&", "| wget", "| curl", "powershell", "; cat ", "; id")
SSRF_HINTS = ("169.254.169.254", "127.0.0.1", "localhost", "metadata.google")
LFI_HINTS = ("php://", "file://", "win.ini", "/etc/passwd", "expect://")
XXE_HINTS = ("<!entity", "<!doctype", "system \"file")
SHELL_EXTS = (".php", ".jsp", ".aspx", ".jspx", "c99", "b374k", "cmd.aspx", "shell.php")


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def extract_features(event: dict[str, Any]) -> dict[str, Any]:
    host = event.get("host") or event.get("tls_sni") or ""
    path = event.get("path") or ""
    query = event.get("query") or ""
    url = event.get("url") or ""
    blob = " ".join(x for x in (url, path, query, event.get("body") or "", event.get("filename") or "") if x)
    blob_l = blob.lower()
    decoded = safe_decode(blob).lower()
    hay = blob_l + " " + decoded

    params = parse_qs(query, keep_blank_values=True) if query else {}
    special = sum(1 for c in blob if not c.isalnum() and c not in "-._~")
    digits = sum(1 for c in blob if c.isdigit())
    pct = blob_l.count("%")
    double_enc = "%25" in blob_l
    ip_host = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))

    feats = {
        "url_len": len(url or (path + query)),
        "host_len": len(host),
        "path_len": len(path),
        "query_len": len(query),
        "path_depth": path.count("/") if path else 0,
        "param_count": sum(len(v) for v in params.values()) if params else 0,
        "digit_ratio": (digits / max(len(blob), 1)),
        "special_char_count": special,
        "entropy_path": round(_entropy(path), 4),
        "entropy_query": round(_entropy(query), 4),
        "dot_count_host": host.count("."),
        "is_ip_host": int(ip_host),
        "has_userinfo": int("@" in (url or "")),
        "port_nondefault": int(bool(event.get("dst_port") and event.get("dst_port") not in (80, 443, 8080, None))),
        "pct_encoded_count": pct,
        "double_encoded": int(double_enc),
        "unicode_escape": int("\\u" in blob_l or "%u" in blob_l),
        "null_byte_enc": int("%00" in blob_l),
        "has_sql_token": int(any(t in hay for t in SQL_HINTS)),
        "has_xss_token": int(any(t in hay for t in XSS_HINTS)),
        "has_traversal": int(any(t in hay for t in TRAV_HINTS)),
        "has_cmd_token": int(any(t in hay for t in CMD_HINTS)),
        "has_ssrf_token": int(any(t in hay for t in SSRF_HINTS)),
        "has_lfi_token": int(any(t in hay for t in LFI_HINTS)),
        "has_xxe_token": int(any(t in hay for t in XXE_HINTS)),
        "has_hpp_dup_params": int(any(len(v) > 1 for v in params.values())),
        "has_upload_ext": int(any(x in hay for x in SHELL_EXTS)),
        "typo_similar_to_watchlist": 0,
        "http_complete": int(event.get("http_complete") or 0),
        "http_status": event.get("http_status") or 0,
        "response_size": event.get("response_size") or 0,
        "src_req_1m": event.get("request_freq_src_1m") or 0,
    }
    return feats


def features_json(event: dict[str, Any]) -> str:
    return json.dumps(extract_features(event))

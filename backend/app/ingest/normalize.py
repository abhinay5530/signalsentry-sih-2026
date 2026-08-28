"""Normalize IPDR-like records into a canonical event. Never invent HTTP paths."""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from typing import Any, Optional
from urllib.parse import urlparse, parse_qs, unquote

from app.config import MAX_DECODE_ROUNDS, MAX_URL_LEN

COLUMN_ALIASES = {
    "timestamp": ["timestamp", "time", "datetime", "event_time", "start_time"],
    "src_ip": ["src_ip", "source_ip", "src", "client_ip", "sip"],
    "dst_ip": ["dst_ip", "dest_ip", "destination_ip", "dst", "server_ip", "dip"],
    "src_port": ["src_port", "sport", "source_port"],
    "dst_port": ["dst_port", "dport", "destination_port"],
    "protocol": ["protocol", "proto"],
    "http_method": ["http_method", "method", "http_verb"],
    "host": ["host", "hostname", "http_host", "domain"],
    "path": ["path", "uri_path", "http_path"],
    "query": ["query", "query_string", "qs"],
    "url": ["url", "uri", "request_uri", "http_url"],
    "http_status": ["http_status", "status", "status_code", "http_code"],
    "response_size": ["response_size", "resp_bytes", "bytes", "content_length"],
    "user_agent": ["user_agent", "ua", "http_user_agent"],
    "dns_qname": ["dns_qname", "dns", "qname"],
    "tls_sni": ["tls_sni", "sni"],
    "body": ["body", "http_body", "post_body"],
    "filename": ["filename", "upload_filename"],
    "scenario_id": ["scenario_id", "scenario"],
}


def _pick(row: dict[str, Any], field: str) -> Any:
    keys = {str(k).strip().lower(): k for k in row.keys()}
    for alias in COLUMN_ALIASES.get(field, [field]):
        if alias.lower() in keys:
            val = row[keys[alias.lower()]]
            if val is not None and str(val).strip() != "":
                return val
    return None


def safe_decode(text: Optional[str]) -> str:
    """Percent-decode at most MAX_DECODE_ROUNDS. Pattern matching only — not execution."""
    if not text:
        return ""
    s = text[:MAX_URL_LEN]
    for _ in range(MAX_DECODE_ROUNDS):
        try:
            nxt = unquote(s)
        except Exception:
            break
        if nxt == s:
            break
        s = nxt[:MAX_URL_LEN]
    return s


def parse_ts(value: Any) -> str:
    if value is None:
        return datetime.utcnow().isoformat()
    s = str(value).strip()
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%d/%m/%Y %H:%M:%S",
    ):
        try:
            return datetime.strptime(s.replace("Z", "").replace("+00:00", "")[:26], fmt).isoformat()
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).replace(tzinfo=None).isoformat()
    except ValueError:
        return s


def _valid_ip(val: Any) -> Optional[str]:
    if val is None:
        return None
    s = str(val).strip()
    try:
        ipaddress.ip_address(s)
        return s
    except ValueError:
        return s if s else None


def split_url(url: Optional[str], host: Optional[str], path: Optional[str], query: Optional[str]):
    h, p, q, full = host, path, query, url
    if url:
        raw = str(url)[:MAX_URL_LEN]
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
            raw_for_parse = "http://" + raw.lstrip("/")
        else:
            raw_for_parse = raw
        parsed = urlparse(raw_for_parse)
        h = h or parsed.hostname
        p = p or parsed.path or "/"
        q = q if q is not None else (parsed.query or None)
        full = raw
    if p and "?" in str(p) and not q:
        p, q = str(p).split("?", 1)
    return h, p, q, full


def infer_availability(host, path, url, tls_sni, dns_qname, http_complete_hint=None, availability_hint=None) -> tuple[int, str]:
    # Honor explicit incomplete records (truncated IPDR) so UNKNOWN can be assigned downstream.
    hint = None
    if http_complete_hint is not None and str(http_complete_hint) != "":
        try:
            hint = int(http_complete_hint)
        except (TypeError, ValueError):
            hint = None
    if hint == 0:
        if tls_sni and not path and not url:
            return 0, "tls_sni_only"
        return 0, availability_hint or "metadata_only"
    if tls_sni and not path and not url:
        return 0, "tls_sni_only"
    if path or url:
        return 1, "full_http"
    if host and not tls_sni:
        return 0, "host_only"
    if dns_qname and not host:
        return 0, "dns_only"
    if host:
        return 0, "host_only"
    if http_complete_hint is not None:
        return int(http_complete_hint), "metadata_only"
    return 0, "metadata_only"


def normalize_row(row: dict[str, Any], source_type: str = "ipdr") -> dict[str, Any]:
    url = _pick(row, "url")
    host = _pick(row, "host")
    path = _pick(row, "path")
    query = _pick(row, "query")
    tls_sni = _pick(row, "tls_sni")
    dns_qname = _pick(row, "dns_qname")
    method = _pick(row, "http_method")
    host, path, query, url = split_url(url, host, path, query)
    if not host and tls_sni:
        host = str(tls_sni)

    complete_hint = row.get("http_complete")
    http_complete, availability = infer_availability(
        host,
        path,
        url,
        tls_sni,
        dns_qname,
        complete_hint,
        row.get("url_availability"),
    )
    if availability == "tls_sni_only":
        path = None
        query = None
        url = None
        http_complete = 0

    def _int(v):
        if v is None or v == "":
            return None
        try:
            return int(float(v))
        except (TypeError, ValueError):
            return None

    proto = _pick(row, "protocol") or "TCP"
    return {
        "source_type": source_type,
        "timestamp": parse_ts(_pick(row, "timestamp")),
        "src_ip": _valid_ip(_pick(row, "src_ip")) or "0.0.0.0",
        "dst_ip": _valid_ip(_pick(row, "dst_ip")) or "0.0.0.0",
        "src_port": _int(_pick(row, "src_port")),
        "dst_port": _int(_pick(row, "dst_port")),
        "protocol": str(proto).upper() if proto else "TCP",
        "http_method": str(method).upper() if method else None,
        "host": str(host).lower() if host else None,
        "path": str(path) if path else None,
        "query": str(query) if query else None,
        "url": str(url)[:MAX_URL_LEN] if url else None,
        "http_status": _int(_pick(row, "http_status")),
        "response_size": _int(_pick(row, "response_size")),
        "user_agent": str(_pick(row, "user_agent")) if _pick(row, "user_agent") else None,
        "dns_qname": str(dns_qname) if dns_qname else None,
        "tls_sni": str(tls_sni).lower() if tls_sni else None,
        "http_complete": http_complete,
        "url_availability": availability,
        "request_freq_src_1m": _int(row.get("request_freq_src_1m")),
        "body": str(_pick(row, "body"))[:MAX_URL_LEN] if _pick(row, "body") else None,
        "filename": str(_pick(row, "filename")) if _pick(row, "filename") else None,
        "scenario_id": str(_pick(row, "scenario_id")) if _pick(row, "scenario_id") else None,
        "features_json": None,
    }


def query_param_map(query: Optional[str]) -> dict[str, list[str]]:
    if not query:
        return {}
    return parse_qs(query, keep_blank_values=True)

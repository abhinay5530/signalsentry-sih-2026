"""Filter helpers: IP, CIDR, attack type, status, time."""

from __future__ import annotations

import ipaddress
from typing import Any, Optional

from app.db import row_to_dict


def parse_cidr(value: Optional[str]):
    if not value:
        return None
    v = value.strip()
    try:
        if "/" in v:
            return ipaddress.ip_network(v, strict=False)
        return ipaddress.ip_network(v + "/32", strict=False)
    except ValueError:
        return None


def ip_matches(ip: Optional[str], network) -> bool:
    if not network:
        return True
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip) in network
    except ValueError:
        return False


def apply_event_filters(rows: list[dict], **f) -> list[dict]:
    src = f.get("src_ip")
    dst = f.get("dst_ip")
    cidr = parse_cidr(f.get("cidr"))
    q = (f.get("q") or "").lower()
    t0, t1 = f.get("time_from"), f.get("time_to")
    source_type = f.get("source_type")
    out = []
    for r in rows:
        if src and r.get("src_ip") != src:
            continue
        if dst and r.get("dst_ip") != dst:
            continue
        if cidr and not (ip_matches(r.get("src_ip"), cidr) or ip_matches(r.get("dst_ip"), cidr)):
            continue
        if source_type and r.get("source_type") != source_type:
            continue
        if t0 and (r.get("timestamp") or "") < t0:
            continue
        if t1 and (r.get("timestamp") or "") > t1:
            continue
        if q:
            blob = " ".join(
                str(r.get(k) or "") for k in ("url", "path", "query", "host", "src_ip", "dst_ip")
            ).lower()
            if q not in blob:
                continue
        out.append(r)
    return out


def detection_join_sql() -> str:
    return """
    SELECT d.id AS detection_id, d.attack_type, d.status, d.severity, d.risk_score,
           d.detectors, d.evidence_json, d.ml_score,
           e.id AS event_id,
           e.batch_id, e.source_type, e.timestamp, e.src_ip, e.dst_ip, e.src_port, e.dst_port,
           e.protocol, e.http_method, e.host, e.path, e.query, e.url, e.http_status,
           e.response_size, e.user_agent, e.dns_qname, e.tls_sni, e.http_complete,
           e.url_availability, e.request_freq_src_1m, e.features_json, e.filename, e.scenario_id
    FROM detections d
    JOIN normalized_events e ON e.id = d.event_id
    WHERE 1=1
    """


def fetch_joined(conn, attack_type=None, status=None, severity=None) -> list[dict[str, Any]]:
    sql = detection_join_sql()
    params: list[Any] = []
    if attack_type:
        sql += " AND d.attack_type = ?"
        params.append(attack_type)
    if status:
        sql += " AND d.status = ?"
        params.append(status)
    if severity:
        sql += " AND d.severity = ?"
        params.append(severity)
    sql += " ORDER BY e.timestamp DESC"
    rows = conn.execute(sql, params).fetchall()
    out = []
    for r in rows:
        d = row_to_dict(r)
        d.pop("features_json", None)
        d.pop("features", None)
        out.append(d)
    return out

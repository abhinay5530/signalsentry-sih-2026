"""FastAPI routes for ingest, query, stats, investigate, export."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from io import StringIO
from typing import Optional

import pandas as pd
from fastapi import APIRouter, File, HTTPException, Query, UploadFile
from fastapi.responses import JSONResponse, Response

from app.config import DATA_DIR, MAX_UPLOAD_BYTES
from app.db import db_session, row_to_dict
from app.ingest.ipdr import parse_ipdr_bytes
from app.ingest.normalize import normalize_row
from app.ingest.pcap import parse_pcap_bytes
from app.api.filters import apply_event_filters, fetch_joined
from app.models import ATTACK_TYPES
from app.pipeline import ingest_events

router = APIRouter(prefix="/api")


def _check_size(data: bytes) -> None:
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "Upload exceeds 50MB limit")


@router.get("/health")
def health():
    return {"ok": True, "service": "SentinelIP"}


@router.get("/attack-types")
def attack_types():
    return {"types": ATTACK_TYPES}


@router.get("/batches")
def batches():
    with db_session() as conn:
        rows = conn.execute("SELECT * FROM ingest_batches ORDER BY id DESC").fetchall()
        return {"batches": [dict(r) for r in rows]}


@router.post("/ingest/ipdr")
async def ingest_ipdr(file: UploadFile = File(...)):
    data = await file.read()
    _check_size(data)
    try:
        events = parse_ipdr_bytes(data, file.filename or "ipdr.csv")
    except Exception as e:
        raise HTTPException(400, f"Could not parse IPDR file: {e}") from e
    with db_session() as conn:
        result = ingest_events(conn, events, "ipdr", file.filename or "ipdr.csv")
    return result


@router.post("/ingest/pcap")
async def ingest_pcap(file: UploadFile = File(...)):
    data = await file.read()
    _check_size(data)
    try:
        events = parse_pcap_bytes(data, file.filename or "capture.pcap")
    except Exception as e:
        raise HTTPException(400, f"Could not parse PCAP: {e}") from e
    with db_session() as conn:
        result = ingest_events(conn, events, "pcap", file.filename or "capture.pcap", note="PCAP parse; HTTPS paths not fabricated")
    return result


@router.post("/ingest/synthetic")
def ingest_synthetic(n: int = 10000, seed: int = 42):
    n = max(500, min(n, 20000))
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    from datasets.generate import generate_events, write_sample_pcap

    raw = generate_events(n, seed)
    events = [normalize_row(r, source_type="synthetic") for r in raw]
    pcap_path = DATA_DIR / "sample.pcap"
    if not pcap_path.exists():
        try:
            write_sample_pcap(pcap_path)
        except Exception:
            pass
    with db_session() as conn:
        result = ingest_events(
            conn,
            events,
            "synthetic",
            f"synthetic_n{n}_seed{seed}.json",
            note="Self-generated dataset (not ISP IPDR)",
        )
    return result


@router.get("/events")
def list_events(
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    cidr: Optional[str] = None,
    source_type: Optional[str] = None,
    q: Optional[str] = None,
    time_from: Optional[str] = None,
    time_to: Optional[str] = None,
    attack_type: Optional[str] = None,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 200,
    offset: int = 0,
):
    """Event list. attack_type/status/severity keep events that have a matching detection (same join as /detections)."""
    with db_session() as conn:
        rows = [row_to_dict(r) for r in conn.execute("SELECT * FROM normalized_events ORDER BY timestamp DESC").fetchall()]
        detection_ids = None
        if attack_type or status or severity:
            hits = fetch_joined(conn, attack_type=attack_type, status=status, severity=severity)
            detection_ids = {h.get("event_id") for h in hits}
    for r in rows:
        r.pop("features_json", None)
        r.pop("features", None)
    if detection_ids is not None:
        rows = [r for r in rows if r.get("id") in detection_ids]
    filtered = apply_event_filters(
        rows, src_ip=src_ip, dst_ip=dst_ip, cidr=cidr, q=q, time_from=time_from, time_to=time_to, source_type=source_type
    )
    return {"total": len(filtered), "events": filtered[offset : offset + limit]}


@router.get("/events/{event_id}")
def event_detail(event_id: int):
    with db_session() as conn:
        ev = conn.execute("SELECT * FROM normalized_events WHERE id=?", (event_id,)).fetchone()
        if not ev:
            raise HTTPException(404, "Event not found")
        event = row_to_dict(ev)
        dets = [row_to_dict(r) for r in conn.execute("SELECT * FROM detections WHERE event_id=?", (event_id,)).fetchall()]
        related = [
            row_to_dict(r)
            for r in conn.execute(
                """SELECT e.id, e.timestamp, e.src_ip, e.dst_ip, e.path, e.http_status, d.attack_type, d.status
                   FROM normalized_events e
                   LEFT JOIN detections d ON d.event_id = e.id
                   WHERE e.src_ip=? AND e.id!=?
                   ORDER BY e.timestamp DESC LIMIT 25""",
                (event.get("src_ip"), event_id),
            ).fetchall()
        ]
    return {"event": event, "detections": dets, "related": related}


@router.get("/detections")
def list_detections(
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    cidr: Optional[str] = None,
    attack_type: Optional[str] = None,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    source_type: Optional[str] = None,
    q: Optional[str] = None,
    time_from: Optional[str] = None,
    time_to: Optional[str] = None,
    limit: int = 200,
    offset: int = 0,
):
    with db_session() as conn:
        rows = fetch_joined(conn, attack_type=attack_type, status=status, severity=severity)
    filtered = apply_event_filters(
        rows, src_ip=src_ip, dst_ip=dst_ip, cidr=cidr, q=q, time_from=time_from, time_to=time_to, source_type=source_type
    )
    return {"total": len(filtered), "detections": filtered[offset : offset + limit]}


@router.get("/stats/overview")
def stats_overview():
    with db_session() as conn:
        ev_n = conn.execute("SELECT COUNT(*) AS c FROM normalized_events").fetchone()["c"]
        det_n = conn.execute("SELECT COUNT(*) AS c FROM detections").fetchone()["c"]
        confirmed = conn.execute("SELECT COUNT(*) AS c FROM detections WHERE status='CONFIRMED'").fetchone()["c"]
        attempt = conn.execute("SELECT COUNT(*) AS c FROM detections WHERE status='ATTEMPT'").fetchone()["c"]
        unknown = conn.execute("SELECT COUNT(*) AS c FROM detections WHERE status='UNKNOWN'").fetchone()["c"]
        srcs = conn.execute("SELECT COUNT(DISTINCT src_ip) AS c FROM normalized_events").fetchone()["c"]
        by_type = [dict(r) for r in conn.execute("SELECT attack_type, COUNT(*) AS c FROM detections GROUP BY attack_type ORDER BY c DESC")]
        by_sev = [dict(r) for r in conn.execute("SELECT severity, COUNT(*) AS c FROM detections GROUP BY severity")]
        by_status = [
            {"status": "ATTEMPT", "c": attempt},
            {"status": "CONFIRMED", "c": confirmed},
            {"status": "UNKNOWN", "c": unknown},
        ]
        recent = fetch_joined(conn)[:20]
    return {
        "events": ev_n,
        "detections": det_n,
        "confirmed": confirmed,
        "attempt": attempt,
        "unknown": unknown,
        "unique_src_ips": srcs,
        "by_type": by_type,
        "by_severity": by_sev,
        "by_status": by_status,
        "recent": recent,
    }


@router.get("/stats/timeline")
def stats_timeline(bucket: str = "hour"):
    with db_session() as conn:
        rows = conn.execute(
            """
            SELECT substr(e.timestamp, 1, 13) AS bucket, d.status, COUNT(*) AS c
            FROM detections d JOIN normalized_events e ON e.id=d.event_id
            GROUP BY bucket, d.status
            ORDER BY bucket
            """
        ).fetchall()
    return {"points": [dict(r) for r in rows]}


@router.get("/stats/by-ip")
def stats_by_ip(limit: int = 15):
    with db_session() as conn:
        src = [
            dict(r)
            for r in conn.execute(
                """
                SELECT e.src_ip AS ip, COUNT(d.id) AS detections,
                       SUM(CASE WHEN d.status='CONFIRMED' THEN 1 ELSE 0 END) AS confirmed
                FROM detections d JOIN normalized_events e ON e.id=d.event_id
                GROUP BY e.src_ip ORDER BY detections DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        ]
        dst = [
            dict(r)
            for r in conn.execute(
                """
                SELECT e.dst_ip AS ip, COUNT(d.id) AS detections
                FROM detections d JOIN normalized_events e ON e.id=d.event_id
                GROUP BY e.dst_ip ORDER BY detections DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        ]
        edges = [
            dict(r)
            for r in conn.execute(
                """
                SELECT e.src_ip, e.dst_ip, COUNT(*) AS c
                FROM detections d JOIN normalized_events e ON e.id=d.event_id
                GROUP BY e.src_ip, e.dst_ip ORDER BY c DESC LIMIT 25
                """
            ).fetchall()
        ]
    return {"sources": src, "destinations": dst, "edges": edges}


@router.get("/investigate/ip")
def investigate_ip(ip: str = Query(..., description="IPv4 or CIDR")):
    from app.api.filters import parse_cidr, ip_matches

    net = parse_cidr(ip)
    if net is None:
        raise HTTPException(400, "Invalid IP or CIDR")
    with db_session() as conn:
        events = [row_to_dict(r) for r in conn.execute("SELECT * FROM normalized_events ORDER BY timestamp").fetchall()]
        events = [e for e in events if ip_matches(e.get("src_ip"), net) or ip_matches(e.get("dst_ip"), net)]
        dets = fetch_joined(conn)
        dets = [d for d in dets if ip_matches(d.get("src_ip"), net) or ip_matches(d.get("dst_ip"), net)]
    as_src = sum(1 for e in events if ip_matches(e.get("src_ip"), net))
    as_dst = sum(1 for e in events if ip_matches(e.get("dst_ip"), net))
    type_counts: dict[str, int] = {}
    status_counts: dict[str, int] = {}
    neighbors: dict[str, int] = {}
    for d in dets:
        type_counts[d.get("attack_type") or ""] = type_counts.get(d.get("attack_type") or "", 0) + 1
        status_counts[d.get("status") or ""] = status_counts.get(d.get("status") or "", 0) + 1
        other = d.get("dst_ip") if ip_matches(d.get("src_ip"), net) else d.get("src_ip")
        if other:
            neighbors[other] = neighbors.get(other, 0) + 1
    high = sorted(dets, key=lambda x: x.get("risk_score") or 0, reverse=True)[:8]
    return {
        "query": ip,
        "as_src": as_src,
        "as_dst": as_dst,
        "event_count": len(events),
        "detection_count": len(dets),
        "by_type": [{"attack_type": k, "c": v} for k, v in sorted(type_counts.items(), key=lambda x: -x[1])],
        "by_status": [{"status": k, "c": v} for k, v in status_counts.items()],
        "neighbors": [{"ip": k, "c": v} for k, v in sorted(neighbors.items(), key=lambda x: -x[1])[:15]],
        "sample": high,
        "timeline": [
            {"timestamp": e.get("timestamp"), "src_ip": e.get("src_ip"), "path": e.get("path"), "http_status": e.get("http_status")}
            for e in events[-80:]
        ],
    }


@router.get("/export")
def export_data(
    format: str = "json",
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    cidr: Optional[str] = None,
    attack_type: Optional[str] = None,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    q: Optional[str] = None,
    time_from: Optional[str] = None,
    time_to: Optional[str] = None,
):
    with db_session() as conn:
        rows = fetch_joined(conn, attack_type=attack_type, status=status, severity=severity)
    filtered = apply_event_filters(rows, src_ip=src_ip, dst_ip=dst_ip, cidr=cidr, q=q, time_from=time_from, time_to=time_to)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    # flatten evidence
    export_rows = []
    for r in filtered:
        item = {k: v for k, v in r.items() if k not in ("features_json", "features")}
        evd = item.get("evidence")
        if not isinstance(evd, str):
            item["evidence"] = json.dumps(evd or [])
        export_rows.append(item)
    if format == "csv":
        buf = StringIO()
        pd.DataFrame(export_rows).to_csv(buf, index=False)
        return Response(
            content=buf.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=sentinelip_export_{stamp}.csv"},
        )
    return JSONResponse(
        content=export_rows,
        headers={"Content-Disposition": f"attachment; filename=sentinelip_export_{stamp}.json"},
    )

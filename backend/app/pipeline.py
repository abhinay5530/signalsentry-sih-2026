"""Persist a batch of normalized events through the detection pipeline."""

from __future__ import annotations

from typing import Any

from app.db import insert_batch, insert_detection, insert_event, refresh_ip_summaries, update_batch_count
from app.detection.engine import run_pipeline


def ingest_events(conn, events: list[dict[str, Any]], source_type: str, filename: str, note: str = "") -> dict[str, Any]:
    batch_id = insert_batch(conn, source_type, filename, note)
    dets = run_pipeline(events)
    n_det = 0
    for ev, hits in zip(events, dets):
        ev["batch_id"] = batch_id
        ev["source_type"] = source_type
        eid = insert_event(conn, ev)
        for h in hits:
            insert_detection(conn, eid, h)
            n_det += 1
    update_batch_count(conn, batch_id, len(events))
    refresh_ip_summaries(conn)
    return {
        "batch_id": batch_id,
        "events": len(events),
        "detections": n_det,
        "source_type": source_type,
        "filename": filename,
    }

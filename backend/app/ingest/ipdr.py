"""IPDR CSV/JSON ingest with column aliases."""

from __future__ import annotations

import json
from io import BytesIO, StringIO
from typing import Any

import pandas as pd

from app.ingest.normalize import normalize_row


def parse_ipdr_bytes(data: bytes, filename: str) -> list[dict[str, Any]]:
    name = (filename or "").lower()
    if name.endswith(".json"):
        payload = json.loads(data.decode("utf-8", errors="replace"))
        if isinstance(payload, dict):
            payload = payload.get("events") or payload.get("records") or payload.get("data") or [payload]
        rows = list(payload)
    else:
        # CSV
        text = data.decode("utf-8", errors="replace")
        df = pd.read_csv(StringIO(text))
        rows = df.where(pd.notnull(df), None).to_dict(orient="records")
    return [normalize_row(r, source_type="ipdr") for r in rows]

"""Vercel build: persist the existing seed-42 synthetic demo as a SQLite file.

Runtime copies this into /tmp because Vercel function storage is not persistent.
Does not change detection code; reuses ingest_synthetic / generate_events.
"""

from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent
os.environ["SENTINEL_DB_PATH"] = str(ROOT / "data" / "vercel_demo.db")

from app.api.routes import ingest_synthetic  # noqa: E402
from app.config import DB_PATH, ML_MODEL_PATH  # noqa: E402
from app.db import get_conn, init_db  # noqa: E402

if not ML_MODEL_PATH.exists():
    from app.ml.train import main as train_ml

    train_ml()

init_db()
ingest_synthetic(n=10000, seed=42)

conn = get_conn()
try:
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    conn.execute("PRAGMA journal_mode=DELETE")
    conn.commit()
finally:
    conn.close()

print(f"baked demo sqlite {DB_PATH} ({DB_PATH.stat().st_size} bytes)")

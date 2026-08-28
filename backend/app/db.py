import json
import sqlite3
from contextlib import contextmanager
from typing import Any, Iterator, Optional

from app.config import DB_PATH

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS ingest_batches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    source_type TEXT NOT NULL,
    filename TEXT,
    row_count INTEGER DEFAULT 0,
    note TEXT
);

CREATE TABLE IF NOT EXISTS normalized_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id INTEGER NOT NULL,
    source_type TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT,
    http_method TEXT,
    host TEXT,
    path TEXT,
    query TEXT,
    url TEXT,
    http_status INTEGER,
    response_size INTEGER,
    user_agent TEXT,
    dns_qname TEXT,
    tls_sni TEXT,
    http_complete INTEGER DEFAULT 0,
    url_availability TEXT,
    request_freq_src_1m INTEGER,
    features_json TEXT,
    body TEXT,
    filename TEXT,
    scenario_id TEXT,
    FOREIGN KEY (batch_id) REFERENCES ingest_batches(id)
);

CREATE TABLE IF NOT EXISTS detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL,
    attack_type TEXT NOT NULL,
    status TEXT NOT NULL,
    severity TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    detectors TEXT,
    evidence_json TEXT,
    ml_score REAL,
    FOREIGN KEY (event_id) REFERENCES normalized_events(id)
);

CREATE TABLE IF NOT EXISTS ip_summaries (
    ip TEXT PRIMARY KEY,
    as_src INTEGER DEFAULT 0,
    as_dst INTEGER DEFAULT 0,
    detection_count INTEGER DEFAULT 0,
    confirmed_count INTEGER DEFAULT 0,
    top_attack_type TEXT,
    last_seen TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_ts ON normalized_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_src ON normalized_events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_dst ON normalized_events(dst_ip);
CREATE INDEX IF NOT EXISTS idx_events_src_ts ON normalized_events(src_ip, timestamp);
CREATE INDEX IF NOT EXISTS idx_det_type ON detections(attack_type);
CREATE INDEX IF NOT EXISTS idx_det_status ON detections(status);
CREATE INDEX IF NOT EXISTS idx_det_event ON detections(event_id);
"""


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = get_conn()
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()


@contextmanager
def db_session() -> Iterator[sqlite3.Connection]:
    conn = get_conn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    d = dict(row)
    if d.get("evidence_json"):
        try:
            d["evidence"] = json.loads(d["evidence_json"])
        except json.JSONDecodeError:
            d["evidence"] = []
    if d.get("features_json"):
        try:
            d["features"] = json.loads(d["features_json"])
        except json.JSONDecodeError:
            d["features"] = {}
    return d


def ip_in_cidr_sql(column: str, cidr: str) -> tuple[str, list[Any]]:
    """SQLite has no native CIDR; filter in Python. Placeholder unused."""
    return "1=1", []


EVENT_INSERT_COLS = [
    "batch_id", "source_type", "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
    "protocol", "http_method", "host", "path", "query", "url", "http_status",
    "response_size", "user_agent", "dns_qname", "tls_sni", "http_complete",
    "url_availability", "request_freq_src_1m", "features_json", "body", "filename",
    "scenario_id",
]


def insert_batch(conn: sqlite3.Connection, source_type: str, filename: str, note: str = "") -> int:
    from datetime import datetime, timezone

    cur = conn.execute(
        "INSERT INTO ingest_batches (created_at, source_type, filename, row_count, note) VALUES (?,?,?,0,?)",
        (datetime.now(timezone.utc).isoformat(), source_type, filename, note),
    )
    return int(cur.lastrowid)


def update_batch_count(conn: sqlite3.Connection, batch_id: int, n: int) -> None:
    conn.execute("UPDATE ingest_batches SET row_count=? WHERE id=?", (n, batch_id))


def insert_event(conn: sqlite3.Connection, ev: dict[str, Any]) -> int:
    cols = EVENT_INSERT_COLS
    placeholders = ",".join("?" * len(cols))
    values = [ev.get(c) for c in cols]
    cur = conn.execute(
        f"INSERT INTO normalized_events ({','.join(cols)}) VALUES ({placeholders})",
        values,
    )
    return int(cur.lastrowid)


def insert_detection(conn: sqlite3.Connection, event_id: int, det: dict[str, Any]) -> int:
    evidence = det.get("evidence") or []
    if not isinstance(evidence, str):
        evidence = json.dumps(evidence)
    cur = conn.execute(
        """INSERT INTO detections
           (event_id, attack_type, status, severity, risk_score, detectors, evidence_json, ml_score)
           VALUES (?,?,?,?,?,?,?,?)""",
        (
            event_id,
            det["attack_type"],
            det.get("status", "ATTEMPT"),
            det.get("severity", "medium"),
            det.get("risk_score", 40),
            det.get("detectors", "rule"),
            evidence,
            det.get("ml_score"),
        ),
    )
    return int(cur.lastrowid)


def refresh_ip_summaries(conn: sqlite3.Connection) -> None:
    conn.execute("DELETE FROM ip_summaries")
    conn.execute(
        """
        INSERT INTO ip_summaries (ip, as_src, as_dst, detection_count, confirmed_count, top_attack_type, last_seen)
        SELECT src_ip,
               COUNT(*) AS as_src,
               0,
               0, 0, NULL,
               MAX(timestamp)
        FROM normalized_events
        WHERE src_ip IS NOT NULL AND src_ip != ''
        GROUP BY src_ip
        """
    )
    # Patch detection counts
    rows = conn.execute(
        """
        SELECT e.src_ip AS ip, COUNT(d.id) AS dc,
               SUM(CASE WHEN d.status='CONFIRMED' THEN 1 ELSE 0 END) AS cc
        FROM detections d
        JOIN normalized_events e ON e.id = d.event_id
        GROUP BY e.src_ip
        """
    ).fetchall()
    for r in rows:
        conn.execute(
            "UPDATE ip_summaries SET detection_count=?, confirmed_count=? WHERE ip=?",
            (r["dc"], r["cc"] or 0, r["ip"]),
        )
    tops = conn.execute(
        """
        SELECT e.src_ip AS ip, d.attack_type, COUNT(*) AS c
        FROM detections d
        JOIN normalized_events e ON e.id = d.event_id
        GROUP BY e.src_ip, d.attack_type
        ORDER BY c DESC
        """
    ).fetchall()
    seen = set()
    for r in tops:
        if r["ip"] in seen:
            continue
        seen.add(r["ip"])
        conn.execute("UPDATE ip_summaries SET top_attack_type=? WHERE ip=?", (r["attack_type"], r["ip"]))

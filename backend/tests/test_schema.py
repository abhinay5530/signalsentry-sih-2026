from app.db import init_db, get_conn


def test_schema_creates():
    init_db()
    conn = get_conn()
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    conn.close()
    assert "normalized_events" in tables
    assert "detections" in tables
    assert "ingest_batches" in tables

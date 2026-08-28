import pytest

from app.db import init_db
from app import config


@pytest.fixture
def tmp_db(tmp_path, monkeypatch):
    db = tmp_path / "t.db"
    monkeypatch.setattr(config, "DB_PATH", db)
    from app import db as dbmod

    monkeypatch.setattr(dbmod, "DB_PATH", db)
    init_db()
    yield db

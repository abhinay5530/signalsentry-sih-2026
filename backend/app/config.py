import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# Baked at Vercel build (see bake_demo_db.py). Not used for local uvicorn.
DEMO_SQLITE = BASE_DIR / "data" / "vercel_demo.db"

_db_override = os.environ.get("SENTINEL_DB_PATH")
# Vercel functions can write only to /tmp; do not use the packaged backend/data path.
if _db_override:
    DATA_DIR = Path(_db_override).parent
    DB_PATH = Path(_db_override)
elif os.environ.get("VERCEL"):
    DATA_DIR = Path("/tmp/signalsentry")
    DB_PATH = DATA_DIR / "sentinelip.db"
else:
    DATA_DIR = BASE_DIR / "data"
    DB_PATH = DATA_DIR / "sentinelip.db"

DATA_DIR.mkdir(parents=True, exist_ok=True)

# Repo-root frontend build (production). Unused when running Vite locally.
FRONTEND_DIST = BASE_DIR.parent / "frontend" / "dist"
ML_MODEL_PATH = BASE_DIR / "app" / "ml" / "model.joblib"
SAMPLE_DIR = DATA_DIR

MAX_UPLOAD_BYTES = 50 * 1024 * 1024
MAX_URL_LEN = 4096
MAX_DECODE_ROUNDS = 2
MAX_PCAP_PACKETS = 50_000

# Bind locally only (see uvicorn command in README).
CORS_ORIGINS = [
    "http://127.0.0.1:5173",
    "http://localhost:5173",
    "https://signalsentry-sih-2026.vercel.app",
    "https://signalsentry-frontend.onrender.com",
]

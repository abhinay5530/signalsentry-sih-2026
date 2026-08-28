from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = DATA_DIR / "sentinelip.db"
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
]

"""Train Random Forest on synthetic labeled events. Demo only — not real-world accuracy."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from app.config import ML_MODEL_PATH  # noqa: E402
from app.features.url_features import extract_features  # noqa: E402
from app.ingest.normalize import normalize_row  # noqa: E402
from app.ml.classifier import FEATURE_KEYS, vectorize  # noqa: E402
from datasets.generate import generate_events  # noqa: E402


def main() -> None:
    import joblib
    from sklearn.ensemble import RandomForestClassifier

    raw = generate_events(4000, seed=42)
    X, y = [], []
    for r in raw:
        ev = normalize_row(r, source_type="synthetic")
        feats = extract_features(ev)
        X.append(vectorize(feats))
        y.append(0 if (r.get("scenario_id") or "").startswith("benign") or r.get("scenario_id") == "https_sni_only" else 1)
    clf = RandomForestClassifier(n_estimators=80, max_depth=12, random_state=42, n_jobs=-1)
    clf.fit(X, y)
    ML_MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": clf, "feature_keys": FEATURE_KEYS}, ML_MODEL_PATH)
    # store raw clf for classifier.py
    joblib.dump(clf, ML_MODEL_PATH)
    acc = clf.score(X, y)
    print(f"Saved {ML_MODEL_PATH} train_acc={acc:.3f} (synthetic only; do not report as real-world accuracy)")


if __name__ == "__main__":
    main()

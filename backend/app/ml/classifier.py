"""Lightweight Random Forest complement. Trained only on synthetic labels. Optional."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from app.config import ML_MODEL_PATH

FEATURE_KEYS = [
    "url_len",
    "host_len",
    "path_len",
    "query_len",
    "path_depth",
    "param_count",
    "digit_ratio",
    "special_char_count",
    "entropy_path",
    "entropy_query",
    "dot_count_host",
    "is_ip_host",
    "pct_encoded_count",
    "double_encoded",
    "null_byte_enc",
    "has_sql_token",
    "has_xss_token",
    "has_traversal",
    "has_cmd_token",
    "has_ssrf_token",
    "has_lfi_token",
    "has_xxe_token",
    "has_hpp_dup_params",
    "has_upload_ext",
    "src_req_1m",
]

_model = None
_tried = False


def vectorize(feats: dict[str, Any]) -> list[float]:
    return [float(feats.get(k) or 0) for k in FEATURE_KEYS]


def _load():
    global _model, _tried
    if _tried:
        return _model
    _tried = True
    path = Path(ML_MODEL_PATH)
    if not path.exists():
        _model = None
        return None
    import joblib

    _model = joblib.load(path)
    return _model


def score_batch(feats_list: list[dict[str, Any]]) -> list[Optional[float]]:
    clf = _load()
    if clf is None or not feats_list:
        return [None] * len(feats_list)
    import numpy as np

    x = np.array([vectorize(f) for f in feats_list])
    proba = clf.predict_proba(x)
    classes = list(clf.classes_)
    idx = classes.index(1) if 1 in classes else -1
    return [float(row[idx]) for row in proba]


def score_features(feats: dict[str, Any]) -> Optional[float]:
    return score_batch([feats])[0]

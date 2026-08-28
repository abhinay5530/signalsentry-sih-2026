"""Orchestrate features → rules → behavior → ML (optional) → correlation."""

from __future__ import annotations

import json
from typing import Any, Optional

from app.detection.behavioral import annotate_frequencies, behavioral_hits
from app.detection.correlator import correlate
from app.detection.rules import (
    bruteforce,
    command,
    hpp,
    lfi_rfi,
    sqli,
    ssrf,
    traversal,
    typosquat,
    webshell,
    xss,
    xxe,
)
from app.features.url_features import extract_features

RULE_MODULES = [
    typosquat,
    sqli,
    xss,
    traversal,
    command,
    ssrf,
    lfi_rfi,
    bruteforce,
    hpp,
    xxe,
    webshell,
]


def _url_rules_applicable(event: dict[str, Any]) -> bool:
    avail = event.get("url_availability")
    if avail == "tls_sni_only":
        return False
    return bool(event.get("http_complete") or event.get("path") or event.get("url") or event.get("query"))


def run_rules(event: dict[str, Any]) -> list[dict]:
    hits = []
    # Typosquat can fire on SNI/host even without a path
    t = typosquat.detect(event)
    if t:
        hits.append(t)
    if _url_rules_applicable(event):
        for mod in RULE_MODULES:
            if mod is typosquat:
                continue
            h = mod.detect(event)
            if h:
                hits.append(h)
    return hits


def attach_ml(event: dict, feats: dict, existing: list[dict], p: Optional[float] = None) -> Optional[float]:
    if p is None:
        try:
            from app.ml.classifier import score_features
        except Exception:
            return None
        p = score_features(feats)
    if p is None:
        return None
    for d in existing:
        d["ml_score"] = p
        d["detectors"] = (d.get("detectors") or "rule") + ",ml"
        d.setdefault("evidence", []).append(
            {
                "code": "ml_support",
                "detail": f"Synthetic-trained Random Forest p(malicious)={p:.2f} (not real-world accuracy)",
                "snippet": str(round(p, 3)),
            }
        )
    if p >= 0.7 and not existing:
        existing.append(
            {
                "attack_type": "ANOMALOUS_URL",
                "status": "ATTEMPT",
                "severity": "low",
                "risk_score": int(40 + 40 * p),
                "detectors": "ml",
                "evidence": [
                    {
                        "code": "ml_anomaly",
                        "detail": "No signature hit; structural features look unusual vs synthetic training distribution",
                        "snippet": f"p={p:.2f}",
                    }
                ],
                "ml_score": p,
            }
        )
    return p


def run_pipeline(events: list[dict[str, Any]]) -> list[list[dict]]:
    """Mutates events (features_json, freq). Returns detections list per event index."""
    annotate_frequencies(events)
    detections_by_idx: list[list[dict]] = []
    feats_list: list[dict] = []
    for ev in events:
        feats = extract_features(ev)
        feats["src_req_1m"] = ev.get("request_freq_src_1m") or 0
        ev["features_json"] = json.dumps(feats)
        feats_list.append(feats)
        detections_by_idx.append(run_rules(ev))

    try:
        from app.ml.classifier import score_batch

        scores = score_batch(feats_list)
    except Exception:
        scores = [None] * len(events)
    for ev, feats, hits, p in zip(events, feats_list, detections_by_idx, scores):
        attach_ml(ev, feats, hits, p)

    extra = behavioral_hits(events)
    for idx, det in extra:
        # avoid exact duplicate brute-force rows
        types = {d["attack_type"] for d in detections_by_idx[idx]}
        if det["attack_type"] in types and det.get("detectors") == "behavior":
            for d in detections_by_idx[idx]:
                if d["attack_type"] == det["attack_type"]:
                    d["detectors"] = (d.get("detectors") or "rule") + ",behavior"
                    d["evidence"] = (d.get("evidence") or []) + det.get("evidence", [])
                    break
        else:
            detections_by_idx[idx].append(det)

    correlate(events, detections_by_idx)
    return detections_by_idx

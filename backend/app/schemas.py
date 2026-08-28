from typing import Any, Optional

from pydantic import BaseModel, Field


class NormalizedEvent(BaseModel):
    id: Optional[int] = None
    batch_id: Optional[int] = None
    source_type: str = "ipdr"
    timestamp: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = "TCP"
    http_method: Optional[str] = None
    host: Optional[str] = None
    path: Optional[str] = None
    query: Optional[str] = None
    url: Optional[str] = None
    http_status: Optional[int] = None
    response_size: Optional[int] = None
    user_agent: Optional[str] = None
    dns_qname: Optional[str] = None
    tls_sni: Optional[str] = None
    http_complete: int = 0
    url_availability: str = "metadata_only"
    request_freq_src_1m: Optional[int] = None
    features_json: Optional[str] = None
    body: Optional[str] = None
    filename: Optional[str] = None
    scenario_id: Optional[str] = None


class EvidenceItem(BaseModel):
    code: str
    detail: str
    snippet: Optional[str] = None


class DetectionHit(BaseModel):
    attack_type: str
    status: str = "ATTEMPT"
    severity: str = "medium"
    risk_score: int = 40
    detectors: str = "rule"
    evidence: list[EvidenceItem] = Field(default_factory=list)
    ml_score: Optional[float] = None


class EventIn(BaseModel):
    event: dict[str, Any]
    detections: list[dict[str, Any]] = Field(default_factory=list)
    related: list[dict[str, Any]] = Field(default_factory=list)

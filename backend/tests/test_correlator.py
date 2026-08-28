from app.detection.engine import run_pipeline

SQLI_Q = "id=1 UNION SELECT password FROM users"
SQLI_URL = "http://portal.gov.in/item?" + SQLI_Q


def _ev(**kwargs):
    base = {
        "timestamp": "2026-08-25T10:00:00",
        "src_ip": "10.50.1.5",
        "dst_ip": "10.20.0.10",
        "http_method": "GET",
        "host": "portal.gov.in",
        "path": "/item",
        "query": SQLI_Q,
        "url": SQLI_URL,
        "http_status": 403,
        "response_size": 200,
        "http_complete": 1,
        "url_availability": "full_http",
    }
    base.update(kwargs)
    return base


def _status(dets, attack="SQL Injection"):
    hits = [d for d in dets if d["attack_type"] == attack]
    assert hits, f"expected {attack} detection, got {[d['attack_type'] for d in dets]}"
    return hits[0]["status"]


def test_url_only_is_not_confirmed():
    dets = run_pipeline([_ev(http_status=403)])
    assert _status(dets[0]) == "ATTEMPT"


def test_malicious_url_arbitrary_2xx_is_attempt():
    dets = run_pipeline([_ev(http_status=200, response_size=9000)])
    assert _status(dets[0]) == "ATTEMPT"


def test_malicious_url_size_band_alone_is_attempt():
    """LFI 2xx + sensitive-looking size must not confirm without a same-type sequence."""
    events = [
        _ev(
            path="/view",
            query="include=../../../../etc/passwd",
            url="http://portal.gov.in/view?include=../../../../etc/passwd",
            http_status=200,
            response_size=4200,
        )
    ]
    dets = run_pipeline(events)
    assert _status(dets[0], "Local File Inclusion / Remote File Inclusion (LFI/RFI)") == "ATTEMPT"


def test_malicious_url_unrelated_500_is_attempt():
    events = [
        _ev(
            timestamp="2026-08-25T10:00:00",
            path="/health",
            query="",
            url="http://portal.gov.in/health",
            http_status=500,
            response_size=400,
        ),
        _ev(timestamp="2026-08-25T10:00:20", http_status=200, response_size=9000),
    ]
    dets = run_pipeline(events)
    assert _status(dets[1]) == "ATTEMPT"


def test_fail_then_success_confirmed():
    events = [
        _ev(timestamp="2026-08-25T10:00:00", http_status=500, response_size=400),
        _ev(timestamp="2026-08-25T10:00:20", http_status=200, response_size=9000),
    ]
    dets = run_pipeline(events)
    assert _status(dets[1]) == "CONFIRMED"
    codes = {e["code"] for e in dets[1][0]["evidence"]}
    assert "not_url_only" in codes
    assert "fail_then_success" in codes or "error_then_data" in codes


def test_same_type_403_then_200_same_path_confirmed():
    events = [
        _ev(timestamp="2026-08-25T10:00:00", http_status=403, response_size=120),
        _ev(timestamp="2026-08-25T10:00:15", http_status=200, response_size=800),
    ]
    dets = run_pipeline(events)
    assert _status(dets[1]) == "CONFIRMED"


def test_incomplete_http_is_unknown_when_detected():
    events = [
        {
            "timestamp": "2026-08-25T10:00:00",
            "src_ip": "10.50.1.5",
            "dst_ip": "10.20.0.10",
            "http_method": "GET",
            "host": "portal.gov.in",
            "path": "/item",
            "query": SQLI_Q,
            "url": SQLI_URL,
            "http_status": None,
            "response_size": None,
            "http_complete": 0,
            "url_availability": "metadata_only",
        }
    ]
    dets = run_pipeline(events)
    sqli = [d for d in dets[0] if d["attack_type"] == "SQL Injection"]
    assert sqli
    assert sqli[0]["status"] == "UNKNOWN"


def test_tls_sni_does_not_invent_path_or_confirm_payload():
    events = [
        {
            "timestamp": "2026-08-25T10:00:00",
            "src_ip": "10.10.1.1",
            "dst_ip": "10.20.0.10",
            "tls_sni": "portal.gov.in",
            "host": "portal.gov.in",
            "path": None,
            "url": None,
            "query": None,
            "http_complete": 0,
            "url_availability": "tls_sni_only",
            "dst_port": 443,
            "protocol": "TCP",
        }
    ]
    dets = run_pipeline(events)
    assert events[0]["path"] is None
    types = {d["attack_type"] for d in dets[0]}
    assert "SQL Injection" not in types

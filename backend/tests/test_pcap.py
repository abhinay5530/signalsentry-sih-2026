from app.api.filters import ip_matches, parse_cidr
from app.ingest.pcap import _parse_http_request, parse_pcap_bytes

ETH = dict(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff")


def _http_pkt(src, dst, sport, dport, payload, seq=1):
    from scapy.all import IP, TCP, Ether, Raw

    return (
        Ether(**ETH)
        / IP(src=src, dst=dst)
        / TCP(sport=sport, dport=dport, flags="PA", seq=seq)
        / Raw(load=payload)
    )


def test_cidr_filter():
    net = parse_cidr("10.50.1.0/24")
    assert ip_matches("10.50.1.9", net)
    assert not ip_matches("10.10.1.9", net)
    assert parse_cidr("not-an-ip") is None


def test_http_request_parse():
    raw = b"GET /item?id=1 HTTP/1.1\r\nHost: portal.gov.in\r\nUser-Agent: t\r\n\r\n"
    p = _parse_http_request(raw)
    assert p["http_method"] == "GET"
    assert p["host"] == "portal.gov.in"
    assert p["path"] == "/item"
    assert p["query"] == "id=1"
    assert p["http_complete"] == 1


def test_pcap_http_and_no_fetch(tmp_path):
    from scapy.all import wrpcap

    http = b"GET /download?file=../../../../etc/passwd HTTP/1.1\r\nHost: intranet.bank.local\r\n\r\n"
    pkt = _http_pkt("10.50.1.10", "10.20.0.11", 40000, 80, http)
    path = tmp_path / "t.pcap"
    wrpcap(str(path), [pkt])
    events = parse_pcap_bytes(path.read_bytes(), "t.pcap")
    assert events
    assert events[0]["src_ip"] == "10.50.1.10"
    assert "etc/passwd" in (events[0].get("query") or "")
    assert events[0]["url_availability"] == "full_http"


def test_https_no_path_honesty(tmp_path):
    from scapy.all import wrpcap

    payload = b"\x16\x03\x01\x00\x10" + b"\x00" * 20
    pkt = _http_pkt("10.10.1.1", "10.20.0.10", 4444, 443, payload)
    path = tmp_path / "tls.pcap"
    wrpcap(str(path), [pkt])
    events = parse_pcap_bytes(path.read_bytes(), "tls.pcap")
    for e in events:
        assert e.get("path") in (None, "")
        assert e.get("url_availability") in ("tls_sni_only", "metadata_only")


def test_pcapng_http_ingest(tmp_path):
    from scapy.utils import wrpcapng

    http = b"GET /search?q=<script>alert(1)</script> HTTP/1.1\r\nHost: portal.gov.in\r\n\r\n"
    pkt = _http_pkt("10.50.1.2", "10.20.0.10", 41000, 80, http)
    path = tmp_path / "t.pcapng"
    wrpcapng(str(path), [pkt])
    events = parse_pcap_bytes(path.read_bytes(), "t.pcapng")
    assert events
    assert events[0]["path"] == "/search"
    assert "script" in (events[0].get("query") or "")


def test_split_tcp_http_reassembly(tmp_path):
    from scapy.all import wrpcap

    a = b"GET /q?id=1%27%20OR%20%271%27%3D%271 HTTP/1.1\r\nHo"
    b = b"st: portal.gov.in\r\n\r\n"
    pkts = [
        _http_pkt("10.50.1.3", "10.20.0.10", 42000, 80, a, seq=1000),
        _http_pkt("10.50.1.3", "10.20.0.10", 42000, 80, b, seq=1000 + len(a)),
    ]
    path = tmp_path / "split.pcap"
    wrpcap(str(path), pkts)
    events = parse_pcap_bytes(path.read_bytes(), "split.pcap")
    assert len(events) == 1
    assert events[0]["path"] == "/q"
    assert "OR" in (events[0].get("query") or "").upper() or "or" in (events[0].get("query") or "")


def test_post_body_extracted(tmp_path):
    from scapy.all import wrpcap

    body = b'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    req = (
        b"POST /xml HTTP/1.1\r\nHost: portal.gov.in\r\nContent-Length: "
        + str(len(body)).encode()
        + b"\r\n\r\n"
        + body
    )
    path = tmp_path / "xxe.pcap"
    wrpcap(str(path), [_http_pkt("10.50.1.4", "10.20.0.10", 43000, 80, req)])
    events = parse_pcap_bytes(path.read_bytes(), "xxe.pcap")
    assert events
    assert "ENTITY" in (events[0].get("body") or "")


def test_http_status_attached_and_confirmed(tmp_path):
    from scapy.all import wrpcap
    from app.detection.engine import run_pipeline

    uri = b"GET /download?file=../../../../etc/passwd HTTP/1.1\r\nHost: intranet.bank.local\r\n\r\n"
    r403 = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 5\r\n\r\ndeny\n"
    r200 = b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nroot:x:0:0:\n"
    pkts = [
        _http_pkt("10.50.1.10", "10.20.0.11", 40000, 80, uri, seq=1),
        _http_pkt("10.20.0.11", "10.50.1.10", 80, 40000, r403, seq=1),
        _http_pkt("10.50.1.10", "10.20.0.11", 40001, 80, uri, seq=1),
        _http_pkt("10.20.0.11", "10.50.1.10", 80, 40001, r200, seq=1),
    ]
    for i, p in enumerate(pkts):
        p.time = 1_700_000_000 + i
    path = tmp_path / "seq.pcap"
    wrpcap(str(path), pkts)
    events = parse_pcap_bytes(path.read_bytes(), "seq.pcap")
    assert len(events) == 2
    assert {e.get("http_status") for e in events} == {403, 200}
    dets = run_pipeline(events)
    statuses = {d["status"] for hits in dets for d in hits}
    assert "CONFIRMED" in statuses
    types = {d["attack_type"] for hits in dets for d in hits if d["status"] == "CONFIRMED"}
    assert "Directory Traversal" in types or "Local File Inclusion / Remote File Inclusion (LFI/RFI)" in types

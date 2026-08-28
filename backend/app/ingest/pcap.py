"""PCAP/PCAPNG parsing with Scapy. Never visits URLs or executes payloads.

HTTPS: extract SNI when present; do not fabricate HTTP path/query.
Parser-only reconstruction: bounded TCP concat, HTTP/1 responses, request body.
Does not change detection rules or the correlator.
"""

from __future__ import annotations

import os
import re
import tempfile
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Optional

from app.config import MAX_PCAP_PACKETS, MAX_URL_LEN
from app.ingest.normalize import normalize_row

MAX_STREAM_BYTES = 65536
_HTTP_PORTS = {80, 443, 8000, 8080, 8888}
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
_REQ_START = re.compile(
    rb"^(GET|POST|PUT|DELETE|HEAD|PATCH|OPTIONS|CONNECT) \S+ HTTP/\d",
)
_RESP_START = re.compile(rb"^HTTP/\d\.\d (\d{3})")
_ANY_HTTP = re.compile(
    rb"(?:(?:GET|POST|PUT|DELETE|HEAD|PATCH|OPTIONS|CONNECT) \S+ HTTP/\d|HTTP/\d\.\d \d{3})"
)


def _sni_from_tls(raw: bytes) -> Optional[str]:
    """Best-effort TLS ClientHello SNI parse from TCP payload. No decryption."""
    if len(raw) < 10:
        return None
    if raw[0] != 0x16:
        return None
    try:
        pos = 0
        while True:
            p = raw.find(b"\x00\x00", pos)
            if p < 0 or p + 9 > len(raw):
                break
            ext_len = int.from_bytes(raw[p + 2 : p + 4], "big")
            if 4 < ext_len < 300 and p + 4 + ext_len <= len(raw):
                chunk = raw[p + 4 : p + 4 + ext_len]
                if len(chunk) >= 5 and chunk[2] == 0:
                    nlen = int.from_bytes(chunk[3:5], "big")
                    if 1 <= nlen <= 253 and 5 + nlen <= len(chunk):
                        host = chunk[5 : 5 + nlen].decode("ascii", errors="ignore")
                        if "." in host or host:
                            return host.lower()
            pos = p + 2
    except Exception:
        return None
    return None


def _content_length(header_block: bytes) -> Optional[int]:
    for line in header_block.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            try:
                return max(0, min(MAX_STREAM_BYTES, int(line.split(b":", 1)[1].strip())))
            except (ValueError, IndexError):
                return None
    return None


def _parse_http_request(payload: bytes) -> Optional[dict[str, Any]]:
    try:
        text = payload.decode("iso-8859-1", errors="replace")
    except Exception:
        return None
    if not re.match(r"^(GET|POST|PUT|DELETE|HEAD|PATCH|OPTIONS|CONNECT)\s+", text):
        return None
    first, _, rest = text.partition("\r\n")
    m = re.match(r"^([A-Z]+)\s+(\S+)\s+HTTP/\d", first)
    if not m:
        return None
    method, uri = m.group(1), m.group(2)
    headers = {}
    header_end = rest.find("\r\n\r\n")
    header_part = rest if header_end < 0 else rest[:header_end]
    body = "" if header_end < 0 else rest[header_end + 4 :]
    for line in header_part.split("\r\n"):
        if line == "":
            break
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    host = headers.get("host")
    path, query = uri, None
    if "?" in uri:
        path, query = uri.split("?", 1)
    url = None
    if host:
        url = f"http://{host}{uri if uri.startswith('/') else '/' + uri}"
    body = body[:MAX_URL_LEN] if body else None
    cl = headers.get("content-length")
    if body is not None and cl:
        try:
            body = body[: int(cl)]
        except ValueError:
            pass
    return {
        "http_method": method,
        "host": host,
        "path": path if path.startswith("/") else path,
        "query": query,
        "url": url,
        "user_agent": headers.get("user-agent"),
        "http_complete": 1,
        "url_availability": "full_http",
        "body": body or None,
    }


def _parse_http_response(payload: bytes) -> Optional[dict[str, Any]]:
    if not _RESP_START.match(payload):
        return None
    try:
        text = payload.decode("iso-8859-1", errors="replace")
    except Exception:
        return None
    first, _, rest = text.partition("\r\n")
    m = re.match(r"^HTTP/\d\.\d (\d{3})", first)
    if not m:
        return None
    status = int(m.group(1))
    header_end = rest.find("\r\n\r\n")
    header_part = rest if header_end < 0 else rest[:header_end]
    body = b"" if header_end < 0 else payload.split(b"\r\n\r\n", 1)[1]
    cl = _content_length(header_part.encode("iso-8859-1", errors="replace"))
    size = cl if cl is not None else len(body)
    return {"http_status": status, "response_size": size}


def _open_reader(path: str, data: bytes):
    from scapy.utils import PcapNgReader, PcapReader

    if data[:4] == _PCAPNG_MAGIC:
        return PcapNgReader(path)
    try:
        return PcapReader(path)
    except Exception:
        return PcapNgReader(path)


def _ts_at(spans: list[tuple[int, int, str]], pos: int) -> str:
    if not spans:
        return datetime.utcnow().isoformat()
    for start, end, ts in spans:
        if start <= pos < end:
            return ts
    return spans[-1][2]


def _assemble(chunks: list[tuple[str, int, bytes]]) -> tuple[bytes, list[tuple[int, int, str]]]:
    if not chunks:
        return b"", []
    ordered = sorted(chunks, key=lambda c: (c[1], c[0]))
    out = bytearray()
    spans: list[tuple[int, int, str]] = []
    expect: Optional[int] = None
    for ts, seq, data in ordered:
        if not data:
            continue
        if expect is None:
            expect = seq
        if seq < expect:
            skip = expect - seq
            if skip >= len(data):
                continue
            data = data[skip:]
            seq = expect
        elif seq > expect:
            expect = seq
        start = len(out)
        room = MAX_STREAM_BYTES - len(out)
        if room <= 0:
            break
        take = data[:room]
        out.extend(take)
        spans.append((start, len(out), ts))
        expect = seq + len(data)
        if len(out) >= MAX_STREAM_BYTES:
            break
    return bytes(out), spans


def _iter_http_messages(buf: bytes):
    pos = 0
    n = len(buf)
    while pos < n:
        rest = buf[pos:]
        if not (_REQ_START.match(rest) or _RESP_START.match(rest)):
            m = _ANY_HTTP.search(rest)
            if not m:
                break
            pos += m.start()
            continue
        hdr_end = buf.find(b"\r\n\r\n", pos)
        if hdr_end < 0:
            break
        head = buf[pos:hdr_end]
        body_start = hdr_end + 4
        cl = _content_length(head)
        if cl is None:
            next_pos = body_start
            msg = buf[pos:body_start]
        else:
            next_pos = min(n, body_start + cl)
            msg = buf[pos:next_pos]
        is_req = bool(_REQ_START.match(buf[pos:]))
        yield pos, msg, is_req
        pos = next_pos if next_pos > pos else pos + 1


def _row_event(row: dict[str, Any]) -> dict[str, Any]:
    ev = normalize_row(row, source_type="pcap")
    if row.get("dns_qname") and ev["url_availability"] == "metadata_only":
        ev["dns_qname"] = row["dns_qname"]
        ev["url_availability"] = "dns_only"
        ev["host"] = ev["host"] or str(row["dns_qname"]).lower()
    return ev


def _events_from_tcp_flows(flows: dict) -> list[dict[str, Any]]:
    requests: dict[tuple, list[dict[str, Any]]] = defaultdict(list)
    responses: dict[tuple, list[dict[str, Any]]] = defaultdict(list)
    leftover: list[dict[str, Any]] = []

    for key, meta in flows.items():
        sip, dip, sport, dport = key
        buf, spans = _assemble(meta["chunks"])
        if not buf:
            continue
        if buf.startswith(b"PRI * HTTP/2"):
            leftover.append(
                _row_event(
                    {
                        "timestamp": meta["first_ts"],
                        "src_ip": sip,
                        "dst_ip": dip,
                        "src_port": sport,
                        "dst_port": dport,
                        "protocol": "TCP",
                        "http_complete": 0,
                        "url_availability": "metadata_only",
                    }
                )
            )
            continue

        parsed_any = False
        for pos, msg, is_req in _iter_http_messages(buf):
            parsed_any = True
            ts = _ts_at(spans, pos)
            if is_req:
                parsed = _parse_http_request(msg)
                if not parsed:
                    continue
                conv = (sip, dip, sport, dport)
                requests[conv].append(
                    {
                        "timestamp": ts,
                        "src_ip": sip,
                        "dst_ip": dip,
                        "src_port": sport,
                        "dst_port": dport,
                        "protocol": "TCP",
                        **parsed,
                    }
                )
            else:
                parsed = _parse_http_response(msg)
                if not parsed:
                    continue
                conv = (dip, sip, dport, sport)
                responses[conv].append({"timestamp": ts, **parsed})

        if parsed_any:
            continue
        sni = _sni_from_tls(buf)
        if sni:
            leftover.append(
                _row_event(
                    {
                        "timestamp": meta["first_ts"],
                        "src_ip": sip,
                        "dst_ip": dip,
                        "src_port": sport,
                        "dst_port": dport,
                        "protocol": "TCP",
                        "host": sni,
                        "tls_sni": sni,
                        "http_complete": 0,
                        "url_availability": "tls_sni_only",
                    }
                )
            )
        elif dport in _HTTP_PORTS or sport in _HTTP_PORTS:
            leftover.append(
                _row_event(
                    {
                        "timestamp": meta["first_ts"],
                        "src_ip": sip,
                        "dst_ip": dip,
                        "src_port": sport,
                        "dst_port": dport,
                        "protocol": "TCP",
                        "http_complete": 0,
                        "url_availability": "metadata_only",
                    }
                )
            )

    events: list[dict[str, Any]] = []
    for conv, reqs in requests.items():
        resps = responses.get(conv, [])
        for i, req in enumerate(reqs):
            if i < len(resps):
                req["http_status"] = resps[i].get("http_status")
                req["response_size"] = resps[i].get("response_size")
            events.append(_row_event(req))
    events.extend(leftover)
    events.sort(key=lambda e: e.get("timestamp") or "")
    return events


def parse_pcap_bytes(data: bytes, filename: str = "capture.pcap") -> list[dict[str, Any]]:
    from scapy.all import DNS, IP, IPv6, TCP, UDP  # noqa: F401

    lower = (filename or "").lower()
    suffix = ".pcapng" if data[:4] == _PCAPNG_MAGIC or lower.endswith(".pcapng") else ".pcap"
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp.write(data)
        path = tmp.name

    events: list[dict[str, Any]] = []
    flows: dict[tuple, dict[str, Any]] = {}
    try:
        reader = _open_reader(path, data)
        n = 0
        for pkt in reader:
            n += 1
            if n > MAX_PCAP_PACKETS:
                break
            ts = datetime.fromtimestamp(float(pkt.time), tz=timezone.utc).replace(tzinfo=None).isoformat()
            if IP in pkt:
                src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
            elif IPv6 in pkt:
                src_ip, dst_ip = pkt[IPv6].src, pkt[IPv6].dst
            else:
                continue

            if UDP in pkt:
                src_port, dst_port = int(pkt[UDP].sport), int(pkt[UDP].dport)
                dns_qname = None
                if DNS in pkt and pkt[DNS].qd:
                    try:
                        dns_qname = pkt[DNS].qd.qname.decode(errors="ignore").rstrip(".")
                    except Exception:
                        dns_qname = None
                if not dns_qname:
                    continue
                events.append(
                    _row_event(
                        {
                            "timestamp": ts,
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "src_port": src_port,
                            "dst_port": dst_port,
                            "protocol": "UDP",
                            "dns_qname": dns_qname,
                            "http_complete": 0,
                            "url_availability": "dns_only",
                        }
                    )
                )
                continue

            if TCP not in pkt:
                continue
            src_port, dst_port = int(pkt[TCP].sport), int(pkt[TCP].dport)
            payload = bytes(pkt[TCP].payload) if pkt[TCP].payload else b""
            if not payload:
                continue
            key = (src_ip, dst_ip, src_port, dst_port)
            slot = flows.setdefault(
                key,
                {
                    "first_ts": ts,
                    "chunks": [],
                },
            )
            seq = int(pkt[TCP].seq)
            slot["chunks"].append((ts, seq, payload[:MAX_STREAM_BYTES]))
        reader.close()
        events.extend(_events_from_tcp_flows(flows))
        events.sort(key=lambda e: e.get("timestamp") or "")
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    return events

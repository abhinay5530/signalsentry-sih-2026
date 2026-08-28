from app.detection.rules import command, hpp, lfi_rfi, sqli, ssrf, traversal, typosquat, webshell, xss, xxe
from app.features.url_features import extract_features


def ev(**kwargs):
    base = {
        "timestamp": "2026-08-25T10:00:00",
        "src_ip": "10.50.1.5",
        "dst_ip": "10.20.0.10",
        "http_method": "GET",
        "host": "portal.gov.in",
        "path": "/",
        "query": "",
        "url": "http://portal.gov.in/",
        "http_status": 403,
        "http_complete": 1,
        "url_availability": "full_http",
    }
    base.update(kwargs)
    return base


def test_sqli_and_benign():
    assert sqli.detect(ev(query="id=1' OR '1'='1", path="/item", url="http://x/item?id=1' OR '1'='1"))
    assert sqli.detect(ev(query="q=UNION SELECT password FROM users"))
    assert not sqli.detect(ev(query="q=report", path="/search"))


def test_xss():
    assert xss.detect(ev(query="q=<script>alert(1)</script>"))
    assert xss.detect(ev(query="x=%3Cscript%3E"))
    assert not xss.detect(ev(query="q=hello"))


def test_traversal():
    assert traversal.detect(ev(query="file=../../../../etc/passwd"))
    assert traversal.detect(ev(query="p=%2e%2e%2fetc%2fpasswd"))
    assert not traversal.detect(ev(query="file=report.pdf"))


def test_command():
    assert command.detect(ev(query="cmd=; cat /etc/passwd"))
    assert not command.detect(ev(query="sort=asc;page=1"))  # semicolon without command token
    assert not command.detect(ev(query="user=admin&id=2"))  # query separator, not shell


def test_ssrf():
    assert ssrf.detect(ev(query="url=http://169.254.169.254/latest/meta-data/"))
    assert not ssrf.detect(ev(query="url=http://cdn.example.com/img.png"))


def test_lfi_rfi():
    assert lfi_rfi.detect(ev(query="include=../../../../etc/passwd", path="/inc"))
    assert lfi_rfi.detect(ev(query="page=http://evil.test/a.txt", path="/view"))
    assert not lfi_rfi.detect(ev(query="page=home"))


def test_hpp():
    assert hpp.detect(ev(query="id=1&id=2"))
    assert not hpp.detect(ev(query="id=1&role=user"))


def test_xxe():
    assert xxe.detect(ev(body='<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'))
    assert not xxe.detect(ev(query="q=xml-help"))


def test_webshell():
    assert webshell.detect(ev(path="/upload", filename="shell.php", query="filename=shell.php"))
    assert not webshell.detect(ev(path="/images", filename="logo.png"))


def test_typosquat():
    assert typosquat.detect(ev(host="g00gle.com", url="http://g00gle.com/login"))
    assert not typosquat.detect(ev(host="google.com"))


def test_features_flags():
    f = extract_features(ev(query="id=1' UNION SELECT 1", url="http://x/a?id=1' UNION SELECT 1"))
    assert f["has_sql_token"] == 1
    assert f["param_count"] >= 1

"""Shared constants. Detection is pattern matching — payloads are never executed."""

ATTACK_TYPES = [
    "Typosquatting / URL spoofing",
    "SQL Injection",
    "Cross-Site Scripting (XSS)",
    "Directory Traversal",
    "Command Injection",
    "Server-Side Request Forgery (SSRF)",
    "Local File Inclusion / Remote File Inclusion (LFI/RFI)",
    "Credential Stuffing / Brute Force",
    "HTTP Parameter Pollution (HPP)",
    "XML External Entity Injection (XXE)",
    "Web shell upload indicators",
    "ANOMALOUS_URL",
]

STATUSES = ["ATTEMPT", "CONFIRMED", "UNKNOWN"]
SEVERITIES = ["low", "medium", "high", "critical"]
SOURCE_TYPES = ["ipdr", "pcap", "synthetic"]

# Types where a 2xx + extra signal can support CONFIRMED (still never URL-only).
SUCCESS_LOOKS_LIKE_PAGE = {
    "SQL Injection",
    "Cross-Site Scripting (XSS)",
    "Directory Traversal",
    "Command Injection",
    "Server-Side Request Forgery (SSRF)",
    "Local File Inclusion / Remote File Inclusion (LFI/RFI)",
    "XML External Entity Injection (XXE)",
    "Web shell upload indicators",
}

LOGIN_PATH_HINTS = ("/login", "/auth", "/signin", "/token", "/oauth")
UPLOAD_PATH_HINTS = ("/upload", "/file", "/media", "/static/uploads")

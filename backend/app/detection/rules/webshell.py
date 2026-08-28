"""Web shell upload filename/path indicators. Pattern match only."""

from __future__ import annotations

from typing import Any, Optional

from app.detection.rules.common import evidence, hit
from app.models import UPLOAD_PATH_HINTS

SHELL_NAMES = ("c99", "b374k", "r57", "wso.php", "cmd.aspx", "shell.php", "cmd.php", "webshell")
SHELL_EXTS = (".php", ".jsp", ".aspx", ".jspx", ".war")


def detect(event: dict[str, Any]) -> Optional[dict]:
    path = (event.get("path") or "").lower()
    fname = (event.get("filename") or "").lower()
    query = (event.get("query") or "").lower()
    blob = " ".join([path, fname, query])
    name_hit = next((n for n in SHELL_NAMES if n in blob), None)
    uploadish = any(h in path for h in UPLOAD_PATH_HINTS) or "filename=" in query or fname
    ext_hit = any(blob.endswith(e) or e in fname or f"filename={e}" in query for e in (".php", ".jsp", ".aspx"))
    if name_hit:
        return hit(
            "Web shell upload indicators",
            [evidence("shell_name", "Known webshell-like filename/path token", name_hit)],
            severity="critical",
            risk=88,
        )
    if uploadish and (fname.endswith(SHELL_EXTS) or any(e in fname for e in SHELL_EXTS)):
        return hit(
            "Web shell upload indicators",
            [evidence("upload_ext", "Executable web extension in upload context", fname or path)],
            severity="high",
            risk=70,
        )
    if "/uploads/" in path and any(path.endswith(e) for e in SHELL_EXTS):
        return hit(
            "Web shell upload indicators",
            [evidence("upload_path", "Request to executable file under upload path", path)],
            severity="high",
            risk=72,
        )
    if ext_hit and uploadish:
        return hit(
            "Web shell upload indicators",
            [evidence("upload_ext", "Upload-like request with web-executable extension", blob[:120])],
            severity="medium",
            risk=60,
        )
    return None

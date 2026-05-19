from __future__ import annotations
import hashlib
from dataclasses import dataclass

try:
    import requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False

_API_BASE = "https://api.pwnedpasswords.com/range/"
_TIMEOUT  = 5


@dataclass
class HIBPResult:
    checked: bool
    pwned: bool
    count: int
    sha1_prefix: str
    error: str | None = None


def check(password: str) -> HIBPResult:
    if not _REQUESTS_AVAILABLE:
        return HIBPResult(
            checked=False, pwned=False, count=0, sha1_prefix="",
            error="requests not installed — run: pip install requests"
        )

    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        resp = requests.get(
            f"{_API_BASE}{prefix}",
            timeout=_TIMEOUT,
            headers={"Add-Padding": "true"},
        )
        resp.raise_for_status()
    except Exception as exc:
        return HIBPResult(
            checked=False, pwned=False, count=0,
            sha1_prefix=prefix,
            error=f"request failed: {exc}",
        )

    count = 0
    for line in resp.text.splitlines():
        parts = line.split(":")
        if len(parts) == 2 and parts[0].upper() == suffix:
            count = int(parts[1])
            break

    return HIBPResult(
        checked=True,
        pwned=count > 0,
        count=count,
        sha1_prefix=prefix,
    )
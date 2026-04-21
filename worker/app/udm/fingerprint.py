from __future__ import annotations

import hashlib
from urllib.parse import urlparse

from app.udm.models import UDMEvidence, UDMIdentity, UDMTarget


# ---------------------------------------------------------------------------
# Canonicalization helpers
# ---------------------------------------------------------------------------

def _c(value: str | int | float | None) -> str:
    """Canonical string: lowercase, stripped, None → empty string."""
    if value is None:
        return ""
    return str(value).lower().strip()


def _port(port: int | None) -> str:
    """Normalize port to plain integer string, e.g. '0443' → '443'."""
    if port is None:
        return ""
    return str(int(port))


def _url_path(url: str | None) -> str:
    """Extract only the path component of a URL, lowercased and stripped."""
    if not url:
        return ""
    try:
        return urlparse(url).path.lower().strip()
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_fingerprint(
    finding_type: str,
    target: UDMTarget,
    identity: UDMIdentity,
    evidence: UDMEvidence | None = None,
) -> str:
    """
    Compute a deterministic SHA-256 fingerprint for a finding.

    Formula varies by finding_type per the spec §3 Formula Matrix.
    All component strings are lowercased + stripped before hashing.
    Separator: pipe character "|".
    Returns: "sha256:<hex_digest>"
    """
    parts: list[str]

    if finding_type == "vulnerability":
        is_web = target.url is not None
        if is_web:
            parts = [
                _c(identity.standardized_rule_id),
                _c(target.hostname),
                _url_path(target.url),
            ]
        else:
            parts = [
                _c(identity.standardized_rule_id),
                _c(target.ip),
                _port(target.port),
                _c(target.protocol),
            ]

    elif finding_type == "exposure":
        is_web = target.url is not None
        if is_web:
            parts = [
                "exposure",
                _c(identity.standardized_rule_id),
                _c(target.hostname),
                _url_path(target.url),
            ]
        else:
            parts = [
                "exposure",
                _c(identity.standardized_rule_id),
                _c(target.hostname),
            ]

    elif finding_type == "misconfiguration":
        is_web = target.url is not None
        if is_web:
            parts = [
                "misconfig",
                _c(identity.standardized_rule_id),
                _c(target.hostname),
                _url_path(target.url),
            ]
        else:
            parts = [
                "misconfig",
                _c(identity.standardized_rule_id),
                _c(target.hostname),
            ]

    elif finding_type == "port_service":
        parts = [
            "port",
            _c(target.ip),
            _port(target.port),
            _c(target.protocol),
        ]

    elif finding_type == "ssl_finding":
        parts = [
            "ssl",
            _c(identity.standardized_rule_id),
            _c(target.hostname),
            _port(target.port),
        ]

    elif finding_type == "dns_finding":
        parts = [
            "dns",
            _c(identity.category),
            _c(target.hostname),
        ]

    elif finding_type == "secret":
        ev = evidence
        repo_or_url = _c(ev.repo_url if ev else None) or _c(target.url)
        file_path   = _c(ev.file_path if ev else None)
        line_num    = _c(str(ev.line_number) if ev and ev.line_number is not None else None)
        parts = [
            "secret",
            _c(identity.standardized_rule_id),
            repo_or_url,
            file_path,
            line_num,
        ]

    elif finding_type == "asset_discovery":
        parts = [
            "asset",
            _c(target.host_normalized),
        ]

    else:
        raise ValueError(f"Unknown finding_type: {finding_type!r}")

    raw = "|".join(parts).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()

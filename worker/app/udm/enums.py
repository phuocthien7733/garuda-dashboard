from __future__ import annotations

from enum import Enum
from typing import Literal


class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"
    UNKNOWN  = "unknown"


SEVERITY_RANK: dict[SeverityLevel, int] = {
    SeverityLevel.CRITICAL: 5,
    SeverityLevel.HIGH:     4,
    SeverityLevel.MEDIUM:   3,
    SeverityLevel.LOW:      2,
    SeverityLevel.INFO:     1,
    SeverityLevel.UNKNOWN:  0,
}

# Aliases for non-standard severity strings coming from scanner output.
# Maps raw string → canonical SeverityLevel value string.
SEVERITY_ALIASES: dict[str, str] = {
    "informational": "info",
    "information":   "info",
    "note":          "info",
    "warn":          "low",
    "warning":       "low",
    "moderate":      "medium",
    "important":     "high",
    "urgent":        "critical",
    "crit":          "critical",
}

# Integer severity scale used by Invicti / Acunetix.
INVICTI_SEVERITY_MAP: dict[int, str] = {
    0: "info",
    1: "low",
    2: "medium",
    3: "high",
    4: "critical",
}

FindingType = Literal[
    "vulnerability",    # Confirmed or possible security flaw (Nuclei CVE, DAST)
    "exposure",         # Exposed panel/file (risky but not confirmed exploitable)
    "port_service",     # Open port + service info (Nmap, Masscan, Shodan)
    "dns_finding",      # Subdomain takeover, dangling CNAME (dnsx, Amass)
    "ssl_finding",      # Cert expiry, weak cipher (SSLyze, testssl, Invicti TLS)
    "secret",           # Leaked key/token/cred (TruffleHog, Gitleaks)
    "misconfiguration", # Missing header, CORS open (Nuclei misconfig, Invicti config)
    "asset_discovery",  # New host/IP found (Subfinder, httpx)
]

FINDING_TYPES: tuple[str, ...] = (
    "vulnerability",
    "exposure",
    "port_service",
    "dns_finding",
    "ssl_finding",
    "secret",
    "misconfiguration",
    "asset_discovery",
)


def normalize_severity(raw: str | None) -> SeverityLevel:
    """Normalize any raw severity string to a SeverityLevel enum value."""
    if raw is None:
        return SeverityLevel.UNKNOWN
    lowered = raw.strip().lower()
    # Check aliases first
    canonical = SEVERITY_ALIASES.get(lowered, lowered)
    try:
        return SeverityLevel(canonical)
    except ValueError:
        return SeverityLevel.UNKNOWN


def resolve_severity_max(a: SeverityLevel, b: SeverityLevel) -> SeverityLevel:
    """Return the higher of two SeverityLevel values."""
    return a if SEVERITY_RANK[a] >= SEVERITY_RANK[b] else b

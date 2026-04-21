from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, field_validator

from app.udm.enums import FindingType, SeverityLevel
from app.core.host_classification import extract_apex_domain


# ---------------------------------------------------------------------------
# Sub-models
# ---------------------------------------------------------------------------

class UDMTarget(BaseModel):
    """Describes the affected asset / scan target."""
    model_config = ConfigDict(populate_by_name=True)

    ip:              str | None = None   # "1.2.3.4"
    hostname:        str | None = None   # "api.example.com"
    url:             str | None = None   # "https://api.example.com/v1/users?id=1"
    port:            int | None = None   # 443
    protocol:        str | None = None   # "tcp" | "https" | "udp"
    path:            str | None = None   # "/v1/users"
    host_normalized: str        = ""     # COMPUTED — set by build_host_normalized()

    def compute_host_normalized(self) -> str:
        """
        Derive the canonical host key used for asset deduplication.
        Returns the FULL hostname (lowercased) so each subdomain is its own asset.
        IP addresses are returned as-is.
        Priority: hostname → url (hostname part) → ip → "unknown"
        """
        if self.hostname:
            return self.hostname.lower().strip().rstrip(".")
        if self.url:
            try:
                from urllib.parse import urlparse
                parsed_host = urlparse(self.url).hostname or ""
                return parsed_host.lower().strip().rstrip(".") if parsed_host else "unknown"
            except Exception:
                pass
        if self.ip:
            return self.ip
        return "unknown"

    def compute_apex_domain(self) -> str | None:
        """
        Return the apex (registrable) domain for grouping/parent queries.
        e.g. sub.example.com → example.com, 1.2.3.4 → None
        """
        host = self.hostname or (
            __import__("urllib.parse", fromlist=["urlparse"]).urlparse(self.url).hostname
            if self.url else None
        )
        if not host:
            return None
        apex = extract_apex_domain(host)
        # Don't return apex if it's the same as the full host (already apex) or an IP
        return apex if apex and apex != host.lower().strip().rstrip(".") else None


class UDMIdentity(BaseModel):
    """Describes what was found — the vulnerability / finding identity."""
    model_config = ConfigDict(populate_by_name=True)

    standardized_rule_id: str              # Canonical cross-tool ID (see §3 of spec)
    raw_rule_id:          str              # As-is from tool output
    name:                 str              # Human-readable name
    category:             str              # "xss" | "rce" | "port_open" | ...
    cve:                  list[str] = []   # ["CVE-2021-44228"]
    cwe:                  list[str] = []   # ["CWE-79"]
    cvss_score:           float | None = None
    cvss_vector:          str   | None = None  # "CVSS:3.1/AV:N/..."


class EvidenceSnapshot(BaseModel):
    """A point-in-time snapshot of raw evidence from a re-scan."""
    model_config = ConfigDict(populate_by_name=True)

    timestamp:   datetime
    source_tool: str
    raw:         dict    # raw finding dict at that point in time


class UDMEvidence(BaseModel):
    """Proof of the finding — request/response, payloads, secrets metadata."""
    model_config = ConfigDict(populate_by_name=True)

    # --- Generic HTTP evidence ---
    request:      str | None = None   # Raw HTTP request
    response:     str | None = None   # Raw HTTP response (may be truncated)
    matched_at:   str | None = None   # URL/string where match occurred
    extracted:    list[str] = []      # Regex captures / extracted values
    curl_command: str | None = None   # Reproducible PoC

    # --- Web scanner specific (Invicti, Burp, Acunetix) ---
    http_method:      str | None = None   # "POST", "GET"
    input_type:       str | None = None   # "json", "query", "header", "cookie"
    input_name:       str | None = None   # Parameter name
    test_value:       str | None = None   # Payload used

    # --- Template/details rendering (Invicti details_template) ---
    details_template: str | None = None
    details_data:     dict       = {}

    # --- Secret scanner specific (TruffleHog, Gitleaks) ---
    secret_type:  str | None = None   # "AWS_ACCESS_KEY", "JWT", "SSH_KEY"
    secret_raw:   str | None = None   # Redacted partial value (never full secret)
    repo_url:     str | None = None
    commit_hash:  str | None = None
    file_path:    str | None = None
    line_number:  int | None = None

    # --- Evidence history: accumulate over time (Option C) ---
    # Each re-scan of the same fingerprint appends a snapshot here.
    history: list[EvidenceSnapshot] = []

    # --- Full raw scanner output (passthrough) ---
    # Truncation is applied BEFORE storage based on adapter evidence_limits config.
    raw:                  dict      = {}
    raw_truncated:        bool      = False
    raw_original_size_kb: int | None = None


# ---------------------------------------------------------------------------
# Root document
# ---------------------------------------------------------------------------

class UniversalFinding(BaseModel):
    """
    The root MongoDB document for the vulnerabilities collection.
    All fields are populated by the ingestion engine — never directly from user input.
    """
    model_config = ConfigDict(populate_by_name=True)

    # ── COMPUTED (set by ingestion engine, never from adapter) ──────────────
    fingerprint:    str       # SHA-256 hex, formula by finding_type (§3 of spec)
    schema_version: int = 2

    # ── CLASSIFICATION ───────────────────────────────────────────────────────
    finding_type: FindingType

    # ── MODELS ───────────────────────────────────────────────────────────────
    target:   UDMTarget
    identity: UDMIdentity
    evidence: UDMEvidence | None = None

    # ── SEVERITY ─────────────────────────────────────────────────────────────
    severity:          SeverityLevel
    severity_source:   str = "scanner"   # "scanner" | "cvss" | "override"
    override_severity: SeverityLevel | None = None

    # ── TIMESTAMPS (immutable: $setOnInsert) ─────────────────────────────────
    first_seen:        datetime
    source_tool_first: str               # Tool that first discovered this finding

    # ── TIMESTAMPS (mutable: $set) ───────────────────────────────────────────
    last_seen: datetime

    # ── CROSS-TOOL ACCUMULATION ($addToSet) ──────────────────────────────────
    discovery_tools: list[str] = []      # ["nuclei", "shodan"] — audit trail
    tags:            list[str] = []
    references:      list[str] = []

    # ── WORKFLOW STATE (user-managed — engine only sets status via $setOnInsert) ──
    status:   str       = "Open"         # "Open"|"Investigating"|"Accepted Risk"|"Resolved"
    asset_id: Any | None = None          # ObjectId → assets collection (set by backend)

    # ── SOURCE METADATA ($set) ───────────────────────────────────────────────
    source_file: str = ""


# ---------------------------------------------------------------------------
# Asset document helper model (not stored as-is; built by upsert.py)
# ---------------------------------------------------------------------------

class PortEntry(BaseModel):
    """Single entry inside the port_metadata dict."""
    model_config = ConfigDict(populate_by_name=True)

    first_seen: datetime
    last_seen:  datetime
    status:     str = "open"   # "open" | "stale"
    service:    str = ""

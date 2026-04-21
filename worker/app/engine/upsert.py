"""
Build PyMongo UpdateOne operations for bulk_write without any DB reads.

Key architectural contracts (from spec §6):
  - status="Open" is ONLY in $setOnInsert — NEVER in $set.
  - _severity_rank internal int field enables MAX comparison without reads.
  - discovery_tools / tags / references always use $addToSet.
  - Ports use $set dot-notation per key + $min for first_seen preservation.
"""
from __future__ import annotations

from datetime import datetime

from pymongo import UpdateOne

from app.core.host_classification import classify_host_type
from app.udm.enums import SEVERITY_RANK, SeverityLevel
from app.udm.models import UniversalFinding


def build_vuln_upsert(finding: UniversalFinding, now: datetime) -> UpdateOne:
    """Return an UpdateOne that upserts a UniversalFinding into `vulnerabilities`."""
    fp = finding.fingerprint
    tool = finding.discovery_tools[0] if finding.discovery_tools else "unknown"
    incoming_rank = SEVERITY_RANK.get(SeverityLevel(finding.severity), 0)

    return UpdateOne(
        filter={"fingerprint": fp},
        update={
            "$setOnInsert": {
                "fingerprint":       fp,
                "finding_type":      finding.finding_type,
                "target":            finding.target.model_dump(),
                "identity":          finding.identity.model_dump(),
                "first_seen":        now,
                "source_tool_first": tool,
                "schema_version":    2,
                "status":            "Open",    # ONLY here — never in $set
                # Severity is set on first insert; build_severity_max_update upgrades it.
                "severity":          finding.severity,
                "_severity_rank":    incoming_rank,
            },
            "$set": {
                "last_seen":   now,
                "evidence":    finding.evidence.model_dump() if finding.evidence else {},
                "source_file": finding.source_file,
            },
            "$addToSet": {
                "discovery_tools": {"$each": finding.discovery_tools},
                "tags":            {"$each": finding.tags},
                "references":      {"$each": finding.references},
            },
        },
        upsert=True,
    )


def build_severity_max_update(fingerprint: str, severity: SeverityLevel | str) -> UpdateOne:
    """
    Conditionally raise severity to `severity` only when the incoming rank is higher.
    Uses `_severity_rank` internal int for filter-side comparison (no client read needed).
    """
    sev = SeverityLevel(severity) if not isinstance(severity, SeverityLevel) else severity
    incoming_rank = SEVERITY_RANK.get(sev, 0)
    return UpdateOne(
        filter={
            "fingerprint":    fingerprint,
            "_severity_rank": {"$lt": incoming_rank},
        },
        update={
            "$set": {
                "severity":       sev.value,
                "_severity_rank": incoming_rank,
            }
        },
    )


def build_asset_upsert(
    host_normalized: str,
    ip: str | None,
    port_str: str | None,      # e.g. "443/tcp"
    port_service: str | None,  # e.g. "https"
    technology: str | None,
    tool_name: str,
    now: datetime,
    apex_domain: str | None = None,  # parent domain for grouping queries
) -> UpdateOne:
    """
    Non-destructive asset upsert.
    - host_normalized is the FULL hostname (e.g. sub.example.com) — each subdomain
      is its own asset record.
    - apex_domain (e.g. example.com) is stored for grouping/parent queries.
    - IPs and technologies: pure $addToSet — never overwrite.
    - Ports: $set dot-notation per key + $min to preserve first_seen.
    """
    host_type = classify_host_type(host_normalized)

    add_to_set: dict = {"discovery_tools": tool_name}
    if ip:
        add_to_set["ip_addresses"] = ip
    if technology:
        add_to_set["technologies"] = technology

    set_fields: dict = {"last_seen": now}
    min_fields: dict = {}

    if port_str:
        key = f"port_metadata.{port_str}"
        set_fields[f"{key}.last_seen"] = now
        set_fields[f"{key}.status"]    = "open"
        set_fields[f"{key}.service"]   = port_service or ""
        min_fields[f"{key}.first_seen"] = now

    set_on_insert: dict = {
        "host_normalized": host_normalized,
        "type":            host_type,
        "first_seen":      now,
    }
    if apex_domain:
        set_on_insert["apex_domain"] = apex_domain

    update: dict = {
        "$setOnInsert": set_on_insert,
        "$set":         set_fields,
        "$addToSet":    add_to_set,
    }
    if min_fields:
        update["$min"] = min_fields

    return UpdateOne(
        filter={"host_normalized": host_normalized},
        update=update,
        upsert=True,
    )

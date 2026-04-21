"""
process_file() — Universal ingestion engine entry point.

Flow for each file:
  1. Resolve adapter config  →  quarantine if no_adapter
  2. Parse file              →  quarantine if parse_error
  3. Map each finding        →  collect all; quarantine whole file if any fail (fail-whole-file policy)
  4. bulk_write              →  quarantine if db_error
  5. severity MAX updates    →  best-effort (log but don't quarantine on failure)
  6. build asset upserts     →  bulk_write to assets
  7. recalculate_assets()    →  async post-processing
  8. move file to archive
"""
from __future__ import annotations

import logging
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from app.adapters.extractor import extract_findings
from app.adapters.mapper import ValidationError as MapperValidationError
from app.adapters.mapper import map_finding
from app.adapters.registry import get_adapter, has_adapter
from app.adapters.base import AdapterConfig
from app.core.jsonpath_utils import extract as jsonpath_extract
from app.db import get_database
from app.engine.file_lifecycle import (
    FindingError,
    QuarantineError,
    move_to_archive,
    move_to_quarantine,
)
from app.engine.recalculator import recalculate_assets
from app.core.host_classification import extract_apex_domain
from app.engine.upsert import build_asset_upsert, build_severity_max_update, build_vuln_upsert
from app.udm.enums import SEVERITY_RANK, SeverityLevel
from app.udm.models import UniversalFinding

logger = logging.getLogger("ingestion-worker.processor")


# ---------------------------------------------------------------------------
# Result summary
# ---------------------------------------------------------------------------

@dataclass
class ProcessingSummary:
    file_name: str
    processed: int = 0
    inserted:  int = 0
    updated:   int = 0
    skipped:   int = 0
    assets_updated: int = 0
    quarantined: bool = False
    errors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Scanner fingerprint validation
# ---------------------------------------------------------------------------

def _validate_scanner_fingerprint(
    file_path: Path,
    adapter: AdapterConfig,
) -> list[str]:
    """
    Load the raw document and check required_paths / forbidden_paths.
    Returns a list of failure messages (empty = valid).
    """
    val_cfg = adapter.input_validation
    if not val_cfg.required_paths and not val_cfg.forbidden_paths:
        return []  # no rules configured — skip

    try:
        import json
        doc = json.loads(file_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return [f"Cannot parse file for fingerprint check: {exc}"]

    failures: list[str] = []

    for path in val_cfg.required_paths:
        value = jsonpath_extract(doc, path)
        if value is None:
            failures.append(f"required_path not found: {path!r}")

    for path in val_cfg.forbidden_paths:
        value = jsonpath_extract(doc, path)
        if value is not None:
            failures.append(f"forbidden_path found (indicates wrong scanner): {path!r}")

    return failures


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

async def process_file(
    file_path: Path,
    scanner_name: str,
    archive_root: Path,
    quarantine_root: Path,
) -> ProcessingSummary:
    """
    Ingest a scanner report file end-to-end.
    Always moves the file to archive/ or quarantine/ before returning.
    """
    summary = ProcessingSummary(file_name=file_path.name)
    now = datetime.now(timezone.utc)
    db = get_database()

    # ── 1. Resolve adapter ───────────────────────────────────────────────────
    if not has_adapter(scanner_name):
        _quarantine(
            file_path, scanner_name, quarantine_root,
            QuarantineError(
                original_filename=file_path.name,
                scanner=scanner_name,
                reason="no_adapter",
                summary=f"No YAML adapter config found for scanner '{scanner_name}'",
            ),
            summary,
        )
        return summary

    adapter = get_adapter(scanner_name)

    # ── 1b. Validate scanner fingerprint ────────────────────────────────────
    fingerprint_failures = _validate_scanner_fingerprint(file_path, adapter)
    if fingerprint_failures:
        logger.warning(
            "Fingerprint check failed for %s (scanner=%s): %s",
            file_path.name, scanner_name, "; ".join(fingerprint_failures),
        )
        _quarantine(
            file_path, scanner_name, quarantine_root,
            QuarantineError(
                original_filename=file_path.name,
                scanner=scanner_name,
                reason="wrong_scanner",
                summary=(
                    f"File does not match expected structure for scanner '{scanner_name}'. "
                    f"{len(fingerprint_failures)} check(s) failed."
                ),
                errors=[
                    FindingError(finding_index=-1, reason=msg)
                    for msg in fingerprint_failures
                ],
            ),
            summary,
        )
        return summary

    # ── 2. Parse + map findings (fail-whole-file policy) ────────────────────
    findings: list[UniversalFinding] = []
    finding_errors: list[FindingError] = []

    try:
        for idx, raw in enumerate(extract_findings(file_path, adapter)):
            try:
                finding = map_finding(raw, adapter, str(file_path), idx)
                findings.append(finding)
            except MapperValidationError as exc:
                finding_errors.append(FindingError(
                    finding_index=exc.finding_index,
                    reason="required_field_missing",
                    missing_fields=exc.missing,
                    raw_finding_preview=dict(list(raw.items())[:10]),
                ))
            except Exception as exc:
                finding_errors.append(FindingError(
                    finding_index=idx,
                    reason="mapping_error",
                    raw_finding_preview=dict(list(raw.items())[:10]),
                ))
                logger.warning("Unexpected mapping error at index %s: %s", idx, exc)

    except Exception as exc:
        _quarantine(
            file_path, scanner_name, quarantine_root,
            QuarantineError(
                original_filename=file_path.name,
                scanner=scanner_name,
                reason="parse_error",
                summary=f"Failed to parse file: {exc}",
                exception_traceback=traceback.format_exc(),
            ),
            summary,
        )
        return summary

    total = len(findings) + len(finding_errors)

    if finding_errors:
        _quarantine(
            file_path, scanner_name, quarantine_root,
            QuarantineError(
                original_filename=file_path.name,
                scanner=scanner_name,
                reason="validation_error",
                summary=f"{len(finding_errors)} findings failed required_fields check",
                total_findings=total,
                failed_findings=len(finding_errors),
                succeeded_findings=len(findings),
                errors=finding_errors,
            ),
            summary,
        )
        return summary

    if not findings:
        # Empty file is a no-op — archive it
        archive_path = move_to_archive(file_path, scanner_name, archive_root)
        logger.info("Empty file archived: %s → %s", file_path.name, archive_path.name)
        return summary

    # ── 3. Build + execute vulnerability bulk_write ──────────────────────────
    vuln_ops = [build_vuln_upsert(f, now) for f in findings]

    try:
        vuln_result = await db.vulnerabilities.bulk_write(vuln_ops, ordered=False)
        summary.inserted = vuln_result.upserted_count
        summary.updated  = vuln_result.modified_count
        summary.processed = len(findings)
    except Exception as exc:
        _quarantine(
            file_path, scanner_name, quarantine_root,
            QuarantineError(
                original_filename=file_path.name,
                scanner=scanner_name,
                reason="db_error",
                summary=f"MongoDB bulk_write failed: {exc}",
                total_findings=total,
                exception_traceback=traceback.format_exc(),
            ),
            summary,
        )
        return summary

    # ── 4. Severity MAX updates (best-effort, not quarantine-worthy) ─────────
    sev_ops = [
        build_severity_max_update(f.fingerprint, f.severity)
        for f in findings
    ]
    if sev_ops:
        try:
            await db.vulnerabilities.bulk_write(sev_ops, ordered=False)
        except Exception:
            logger.exception("Severity MAX update bulk_write failed (non-fatal)")

    # ── 5. Asset upserts ─────────────────────────────────────────────────────
    touched_hosts: set[str] = set()
    asset_ops = []

    for f in findings:
        host = f.target.host_normalized
        if not host or host == "unknown":
            continue
        touched_hosts.add(host)

        port_str: str | None = None
        port_service: str | None = None
        if f.target.port and f.target.protocol:
            port_str = f"{f.target.port}/{f.target.protocol.lower()}"
        elif f.target.port:
            port_str = f"{f.target.port}/tcp"

        if f.evidence and f.evidence.matched_at:
            port_service = f.target.protocol

        tool = f.discovery_tools[0] if f.discovery_tools else scanner_name

        # Compute apex domain for grouping (None if host is already apex or is an IP)
        apex = extract_apex_domain(f.target.hostname) if f.target.hostname else None
        if apex == host:
            apex = None

        asset_ops.append(build_asset_upsert(
            host_normalized=host,
            ip=f.target.ip,
            port_str=port_str,
            port_service=port_service,
            technology=None,       # adapters may populate via tags in future
            tool_name=tool,
            now=now,
            apex_domain=apex,
        ))

    if asset_ops:
        try:
            asset_result = await db.assets.bulk_write(asset_ops, ordered=False)
            summary.assets_updated = asset_result.upserted_count + asset_result.modified_count
        except Exception:
            logger.exception("Asset bulk_write failed (non-fatal)")

    # ── 6. Recalculate asset stats ───────────────────────────────────────────
    try:
        await recalculate_assets(db, touched_hosts)
    except Exception:
        logger.exception("recalculate_assets failed (non-fatal)")

    # ── 7. Archive processed file ────────────────────────────────────────────
    archive_path = move_to_archive(file_path, scanner_name, archive_root)
    logger.info(
        "Archived %s → %s | processed=%s inserted=%s updated=%s assets=%s",
        file_path.name,
        archive_path.name,
        summary.processed,
        summary.inserted,
        summary.updated,
        summary.assets_updated,
    )
    return summary


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _quarantine(
    file_path: Path,
    scanner: str,
    quarantine_root: Path,
    error: QuarantineError,
    summary: ProcessingSummary,
) -> None:
    dest = move_to_quarantine(file_path, scanner, quarantine_root, error)
    summary.quarantined = True
    summary.errors.append(error.reason)
    logger.error(
        "Quarantined %s → %s | reason=%s summary=%s",
        file_path.name,
        dest.name,
        error.reason,
        error.summary,
    )

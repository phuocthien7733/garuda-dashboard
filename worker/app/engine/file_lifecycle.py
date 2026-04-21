"""
File lifecycle management for the ingestion engine.

Processed files are moved from incoming/ to archive/ (success) or quarantine/ (failure).
Every quarantined file gets a .error.json sidecar describing why it failed.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Error data structures
# ---------------------------------------------------------------------------

@dataclass
class FindingError:
    finding_index: int
    reason: str
    missing_fields: list[str] = field(default_factory=list)
    raw_finding_preview: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "finding_index":       self.finding_index,
            "reason":              self.reason,
            "missing_fields":      self.missing_fields,
            "raw_finding_preview": self.raw_finding_preview,
        }


@dataclass
class QuarantineError:
    """All information needed to write a quarantine sidecar."""
    original_filename: str
    scanner: str
    reason: str                                    # no_adapter | validation_error | db_error | parse_error
    summary: str
    total_findings: int    = 0
    failed_findings: int   = 0
    succeeded_findings: int = 0
    errors: list[FindingError] = field(default_factory=list)
    exception_traceback: str | None = None

    def to_dict(self) -> dict:
        data: dict = {
            "quarantined_at":    datetime.now(timezone.utc).isoformat(),
            "original_filename": self.original_filename,
            "scanner":           self.scanner,
            "reason":            self.reason,
            "summary":           self.summary,
            "stats": {
                "total_findings":     self.total_findings,
                "failed_findings":    self.failed_findings,
                "succeeded_findings": self.succeeded_findings,
            },
            "errors": [e.to_dict() for e in self.errors],
            "possible_causes": [
                "Scanner output format may have changed — check adapter YAML mappings",
                f"Adapter: worker/app/adapters/configs/{self.scanner}.yaml",
            ],
        }
        if self.exception_traceback:
            data["exception_traceback"] = self.exception_traceback
        return data


# ---------------------------------------------------------------------------
# Lifecycle functions
# ---------------------------------------------------------------------------

def _timestamped_name(file_path: Path) -> str:
    """Return '<stem>-<YYYYMMDDTHHMMSSZ><suffix>' for the given file."""
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{file_path.stem}-{timestamp}{file_path.suffix}"


def move_to_archive(
    file_path: Path,
    scanner: str,
    archive_root: Path,
) -> Path:
    """Move a successfully processed file into archive/<scanner>/ with a UTC timestamp suffix."""
    dest = archive_root / scanner / _timestamped_name(file_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    file_path.rename(dest)
    return dest


def move_to_quarantine(
    file_path: Path,
    scanner: str,
    quarantine_root: Path,
    error: QuarantineError,
) -> Path:
    """
    Move a failed file to quarantine/<scanner>/ and write an .error.json sidecar.
    Returns the destination path.
    """
    dest = quarantine_root / scanner / _timestamped_name(file_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    file_path.rename(dest)

    sidecar = dest.with_suffix("").with_suffix(dest.suffix + ".error.json")
    sidecar.write_text(
        json.dumps(error.to_dict(), indent=2, default=str),
        encoding="utf-8",
    )
    return dest


def ensure_dirs(data_root: Path, scanner_names: list[str]) -> None:
    """
    Create incoming/, archive/, quarantine/ sub-folders for every scanner.
    Called once at worker startup.
    """
    for sub in ("incoming", "archive", "quarantine"):
        for scanner in scanner_names:
            (data_root / sub / scanner).mkdir(parents=True, exist_ok=True)

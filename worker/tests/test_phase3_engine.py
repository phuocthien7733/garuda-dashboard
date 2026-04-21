"""
Phase 3 — Ingestion Engine unit tests.

These tests cover:
  - upsert.py: build_vuln_upsert, build_asset_upsert, build_severity_max_update
  - file_lifecycle.py: move_to_archive, move_to_quarantine, ensure_dirs
  - recalculator.py: _rank_to_severity helper

MongoDB-dependent tests (processor.py) are marked with @pytest.mark.asyncio
and require a live MongoDB instance — they are skipped in unit-test-only runs
via the SKIP_MONGO_TESTS env var.
"""
from __future__ import annotations

import json
import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.engine.file_lifecycle import (
    FindingError,
    QuarantineError,
    ensure_dirs,
    move_to_archive,
    move_to_quarantine,
)
from app.engine.recalculator import _rank_to_severity
from app.engine.upsert import (
    build_asset_upsert,
    build_severity_max_update,
    build_vuln_upsert,
)
from app.udm.enums import SeverityLevel
from app.udm.models import UDMEvidence, UDMIdentity, UDMTarget, UniversalFinding

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(
    fingerprint: str = "sha256:abc123",
    finding_type: str = "vulnerability",
    severity: str = "high",
    hostname: str = "example.com",
    source_file: str = "test.json",
) -> UniversalFinding:
    target = UDMTarget(hostname=hostname)
    target.host_normalized = target.compute_host_normalized()
    identity = UDMIdentity(
        standardized_rule_id="CVE-2021-44228",
        raw_rule_id="CVE-2021-44228",
        name="Log4Shell",
        category="rce",
    )
    now = datetime.now(timezone.utc)
    return UniversalFinding(
        fingerprint=fingerprint,
        finding_type=finding_type,
        target=target,
        identity=identity,
        severity=SeverityLevel(severity),
        first_seen=now,
        last_seen=now,
        source_tool_first="nuclei",
        discovery_tools=["nuclei"],
        tags=["cve", "rce"],
        references=["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228"],
        source_file=source_file,
    )


# ---------------------------------------------------------------------------
# Tests: upsert.py
# ---------------------------------------------------------------------------

class TestBuildVulnUpsert:
    def test_has_set_on_insert_with_status_open(self):
        f = _make_finding()
        now = datetime.now(timezone.utc)
        op = build_vuln_upsert(f, now)
        doc = op._doc
        assert "$setOnInsert" in doc
        assert doc["$setOnInsert"]["status"] == "Open"

    def test_severity_in_set_on_insert(self):
        """severity and _severity_rank must be set on first insert (never missing on new docs)."""
        f = _make_finding()
        now = datetime.now(timezone.utc)
        op = build_vuln_upsert(f, now)
        soi = op._doc["$setOnInsert"]
        assert "severity" in soi
        assert "_severity_rank" in soi
        assert soi["severity"] == "high"
        assert soi["_severity_rank"] == 4  # high rank

    def test_status_not_in_set(self):
        """status must NEVER appear in $set — hard architectural rule."""
        f = _make_finding()
        now = datetime.now(timezone.utc)
        op = build_vuln_upsert(f, now)
        doc = op._doc
        assert "status" not in doc.get("$set", {})

    def test_set_has_last_seen(self):
        f = _make_finding()
        now = datetime.now(timezone.utc)
        op = build_vuln_upsert(f, now)
        assert op._doc["$set"]["last_seen"] == now

    def test_add_to_set_discovery_tools(self):
        f = _make_finding()
        now = datetime.now(timezone.utc)
        op = build_vuln_upsert(f, now)
        add = op._doc["$addToSet"]
        assert add["discovery_tools"]["$each"] == ["nuclei"]

    def test_add_to_set_tags(self):
        f = _make_finding()
        now = datetime.now(timezone.utc)
        op = build_vuln_upsert(f, now)
        assert op._doc["$addToSet"]["tags"]["$each"] == ["cve", "rce"]

    def test_filter_is_fingerprint(self):
        f = _make_finding(fingerprint="sha256:deadbeef")
        op = build_vuln_upsert(f, datetime.now(timezone.utc))
        assert op._filter == {"fingerprint": "sha256:deadbeef"}

    def test_upsert_true(self):
        f = _make_finding()
        op = build_vuln_upsert(f, datetime.now(timezone.utc))
        assert op._upsert is True


class TestBuildSeverityMaxUpdate:
    def test_filter_has_severity_rank_lt(self):
        op = build_severity_max_update("sha256:abc", SeverityLevel.HIGH)
        assert op._filter["_severity_rank"] == {"$lt": 4}  # HIGH rank = 4

    def test_set_updates_both_fields(self):
        op = build_severity_max_update("sha256:abc", "critical")
        assert op._doc["$set"]["severity"] == "critical"
        assert op._doc["$set"]["_severity_rank"] == 5

    def test_unknown_severity_rank_is_zero(self):
        op = build_severity_max_update("sha256:abc", SeverityLevel.UNKNOWN)
        assert op._filter["_severity_rank"] == {"$lt": 0}


class TestBuildAssetUpsert:
    def test_set_on_insert_has_host_type(self):
        now = datetime.now(timezone.utc)
        op = build_asset_upsert("example.com", None, None, None, None, "nuclei", now)
        soi = op._doc["$setOnInsert"]
        assert soi["host_normalized"] == "example.com"
        assert "type" in soi
        assert soi["first_seen"] == now

    def test_apex_domain_stored_when_subdomain(self):
        now = datetime.now(timezone.utc)
        op = build_asset_upsert("api.example.com", None, None, None, None, "nuclei", now, apex_domain="example.com")
        assert op._doc["$setOnInsert"]["apex_domain"] == "example.com"

    def test_no_apex_domain_for_apex_host(self):
        now = datetime.now(timezone.utc)
        op = build_asset_upsert("example.com", None, None, None, None, "nuclei", now)
        assert "apex_domain" not in op._doc["$setOnInsert"]

    def test_port_creates_set_and_min_fields(self):
        now = datetime.now(timezone.utc)
        op = build_asset_upsert("1.2.3.4", "1.2.3.4", "443/tcp", "https", None, "nmap", now)
        doc = op._doc
        assert "port_metadata.443/tcp.last_seen" in doc["$set"]
        assert "port_metadata.443/tcp.first_seen" in doc["$min"]
        assert doc["$set"]["port_metadata.443/tcp.status"] == "open"

    def test_ip_added_to_add_to_set(self):
        now = datetime.now(timezone.utc)
        op = build_asset_upsert("example.com", "1.2.3.4", None, None, None, "nuclei", now)
        assert op._doc["$addToSet"]["ip_addresses"] == "1.2.3.4"

    def test_no_port_no_min_operator(self):
        now = datetime.now(timezone.utc)
        op = build_asset_upsert("example.com", None, None, None, None, "nuclei", now)
        assert "$min" not in op._doc

    def test_upsert_true(self):
        now = datetime.now(timezone.utc)
        op = build_asset_upsert("example.com", None, None, None, None, "nuclei", now)
        assert op._upsert is True


# ---------------------------------------------------------------------------
# Tests: file_lifecycle.py
# ---------------------------------------------------------------------------

class TestMoveToArchive:
    def test_moves_file_to_archive_subdir(self, tmp_path):
        incoming = tmp_path / "incoming" / "nuclei"
        incoming.mkdir(parents=True)
        archive_root = tmp_path / "archive"
        src = incoming / "scan.json"
        src.write_text('{"test": 1}')

        dest = move_to_archive(src, "nuclei", archive_root)

        assert not src.exists()
        assert dest.exists()
        assert dest.parent == archive_root / "nuclei"
        # filename should contain a timestamp suffix
        assert dest.stem.startswith("scan-")

    def test_timestamp_format(self, tmp_path):
        incoming = tmp_path / "incoming" / "nuclei"
        incoming.mkdir(parents=True)
        archive_root = tmp_path / "archive"
        src = incoming / "scan.json"
        src.write_text("{}")

        dest = move_to_archive(src, "nuclei", archive_root)
        # stem format: scan-YYYYMMDDTHHMMSSZ
        import re
        assert re.match(r"scan-\d{8}T\d{6}Z", dest.stem)


class TestMoveToQuarantine:
    def test_moves_file_and_writes_sidecar(self, tmp_path):
        incoming = tmp_path / "incoming" / "nuclei"
        incoming.mkdir(parents=True)
        quarantine_root = tmp_path / "quarantine"
        src = incoming / "bad.json"
        src.write_text("not json")

        error = QuarantineError(
            original_filename="bad.json",
            scanner="nuclei",
            reason="parse_error",
            summary="File is not valid JSON",
        )
        dest = move_to_quarantine(src, "nuclei", quarantine_root, error)

        assert not src.exists()
        assert dest.exists()
        # sidecar written
        sidecar = dest.with_suffix("").with_suffix(dest.suffix + ".error.json")
        assert sidecar.exists()
        sidecar_data = json.loads(sidecar.read_text())
        assert sidecar_data["reason"] == "parse_error"
        assert sidecar_data["scanner"] == "nuclei"

    def test_sidecar_contains_errors_list(self, tmp_path):
        incoming = tmp_path / "incoming" / "nuclei"
        incoming.mkdir(parents=True)
        quarantine_root = tmp_path / "quarantine"
        src = incoming / "fail.json"
        src.write_text("{}")

        error = QuarantineError(
            original_filename="fail.json",
            scanner="nuclei",
            reason="validation_error",
            summary="1 finding failed",
            total_findings=5,
            failed_findings=1,
            succeeded_findings=4,
            errors=[
                FindingError(
                    finding_index=2,
                    reason="required_field_missing",
                    missing_fields=["identity.standardized_rule_id"],
                )
            ],
        )
        dest = move_to_quarantine(src, "nuclei", quarantine_root, error)
        sidecar = dest.with_suffix("").with_suffix(dest.suffix + ".error.json")
        data = json.loads(sidecar.read_text())
        assert data["stats"]["total_findings"] == 5
        assert len(data["errors"]) == 1
        assert data["errors"][0]["missing_fields"] == ["identity.standardized_rule_id"]


class TestEnsureDirs:
    def test_creates_all_subdirs(self, tmp_path):
        ensure_dirs(tmp_path, ["nuclei", "nmap", "invicti"])
        for sub in ("incoming", "archive", "quarantine"):
            for scanner in ("nuclei", "nmap", "invicti"):
                assert (tmp_path / sub / scanner).is_dir()


# ---------------------------------------------------------------------------
# Tests: recalculator._rank_to_severity helper
# ---------------------------------------------------------------------------

class TestRankToSeverity:
    def test_rank_5_is_critical(self):
        assert _rank_to_severity(5) == "critical"

    def test_rank_0_is_unknown(self):
        assert _rank_to_severity(0) == "unknown"

    def test_rank_3_is_medium(self):
        assert _rank_to_severity(3) == "medium"

    def test_invalid_rank_returns_unknown(self):
        assert _rank_to_severity(99) == "unknown"


# ---------------------------------------------------------------------------
# Tests: processor.py (mocked DB)
# ---------------------------------------------------------------------------

class TestProcessorMocked:
    """Tests for process_file that mock the DB and file system."""

    @pytest.mark.asyncio
    async def test_no_adapter_quarantines_file(self, tmp_path):
        """File dropped into unknown scanner folder → quarantined with no_adapter reason."""
        from app.engine.processor import process_file

        # Create a dummy incoming file
        incoming = tmp_path / "incoming" / "unknown_scanner"
        incoming.mkdir(parents=True)
        src = incoming / "scan.json"
        src.write_text('{"test": 1}')

        summary = await process_file(
            file_path=src,
            scanner_name="unknown_scanner",
            archive_root=tmp_path / "archive",
            quarantine_root=tmp_path / "quarantine",
        )

        assert summary.quarantined is True
        assert "no_adapter" in summary.errors
        assert not src.exists()  # file was moved
        # quarantine directory was created
        quarantine_dir = tmp_path / "quarantine" / "unknown_scanner"
        assert quarantine_dir.exists()
        # at least one file in quarantine
        assert any(quarantine_dir.iterdir())

    @pytest.mark.asyncio
    async def test_parse_error_quarantines_file(self, tmp_path):
        """Malformed JSON file → quarantined with parse_error reason."""
        from app.engine.processor import process_file

        incoming = tmp_path / "incoming" / "nuclei"
        incoming.mkdir(parents=True)
        src = incoming / "bad.json"
        src.write_text("THIS IS NOT JSON AT ALL !! {{{")

        summary = await process_file(
            file_path=src,
            scanner_name="nuclei",
            archive_root=tmp_path / "archive",
            quarantine_root=tmp_path / "quarantine",
        )

        assert summary.quarantined is True
        assert "parse_error" in summary.errors

    @pytest.mark.asyncio
    async def test_valid_nuclei_file_calls_bulk_write(self, tmp_path):
        """Valid nuclei file → bulk_write called once; file archived."""
        from app.engine.processor import process_file

        nuclei_fixture = Path(__file__).parent / "fixtures" / "nuclei_sample.jsonl"
        if not nuclei_fixture.exists():
            pytest.skip("nuclei_sample.jsonl fixture not found")

        incoming = tmp_path / "incoming" / "nuclei"
        incoming.mkdir(parents=True)
        src = incoming / "nuclei_sample.jsonl"
        shutil.copy(nuclei_fixture, src)

        # Mock the DB
        mock_db = MagicMock()
        mock_bulk = AsyncMock()
        mock_bulk.upserted_count = 3
        mock_bulk.modified_count = 0
        mock_db.vulnerabilities.bulk_write = AsyncMock(return_value=mock_bulk)
        mock_db.assets.bulk_write = AsyncMock(return_value=mock_bulk)
        mock_db.vulnerabilities.aggregate.return_value.__aiter__ = AsyncMock(return_value=iter([]))
        # Make aggregate().to_list return an empty list
        agg_mock = MagicMock()
        agg_mock.to_list = AsyncMock(return_value=[])
        mock_db.vulnerabilities.aggregate = MagicMock(return_value=agg_mock)
        mock_db.assets.find_one = AsyncMock(return_value=None)
        mock_db.assets.update_one = AsyncMock()

        with patch("app.engine.processor.get_database", return_value=mock_db):
            summary = await process_file(
                file_path=src,
                scanner_name="nuclei",
                archive_root=tmp_path / "archive",
                quarantine_root=tmp_path / "quarantine",
            )

        assert not summary.quarantined
        assert summary.processed > 0
        assert not src.exists()  # file was moved to archive
        archive_dir = tmp_path / "archive" / "nuclei"
        assert archive_dir.exists()
        assert any(archive_dir.iterdir())

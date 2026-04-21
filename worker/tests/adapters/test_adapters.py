"""
Unit tests — Phase 2: Adapter Config System.

Run:
    docker compose exec worker pytest tests/adapters/test_adapters.py -v
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.adapters.base import parse_field_mapping, AdapterConfigError
from app.adapters.loader import load_adapter
from app.adapters.registry import get_adapter, has_adapter, clear_cache
from app.adapters.extractor import extract_findings
from app.adapters.mapper import map_finding, ValidationError
from app.udm.enums import SeverityLevel
from app.udm.models import UniversalFinding

FIXTURES = Path(__file__).parent.parent / "fixtures"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _nuclei_config():
    clear_cache()
    return get_adapter("nuclei")


def _invicti_config():
    clear_cache()
    return get_adapter("invicti")


def _trufflehog_config():
    clear_cache()
    return get_adapter("trufflehog")


# ---------------------------------------------------------------------------
# parse_field_mapping
# ---------------------------------------------------------------------------

class TestParseFieldMapping:
    def test_simple_string(self):
        fm = parse_field_mapping("$.info.name")
        assert fm.sources == ["$.info.name"]
        assert not fm.collect_all

    def test_static_string(self):
        fm = parse_field_mapping("'info'")
        assert fm.sources == ["'info'"]

    def test_static_list(self):
        fm = parse_field_mapping(["burp", "dast"])
        assert fm.static == ["burp", "dast"]
        assert not fm.sources

    def test_null(self):
        fm = parse_field_mapping(None)
        assert not fm.sources
        assert fm.static is None

    def test_dict_single_source(self):
        fm = parse_field_mapping({"source": "$.port", "transform": [{"type": "cast_int"}]})
        assert fm.sources == ["$.port"]
        assert not fm.collect_all
        assert len(fm.transform) == 1
        assert fm.transform[0].type == "cast_int"

    def test_dict_sources_first_non_null(self):
        fm = parse_field_mapping({"sources": ["$.matched-at", "$.url"]})
        assert fm.sources == ["$.matched-at", "$.url"]
        assert not fm.collect_all

    def test_dict_source_list_collect_all(self):
        fm = parse_field_mapping({"source": ["$.service.product", "$.service.extrainfo"]})
        assert fm.sources == ["$.service.product", "$.service.extrainfo"]
        assert fm.collect_all

    def test_dict_with_static(self):
        fm = parse_field_mapping({"source": ["$.DetectorName"], "static": ["secret", "credential"]})
        assert fm.collect_all
        assert fm.static == ["secret", "credential"]


# ---------------------------------------------------------------------------
# load_adapter / has_adapter
# ---------------------------------------------------------------------------

class TestAdapterLoader:
    def setup_method(self):
        clear_cache()

    def test_load_nuclei(self):
        config = load_adapter("nuclei")
        assert config.scanner == "nuclei"
        assert config.extraction.mode == "flat"

    def test_load_invicti(self):
        config = load_adapter("invicti")
        assert config.scanner == "invicti"
        assert config.extraction.mode == "nested_join"
        assert "location" in config.extraction.lookups

    def test_load_trufflehog(self):
        config = load_adapter("trufflehog")
        assert config.scanner == "trufflehog"
        assert config.finding_type_default == "secret"

    def test_load_nmap(self):
        config = load_adapter("nmap")
        assert config.scanner == "nmap"
        assert config.finding_type_default == "port_service"

    def test_load_burp(self):
        config = load_adapter("burp")
        assert config.scanner == "burp"
        assert config.extraction.mode == "envelope"

    def test_missing_adapter_raises(self):
        with pytest.raises(AdapterConfigError, match="No adapter config found"):
            load_adapter("nonexistent_scanner_xyz")

    def test_has_adapter_true(self):
        assert has_adapter("nuclei") is True

    def test_has_adapter_false(self):
        assert has_adapter("nonexistent_scanner_xyz") is False


# ---------------------------------------------------------------------------
# Extractor — flat mode (Nuclei JSON array)
# ---------------------------------------------------------------------------

class TestExtractorNucleiFlatJsonArray:
    def test_yields_correct_count(self):
        config = _nuclei_config()
        findings = list(extract_findings(FIXTURES / "nuclei_sample.json", config))
        assert len(findings) == 4

    def test_each_finding_has_host(self):
        config = _nuclei_config()
        for finding in extract_findings(FIXTURES / "nuclei_sample.json", config):
            assert "host" in finding

    def test_first_finding_is_log4j(self):
        config = _nuclei_config()
        first = next(extract_findings(FIXTURES / "nuclei_sample.json", config))
        assert first["template-id"] == "cve-2021-44228"


# ---------------------------------------------------------------------------
# Extractor — flat mode (Nuclei JSONL)
# ---------------------------------------------------------------------------

class TestExtractorNucleiFlatJsonl:
    def test_yields_correct_count(self):
        config = _nuclei_config()
        findings = list(extract_findings(FIXTURES / "nuclei_sample.jsonl", config))
        assert len(findings) == 3

    def test_all_have_template_id(self):
        config = _nuclei_config()
        for f in extract_findings(FIXTURES / "nuclei_sample.jsonl", config):
            assert "template-id" in f


# ---------------------------------------------------------------------------
# Extractor — nested_join mode (Invicti)
# ---------------------------------------------------------------------------

class TestExtractorInvictiNestedJoin:
    def test_yields_correct_count(self):
        config = _invicti_config()
        # The invicti sample has 3 vulnerability_types
        findings = list(extract_findings(FIXTURES / "invicti_sample.json", config))
        assert len(findings) == 3

    def test_context_injected(self):
        config = _invicti_config()
        findings = list(extract_findings(FIXTURES / "invicti_sample.json", config))
        for f in findings:
            assert "ctx_scan_host" in f
            assert f["ctx_scan_host"] == "https://shop.example.com"

    def test_lookup_injected(self):
        config = _invicti_config()
        findings = list(extract_findings(FIXTURES / "invicti_sample.json", config))
        # First finding has loc_id=1 → location url should be joined
        first = findings[0]
        assert "lkp_location_url" in first
        assert "shop.example.com" in first["lkp_location_url"]

    def test_all_findings_have_distinct_locations(self):
        config = _invicti_config()
        findings = list(extract_findings(FIXTURES / "invicti_sample.json", config))
        urls = [f.get("lkp_location_url") for f in findings]
        assert len(set(urls)) == 3  # 3 distinct URLs


# ---------------------------------------------------------------------------
# Mapper — Nuclei findings
# ---------------------------------------------------------------------------

class TestMapperNuclei:
    def test_cve_finding_type_vulnerability(self):
        config = _nuclei_config()
        raw = {
            "template-id": "cve-2021-44228",
            "info": {"name": "Log4Shell", "severity": "critical", "tags": ["cve", "rce"]},
            "host": "example.com",
            "matched-at": "https://example.com/api",
        }
        finding = map_finding(raw, config, source_file="test.json")
        assert finding.finding_type == "vulnerability"
        assert finding.severity == SeverityLevel.CRITICAL
        assert finding.identity.standardized_rule_id == "CVE-2021-44228"
        assert finding.target.host_normalized == "example.com"

    def test_standardized_rule_id_non_cve(self):
        config = _nuclei_config()
        raw = {
            "template-id": "http/exposures/configs/nginx-config",
            "info": {"name": "Nginx Config Exposure", "severity": "medium", "tags": ["exposure"]},
            "host": "example.com",
            "matched-at": "https://example.com/nginx.conf",
        }
        finding = map_finding(raw, config, source_file="test.json")
        assert finding.identity.standardized_rule_id.startswith("nuclei:")

    def test_exposure_finding_type(self):
        config = _nuclei_config()
        raw = {
            "template-id": "aws-env-exposure",
            "info": {"name": "AWS Env Exposure", "severity": "critical", "tags": ["exposure", "aws"]},
            "host": "admin.example.com",
            "matched-at": "https://admin.example.com/.env",
        }
        finding = map_finding(raw, config, source_file="test.json")
        assert finding.finding_type == "exposure"

    def test_misconfig_finding_type(self):
        config = _nuclei_config()
        raw = {
            "template-id": "cors-misconfig",
            "info": {"name": "CORS Misconfiguration", "severity": "medium", "tags": ["misconfig", "cors"]},
            "host": "api.example.com",
            "matched-at": "https://api.example.com/v1/data",
        }
        finding = map_finding(raw, config, source_file="test.json")
        assert finding.finding_type == "misconfiguration"

    def test_ssl_finding_type(self):
        config = _nuclei_config()
        raw = {
            "template-id": "ssl-tls-version",
            "info": {"name": "Weak TLS", "severity": "low", "tags": ["ssl", "tls"]},
            "host": "example.com",
            "matched-at": "https://example.com:443",
        }
        finding = map_finding(raw, config, source_file="test.json")
        assert finding.finding_type == "ssl_finding"

    def test_fingerprint_is_deterministic(self):
        config = _nuclei_config()
        raw = {
            "template-id": "cve-2021-44228",
            "info": {"name": "Log4Shell", "severity": "critical", "tags": ["cve"]},
            "host": "example.com",
            "matched-at": "https://example.com/api/v1",
        }
        fp1 = map_finding(raw, config).fingerprint
        fp2 = map_finding(raw, config).fingerprint
        assert fp1 == fp2
        assert fp1.startswith("sha256:")

    def test_fingerprint_differs_by_url_path(self):
        config = _nuclei_config()
        base = {
            "template-id": "cve-2021-44228",
            "info": {"name": "Log4Shell", "severity": "critical", "tags": ["cve"]},
            "host": "example.com",
        }
        r1 = {**base, "matched-at": "https://example.com/login"}
        r2 = {**base, "matched-at": "https://example.com/admin"}
        assert map_finding(r1, config).fingerprint != map_finding(r2, config).fingerprint

    def test_fingerprint_same_for_same_path_different_query(self):
        config = _nuclei_config()
        base = {
            "template-id": "sqli",
            "info": {"name": "SQLi", "severity": "high", "tags": ["sqli"]},
            "host": "example.com",
        }
        r1 = {**base, "matched-at": "https://example.com/search?q=a"}
        r2 = {**base, "matched-at": "https://example.com/search?q=b"}
        assert map_finding(r1, config).fingerprint == map_finding(r2, config).fingerprint

    def test_discovery_tools_set_to_scanner_name(self):
        config = _nuclei_config()
        raw = {
            "template-id": "test",
            "info": {"name": "Test", "severity": "low", "tags": ["test"]},
            "host": "example.com",
            "matched-at": "https://example.com/",
        }
        finding = map_finding(raw, config)
        assert "nuclei" in finding.discovery_tools

    def test_tags_populated(self):
        config = _nuclei_config()
        raw = {
            "template-id": "cve-2021-44228",
            "info": {"name": "Log4Shell", "severity": "critical", "tags": ["cve", "rce", "log4j"]},
            "host": "example.com",
            "matched-at": "https://example.com/api",
        }
        finding = map_finding(raw, config)
        assert "cve" in finding.tags
        assert "rce" in finding.tags

    def test_required_fields_validation_fails(self):
        config = _nuclei_config()
        # Missing host / matched-at → hostname will be None
        raw = {
            "template-id": "cve-2021-44228",
            "info": {"name": "Log4Shell", "severity": "critical", "tags": ["cve"]},
            # "host" intentionally omitted
        }
        with pytest.raises(ValidationError) as exc_info:
            map_finding(raw, config)
        assert "target.hostname" in exc_info.value.missing

    def test_status_is_open(self):
        config = _nuclei_config()
        raw = {
            "template-id": "test",
            "info": {"name": "Test", "severity": "info", "tags": ["test"]},
            "host": "example.com",
            "matched-at": "https://example.com/",
        }
        finding = map_finding(raw, config)
        assert finding.status == "Open"


# ---------------------------------------------------------------------------
# Mapper — Invicti (nested_join + integer severity)
# ---------------------------------------------------------------------------

class TestMapperInvicti:
    def test_three_findings_from_sample(self):
        config = _invicti_config()
        results = []
        for i, raw in enumerate(extract_findings(FIXTURES / "invicti_sample.json", config)):
            results.append(map_finding(raw, config, finding_index=i))
        assert len(results) == 3

    def test_integer_severity_high(self):
        config = _invicti_config()
        findings = list(extract_findings(FIXTURES / "invicti_sample.json", config))
        # SQLi has severity=4 (critical) in fixture
        sqli_raw = findings[1]  # loc_id=2 = SQLi
        f = map_finding(sqli_raw, config)
        assert f.severity == SeverityLevel.CRITICAL

    def test_hostname_extracted_from_context(self):
        config = _invicti_config()
        findings = list(extract_findings(FIXTURES / "invicti_sample.json", config))
        f = map_finding(findings[0], config)
        assert f.target.hostname == "shop.example.com"

    def test_standardized_rule_id_prefixed(self):
        config = _invicti_config()
        findings = list(extract_findings(FIXTURES / "invicti_sample.json", config))
        f = map_finding(findings[0], config)
        assert f.identity.standardized_rule_id.startswith("invicti:")

    def test_three_distinct_fingerprints(self):
        config = _invicti_config()
        fps = set()
        for i, raw in enumerate(extract_findings(FIXTURES / "invicti_sample.json", config)):
            fps.add(map_finding(raw, config, finding_index=i).fingerprint)
        assert len(fps) == 3


# ---------------------------------------------------------------------------
# Mapper — TruffleHog (secret redaction)
# ---------------------------------------------------------------------------

class TestMapperTrufflehog:
    def test_two_findings_from_sample(self):
        config = _trufflehog_config()
        findings = list(extract_findings(FIXTURES / "trufflehog_sample.jsonl", config))
        results = [map_finding(f, config, finding_index=i) for i, f in enumerate(findings)]
        assert len(results) == 2

    def test_finding_type_is_secret(self):
        config = _trufflehog_config()
        findings = list(extract_findings(FIXTURES / "trufflehog_sample.jsonl", config))
        f = map_finding(findings[0], config)
        assert f.finding_type == "secret"

    def test_severity_is_high(self):
        config = _trufflehog_config()
        findings = list(extract_findings(FIXTURES / "trufflehog_sample.jsonl", config))
        f = map_finding(findings[0], config)
        assert f.severity == SeverityLevel.HIGH

    def test_raw_does_not_contain_secret_value(self):
        config = _trufflehog_config()
        findings = list(extract_findings(FIXTURES / "trufflehog_sample.jsonl", config))
        f = map_finding(findings[0], config)
        assert f.evidence is not None
        raw_json = json.dumps(f.evidence.raw)
        assert "AKIAIOSFODNN7EXAMPLE" not in raw_json
        # Raw and RawV2 keys should be omitted
        assert "Raw" not in f.evidence.raw
        assert "RawV2" not in f.evidence.raw

    def test_standardized_rule_id_prefixed(self):
        config = _trufflehog_config()
        findings = list(extract_findings(FIXTURES / "trufflehog_sample.jsonl", config))
        f = map_finding(findings[0], config)
        assert f.identity.standardized_rule_id.startswith("trufflehog:")

    def test_tags_include_static_values(self):
        config = _trufflehog_config()
        findings = list(extract_findings(FIXTURES / "trufflehog_sample.jsonl", config))
        f = map_finding(findings[0], config)
        assert "secret" in f.tags
        assert "credential" in f.tags


# ---------------------------------------------------------------------------
# End-to-end: process entire nuclei sample file
# ---------------------------------------------------------------------------

class TestEndToEndNuclei:
    def test_all_json_array_findings_map_successfully(self):
        config = _nuclei_config()
        findings = []
        for i, raw in enumerate(extract_findings(FIXTURES / "nuclei_sample.json", config)):
            findings.append(map_finding(raw, config, source_file="nuclei_sample.json", finding_index=i))
        assert len(findings) == 4
        assert all(isinstance(f, UniversalFinding) for f in findings)

    def test_all_jsonl_findings_map_successfully(self):
        config = _nuclei_config()
        findings = []
        for i, raw in enumerate(extract_findings(FIXTURES / "nuclei_sample.jsonl", config)):
            findings.append(map_finding(raw, config, source_file="nuclei_sample.jsonl", finding_index=i))
        assert len(findings) == 3
        assert all(isinstance(f, UniversalFinding) for f in findings)

    def test_schema_version_is_2(self):
        config = _nuclei_config()
        raw = next(extract_findings(FIXTURES / "nuclei_sample.json", config))
        f = map_finding(raw, config)
        assert f.schema_version == 2

    def test_source_file_stored(self):
        config = _nuclei_config()
        raw = next(extract_findings(FIXTURES / "nuclei_sample.json", config))
        f = map_finding(raw, config, source_file="my_scan.json")
        assert f.source_file == "my_scan.json"

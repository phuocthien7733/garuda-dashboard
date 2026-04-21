"""
Unit tests — Phase 1: UDM enums, models, fingerprint, jsonpath_utils.

Run:
    docker compose exec worker pytest tests/test_phase1_udm.py -v
"""
import pytest
from datetime import datetime, timezone

from app.udm.enums import (
    SeverityLevel,
    SEVERITY_RANK,
    normalize_severity,
    resolve_severity_max,
)
from app.udm.models import (
    UDMTarget,
    UDMIdentity,
    UDMEvidence,
    UniversalFinding,
)
from app.udm.fingerprint import build_fingerprint
from app.core.jsonpath_utils import extract, extract_all
from app.core.host_classification import extract_apex_domain


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


def _make_target(**kwargs) -> UDMTarget:
    defaults = dict(hostname="example.com", ip="1.2.3.4", port=443, protocol="tcp")
    defaults.update(kwargs)
    t = UDMTarget(**defaults)
    t.host_normalized = t.compute_host_normalized()
    return t


def _make_identity(**kwargs) -> UDMIdentity:
    defaults = dict(
        standardized_rule_id="CVE-2021-44228",
        raw_rule_id="cves/2021/CVE-2021-44228.yaml",
        name="Log4Shell",
        category="rce",
    )
    defaults.update(kwargs)
    return UDMIdentity(**defaults)


# ---------------------------------------------------------------------------
# SeverityLevel / SEVERITY_RANK
# ---------------------------------------------------------------------------

class TestSeverityEnum:
    def test_rank_ordering(self):
        assert SEVERITY_RANK[SeverityLevel.CRITICAL] > SEVERITY_RANK[SeverityLevel.HIGH]
        assert SEVERITY_RANK[SeverityLevel.HIGH]     > SEVERITY_RANK[SeverityLevel.MEDIUM]
        assert SEVERITY_RANK[SeverityLevel.MEDIUM]   > SEVERITY_RANK[SeverityLevel.LOW]
        assert SEVERITY_RANK[SeverityLevel.LOW]      > SEVERITY_RANK[SeverityLevel.INFO]
        assert SEVERITY_RANK[SeverityLevel.INFO]     > SEVERITY_RANK[SeverityLevel.UNKNOWN]

    def test_normalize_standard_values(self):
        assert normalize_severity("critical") == SeverityLevel.CRITICAL
        assert normalize_severity("HIGH")     == SeverityLevel.HIGH
        assert normalize_severity("  medium") == SeverityLevel.MEDIUM
        assert normalize_severity("low")      == SeverityLevel.LOW
        assert normalize_severity("info")     == SeverityLevel.INFO

    def test_normalize_aliases(self):
        assert normalize_severity("informational") == SeverityLevel.INFO
        assert normalize_severity("warning")       == SeverityLevel.LOW
        assert normalize_severity("moderate")      == SeverityLevel.MEDIUM
        assert normalize_severity("important")     == SeverityLevel.HIGH
        assert normalize_severity("crit")          == SeverityLevel.CRITICAL

    def test_normalize_unknown_fallback(self):
        assert normalize_severity(None)            == SeverityLevel.UNKNOWN
        assert normalize_severity("")              == SeverityLevel.UNKNOWN
        assert normalize_severity("garbage_value") == SeverityLevel.UNKNOWN

    def test_resolve_severity_max(self):
        assert resolve_severity_max(SeverityLevel.CRITICAL, SeverityLevel.HIGH) == SeverityLevel.CRITICAL
        assert resolve_severity_max(SeverityLevel.LOW,      SeverityLevel.HIGH) == SeverityLevel.HIGH
        assert resolve_severity_max(SeverityLevel.MEDIUM,   SeverityLevel.MEDIUM) == SeverityLevel.MEDIUM


# ---------------------------------------------------------------------------
# UDMTarget.compute_host_normalized
# ---------------------------------------------------------------------------

class TestUDMTargetNormalized:
    def test_hostname_subdomain_keeps_full_hostname(self):
        """Each subdomain is its own distinct asset — full hostname is returned."""
        t = UDMTarget(hostname="api.example.com")
        assert t.compute_host_normalized() == "api.example.com"

    def test_hostname_already_apex(self):
        t = UDMTarget(hostname="example.com")
        assert t.compute_host_normalized() == "example.com"

    def test_url_fallback(self):
        t = UDMTarget(url="https://sub.example.org/path?q=1")
        assert t.compute_host_normalized() == "sub.example.org"

    def test_ip_fallback(self):
        t = UDMTarget(ip="10.0.0.1")
        assert t.compute_host_normalized() == "10.0.0.1"

    def test_empty_fallback(self):
        t = UDMTarget()
        assert t.compute_host_normalized() == "unknown"

    def test_compute_apex_domain_returns_parent(self):
        """compute_apex_domain returns the apex for grouping, None when host is already apex."""
        t = UDMTarget(hostname="api.example.com")
        assert t.compute_apex_domain() == "example.com"

    def test_compute_apex_domain_none_for_apex(self):
        t = UDMTarget(hostname="example.com")
        assert t.compute_apex_domain() is None

    def test_compute_apex_domain_none_for_ip(self):
        t = UDMTarget(ip="1.2.3.4")
        assert t.compute_apex_domain() is None


# ---------------------------------------------------------------------------
# extract_apex_domain
# ---------------------------------------------------------------------------

class TestExtractApexDomain:
    def test_subdomain(self):
        assert extract_apex_domain("api.sub.example.com") == "example.com"

    def test_apex(self):
        assert extract_apex_domain("example.com") == "example.com"

    def test_ip(self):
        assert extract_apex_domain("192.168.1.1") == "192.168.1.1"

    def test_none(self):
        assert extract_apex_domain(None) == "unknown"

    def test_empty(self):
        assert extract_apex_domain("") == "unknown"


# ---------------------------------------------------------------------------
# build_fingerprint — determinism & distinction
# ---------------------------------------------------------------------------

class TestBuildFingerprint:
    """Test the SHA-256 fingerprint formula matrix from spec §3."""

    def _fp(self, finding_type, target=None, identity=None, evidence=None):
        t = target or _make_target()
        i = identity or _make_identity()
        return build_fingerprint(finding_type, t, i, evidence)

    # --- Determinism ---
    def test_same_input_same_output(self):
        t = _make_target(hostname="example.com", url="https://example.com/login", port=443)
        i = _make_identity(standardized_rule_id="CVE-2021-44228")
        fp1 = build_fingerprint("vulnerability", t, i)
        fp2 = build_fingerprint("vulnerability", t, i)
        assert fp1 == fp2

    # --- Format ---
    def test_starts_with_sha256_prefix(self):
        fp = self._fp("vulnerability")
        assert fp.startswith("sha256:")
        assert len(fp) == len("sha256:") + 64  # 64 hex chars

    # --- Web vs Network distinction for vulnerability ---
    def test_vulnerability_web_uses_url_path(self):
        t_web = _make_target(hostname="example.com", url="https://example.com/login", ip=None)
        t_net = _make_target(hostname=None, url=None, ip="1.2.3.4", port=443, protocol="tcp")
        i = _make_identity()
        fp_web = build_fingerprint("vulnerability", t_web, i)
        fp_net = build_fingerprint("vulnerability", t_net, i)
        assert fp_web != fp_net

    def test_vulnerability_web_different_paths(self):
        i = _make_identity()
        t1 = _make_target(hostname="example.com", url="https://example.com/login")
        t2 = _make_target(hostname="example.com", url="https://example.com/admin")
        assert build_fingerprint("vulnerability", t1, i) != build_fingerprint("vulnerability", t2, i)

    def test_vulnerability_web_same_path_same_fp(self):
        i = _make_identity()
        t1 = _make_target(hostname="example.com", url="https://example.com/login?a=1")
        t2 = _make_target(hostname="example.com", url="https://example.com/login?b=2")
        # query strings stripped → same fingerprint
        assert build_fingerprint("vulnerability", t1, i) == build_fingerprint("vulnerability", t2, i)

    # --- port_service ---
    def test_port_service_uses_ip_port_proto(self):
        t = _make_target(ip="1.2.3.4", port=22, protocol="tcp", hostname=None, url=None)
        i = _make_identity()
        fp = build_fingerprint("port_service", t, i)
        assert fp.startswith("sha256:")

    def test_port_service_different_ports(self):
        i = _make_identity()
        t22  = _make_target(ip="1.2.3.4", port=22,  protocol="tcp", hostname=None, url=None)
        t443 = _make_target(ip="1.2.3.4", port=443, protocol="tcp", hostname=None, url=None)
        assert build_fingerprint("port_service", t22, i) != build_fingerprint("port_service", t443, i)

    # --- ssl_finding ---
    def test_ssl_finding(self):
        t = _make_target(hostname="example.com", port=443, url=None, ip=None)
        i = _make_identity(standardized_rule_id="ssl:cert-expired")
        fp = build_fingerprint("ssl_finding", t, i)
        assert fp.startswith("sha256:")

    # --- dns_finding ---
    def test_dns_finding(self):
        t = _make_target(hostname="sub.example.com", url=None, ip=None)
        i = _make_identity(category="dns_takeover")
        fp = build_fingerprint("dns_finding", t, i)
        assert fp.startswith("sha256:")

    # --- secret ---
    def test_secret_uses_evidence_fields(self):
        t = _make_target(url="https://github.com/org/repo", hostname=None, ip=None)
        i = _make_identity(standardized_rule_id="trufflehog:AWS")
        ev = UDMEvidence(
            repo_url="https://github.com/org/repo",
            file_path="config/prod.env",
            line_number=42,
        )
        fp = build_fingerprint("secret", t, i, ev)
        assert fp.startswith("sha256:")

    def test_secret_different_lines_different_fp(self):
        t  = _make_target(url="https://github.com/org/repo", hostname=None, ip=None)
        i  = _make_identity(standardized_rule_id="trufflehog:AWS")
        ev1 = UDMEvidence(repo_url="https://github.com/org/repo", file_path="a.env", line_number=1)
        ev2 = UDMEvidence(repo_url="https://github.com/org/repo", file_path="a.env", line_number=2)
        assert build_fingerprint("secret", t, i, ev1) != build_fingerprint("secret", t, i, ev2)

    # --- exposure / misconfiguration ---
    def test_exposure_and_misconfig_distinct_from_vuln(self):
        t = _make_target(hostname="example.com", url="https://example.com/admin")
        i = _make_identity()
        fp_vuln   = build_fingerprint("vulnerability",    t, i)
        fp_exp    = build_fingerprint("exposure",         t, i)
        fp_miscon = build_fingerprint("misconfiguration", t, i)
        assert len({fp_vuln, fp_exp, fp_miscon}) == 3

    # --- asset_discovery ---
    def test_asset_discovery(self):
        t = _make_target(hostname="example.com")
        t.host_normalized = t.compute_host_normalized()
        i = _make_identity()
        fp = build_fingerprint("asset_discovery", t, i)
        assert fp.startswith("sha256:")

    # --- Unknown type raises ---
    def test_unknown_type_raises(self):
        t = _make_target()
        i = _make_identity()
        with pytest.raises(ValueError, match="Unknown finding_type"):
            build_fingerprint("not_a_type", t, i)


# ---------------------------------------------------------------------------
# jsonpath_utils
# ---------------------------------------------------------------------------

class TestJsonpathUtils:
    OBJ = {
        "info": {
            "name": "Log4Shell",
            "severity": "critical",
            "tags": ["cve", "rce", "log4j"],
            "classification": {
                "cve-id": ["CVE-2021-44228"],
                "cvss-score": 10.0,
            },
        },
        "host": "example.com",
        "port": 8080,
        "nested": [{"id": 1}, {"id": 2}],
    }

    def test_extract_simple(self):
        assert extract(self.OBJ, "$.host") == "example.com"

    def test_extract_nested(self):
        assert extract(self.OBJ, "$.info.severity") == "critical"

    def test_extract_deep_nested(self):
        assert extract(self.OBJ, "$.info.classification.cvss-score") == 10.0

    def test_extract_missing_key(self):
        assert extract(self.OBJ, "$.does_not_exist") is None

    def test_extract_array_first(self):
        assert extract(self.OBJ, "$.info.tags[0]") == "cve"

    def test_extract_all_array(self):
        result = extract_all(self.OBJ, "$.info.tags[*]")
        assert result == ["cve", "rce", "log4j"]

    def test_extract_all_nested_ids(self):
        result = extract_all(self.OBJ, "$.nested[*].id")
        assert result == [1, 2]

    def test_extract_none_object(self):
        assert extract(None, "$.host") is None

    def test_extract_all_none_object(self):
        assert extract_all(None, "$.info.tags[*]") == []

    def test_extract_invalid_path(self):
        # Invalid JSONPath should not raise — returns None gracefully
        assert extract(self.OBJ, "INVALID[[[") is None

    def test_extract_all_invalid_path(self):
        assert extract_all(self.OBJ, "INVALID[[[") == []

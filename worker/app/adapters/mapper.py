from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from app.adapters.base import (
    AdapterConfig,
    FieldMapping,
    FindingTypeRule,
    Transform,
    parse_field_mapping,
)
from app.core.host_classification import classify_host_type, extract_apex_domain
from app.core.jsonpath_utils import extract, extract_all
from app.udm.enums import SeverityLevel, normalize_severity
from app.udm.fingerprint import build_fingerprint
from app.udm.models import (
    UDMEvidence,
    UDMIdentity,
    UDMTarget,
    UniversalFinding,
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class ValidationError(Exception):
    """Raised when required_fields check fails after mapping."""
    def __init__(self, missing: list[str], finding_index: int = 0):
        self.missing = missing
        self.finding_index = finding_index
        super().__init__(f"Missing required fields: {missing}")


def map_finding(
    raw: dict,
    config: AdapterConfig,
    source_file: str = "",
    finding_index: int = 0,
) -> UniversalFinding:
    """
    Map a raw scanner finding dict → UniversalFinding using the adapter config.

    Raises:
        ValidationError — if any required_fields are None after mapping.
    """
    # Step 1: resolve all field mappings → flat dotted-key dict
    resolved: dict[str, Any] = {}
    for field_path, raw_mapping in config.mappings.items():
        mapping = parse_field_mapping(raw_mapping)
        resolved[field_path] = _resolve_mapping(raw, mapping)

    # Step 2: convert flat dotted keys → nested dict
    nested = _to_nested(resolved)

    # Step 3: required_fields validation
    if config.required_fields:
        missing = _check_required(nested, config.required_fields)
        if missing:
            raise ValidationError(missing, finding_index)

    # Step 4: determine finding_type
    finding_type = _resolve_finding_type(
        config.finding_type_default,
        config.finding_type_rules,
        nested,
    )

    # Step 5: build UDM sub-models
    target   = _build_target(nested.get("target") or {})
    identity = _build_identity(nested.get("identity") or {})
    evidence = _build_evidence(nested.get("evidence") or {}, config)

    # Step 6: normalize severity (handles int and string forms)
    severity = _resolve_severity(nested.get("severity"))

    # Step 7: compute fingerprint
    fingerprint = build_fingerprint(finding_type, target, identity, evidence)

    now = datetime.now(tz=timezone.utc)

    return UniversalFinding(
        fingerprint=fingerprint,
        finding_type=finding_type,
        target=target,
        identity=identity,
        evidence=evidence,
        severity=severity,
        first_seen=now,
        last_seen=now,
        source_tool_first=config.scanner,
        discovery_tools=[config.scanner],
        tags=_as_str_list(nested.get("tags")),
        references=_as_str_list(nested.get("references")),
        source_file=source_file,
    )


# ---------------------------------------------------------------------------
# Mapping resolution
# ---------------------------------------------------------------------------

def _resolve_mapping(raw: dict, mapping: FieldMapping) -> Any:
    """Evaluate a FieldMapping against a raw finding dict."""
    if not mapping.sources and mapping.static is None:
        return None

    dynamic: Any = None

    if mapping.sources:
        if mapping.collect_all:
            # Collect values from ALL sources
            collected: list[Any] = []
            for src in mapping.sources:
                val = _eval_source(raw, src)
                if isinstance(val, list):
                    collected.extend(v for v in val if v is not None)
                elif val is not None:
                    collected.append(val)
            dynamic = collected if collected else None
        else:
            # First non-null wins
            for src in mapping.sources:
                val = _eval_source(raw, src)
                if val is not None:
                    dynamic = val
                    break

    # Apply transform pipeline
    value = dynamic
    for transform in mapping.transform:
        value = _apply_transform(value, transform, raw)

    # Merge with static values
    if mapping.static is not None:
        if isinstance(value, list):
            # Append static items that are not already present
            extra = [s for s in mapping.static if s not in value]
            value = value + extra
        elif value is None:
            value = mapping.static
        else:
            # scalar + static list
            value = [value] + [s for s in mapping.static if s != value]

    return value


def _eval_source(raw: dict, source: str) -> Any:
    """
    Evaluate a single source string:
    - Static: starts and ends with single quote → return inner string
    - JSONPath: anything else
    """
    if source.startswith("'") and source.endswith("'") and len(source) >= 2:
        return source[1:-1]
    return extract(raw, source)


# ---------------------------------------------------------------------------
# Transform pipeline
# ---------------------------------------------------------------------------

def _apply_transform(value: Any, transform: Transform, raw: dict) -> Any:  # noqa: C901
    """Apply one transform step. Returns transformed value."""
    t = transform.type

    if t == "passthrough":
        return value

    if t == "integer_map":
        if value is None:
            return None
        try:
            key = int(value)
            return (transform.map or {}).get(key, "unknown")
        except (TypeError, ValueError):
            return "unknown"

    if t == "string_map":
        if value is None:
            return None
        return (transform.map or {}).get(str(value).lower(), str(value))

    if t == "regex_extract":
        str_val = str(value) if value is not None else None
        pattern = transform.pattern

        if str_val and pattern:
            m = re.search(pattern, str_val)
            if m:
                result = m.group(transform.group)
                if transform.uppercase_match:
                    result = result.upper()
                if transform.prefix:
                    result = f"{transform.prefix}{result}"
                return result

        # No match or no value — use fallback
        if transform.fallback_source:
            fb = _eval_source(raw, transform.fallback_source)
            if fb is not None:
                fb_str = str(fb)
                if transform.fallback_prefix:
                    return f"{transform.fallback_prefix}{fb_str}"
                return fb_str

        if str_val is not None and transform.fallback_prefix:
            return f"{transform.fallback_prefix}{str_val}"

        return str_val

    if t == "regex_replace":
        if value is None:
            return None
        return re.sub(
            transform.pattern or "",
            transform.replacement or "",
            str(value),
        )

    if t == "filter_by_prefix":
        if not isinstance(value, list):
            return []
        pfx = transform.prefix or ""
        return [v for v in value if isinstance(v, str) and v.startswith(pfx)]

    if t == "filter_empty":
        if not isinstance(value, list):
            return [value] if value else []
        return [v for v in value if v is not None and v != ""]

    if t == "cast_int":
        if value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    if t == "cast_str":
        return str(value) if value is not None else None

    if t == "split":
        if value is None:
            return []
        return str(value).split(transform.delimiter)

    if t == "join":
        if isinstance(value, list):
            return transform.delimiter.join(str(v) for v in value if v is not None)
        return str(value) if value is not None else None

    if t == "slugify":
        if value is None:
            return None
        slug = re.sub(r"[^a-z0-9]+", "-", str(value).lower()).strip("-")
        if transform.prefix:
            slug = f"{transform.prefix}{slug}"
        return slug

    if t == "strip_scheme":
        if value is None:
            return None
        try:
            p = urlparse(str(value))
            return (p.netloc + p.path).lstrip("/")
        except Exception:
            return value

    if t == "url_path_only":
        if value is None:
            return None
        try:
            return urlparse(str(value)).path
        except Exception:
            return value

    if t == "url_hostname_only":
        if value is None:
            return None
        try:
            return urlparse(str(value)).hostname or value
        except Exception:
            return value

    if t == "url_port_only":
        if value is None:
            return None
        try:
            port = urlparse(str(value)).port
            return int(port) if port else None
        except Exception:
            return None

    if t == "url_scheme_only":
        if value is None:
            return None
        try:
            return urlparse(str(value)).scheme or None
        except Exception:
            return None

    if t == "omit_keys":
        if not isinstance(value, dict):
            return value
        return {k: v for k, v in value.items() if k not in (transform.keys or [])}

    if t == "upper":
        return str(value).upper() if value is not None else None

    if t == "lower":
        return str(value).lower() if value is not None else None

    # Unknown transform — pass through unchanged
    return value


# ---------------------------------------------------------------------------
# Nested dict builder
# ---------------------------------------------------------------------------

def _to_nested(flat: dict[str, Any]) -> dict[str, Any]:
    """
    Convert flat dotted-key dict to nested dict.
    {"target.hostname": "example.com"} → {"target": {"hostname": "example.com"}}
    """
    nested: dict = {}
    for key, value in flat.items():
        parts = key.split(".")
        d = nested
        for part in parts[:-1]:
            if part not in d or not isinstance(d[part], dict):
                d[part] = {}
            d = d[part]
        d[parts[-1]] = value
    return nested


# ---------------------------------------------------------------------------
# Required fields check
# ---------------------------------------------------------------------------

def _check_required(nested: dict, required: list[str]) -> list[str]:
    """Return list of field paths that are missing (None) after mapping."""
    missing = []
    for field_path in required:
        val = nested
        for part in field_path.split("."):
            if isinstance(val, dict):
                val = val.get(part)
            else:
                val = None
                break
        if val is None:
            missing.append(field_path)
    return missing


# ---------------------------------------------------------------------------
# Finding type resolution
# ---------------------------------------------------------------------------

def _resolve_finding_type(
    default: str,
    rules: list[FindingTypeRule],
    nested: dict,
) -> str:
    """Evaluate finding_type_rules in order; first match wins."""
    tags_lower = [t.lower() for t in _as_str_list(nested.get("tags"))]
    category   = str((nested.get("identity") or {}).get("category") or "").lower()
    name       = str((nested.get("identity") or {}).get("name")     or "").lower()

    for rule in rules:
        # default rule — always matches; must be last
        if rule.default is not None:
            return rule.default

        if rule.set_type is None:
            continue

        if rule.if_tag_contains and any(
            t.lower() in tags_lower for t in rule.if_tag_contains
        ):
            return rule.set_type

        if rule.if_category_equals and category in [
            c.lower() for c in rule.if_category_equals
        ]:
            return rule.set_type

        if rule.if_name_contains and any(
            s.lower() in name for s in rule.if_name_contains
        ):
            return rule.set_type

    return default


# ---------------------------------------------------------------------------
# UDM sub-model builders
# ---------------------------------------------------------------------------

def _build_target(data: dict) -> UDMTarget:
    t = UDMTarget(
        ip=data.get("ip") or None,
        hostname=data.get("hostname") or None,
        url=data.get("url") or None,
        port=_as_int(data.get("port")),
        protocol=data.get("protocol") or None,
        path=data.get("path") or None,
    )
    t.host_normalized = t.compute_host_normalized()
    return t


def _build_identity(data: dict) -> UDMIdentity:
    return UDMIdentity(
        standardized_rule_id=str(data.get("standardized_rule_id") or "unknown"),
        raw_rule_id=str(data.get("raw_rule_id") or "unknown"),
        name=str(data.get("name") or "unknown"),
        category=str(data.get("category") or "unknown"),
        cve=_as_str_list(data.get("cve")),
        cwe=_as_str_list(data.get("cwe")),
        cvss_score=_as_float(data.get("cvss_score")),
        cvss_vector=data.get("cvss_vector") or None,
    )


def _build_evidence(data: dict, config: AdapterConfig) -> UDMEvidence | None:
    """Build UDMEvidence and apply evidence_limits truncation."""
    if not any(v is not None and v != {} and v != [] for v in data.values()):
        return None

    limits   = config.evidence_limits
    response = data.get("response")
    raw      = data.get("raw") or {}

    raw_truncated        = False
    raw_original_size_kb: int | None = None

    # Truncate response body if too large
    if response and isinstance(response, str):
        size_kb = len(response.encode("utf-8")) / 1024
        if size_kb > limits.max_response_size_kb:
            raw_original_size_kb = int(size_kb)
            response = response[: limits.max_response_size_kb * 1024]
            raw_truncated = True

    # Truncate raw dict if too large
    if raw and isinstance(raw, dict):
        raw_json   = json.dumps(raw, default=str)
        raw_size_kb = len(raw_json.encode("utf-8")) / 1024
        if raw_size_kb > limits.max_raw_size_kb:
            if raw_original_size_kb is None:
                raw_original_size_kb = int(raw_size_kb)
            raw = {"_truncated": True, "_original_size_kb": int(raw_size_kb)}
            raw_truncated = True

    return UDMEvidence(
        request=data.get("request") or None,
        response=response or None,
        matched_at=data.get("matched_at") or None,
        extracted=_as_str_list(data.get("extracted")),
        curl_command=data.get("curl_command") or None,
        http_method=data.get("http_method") or None,
        input_type=data.get("input_type") or None,
        input_name=data.get("input_name") or None,
        test_value=data.get("test_value") or None,
        details_template=data.get("details_template") or None,
        details_data=data.get("details_data") or {},
        secret_type=data.get("secret_type") or None,
        secret_raw=data.get("secret_raw") or None,
        repo_url=data.get("repo_url") or None,
        commit_hash=data.get("commit_hash") or None,
        file_path=data.get("file_path") or None,
        line_number=_as_int(data.get("line_number")),
        raw=raw if isinstance(raw, dict) else {},
        raw_truncated=raw_truncated,
        raw_original_size_kb=raw_original_size_kb,
    )


# ---------------------------------------------------------------------------
# Severity resolution
# ---------------------------------------------------------------------------

def _resolve_severity(raw_severity: Any) -> SeverityLevel:
    """Normalize any severity value (int or str) to SeverityLevel enum."""
    if raw_severity is None:
        return SeverityLevel.UNKNOWN
    if isinstance(raw_severity, int):
        from app.udm.enums import INVICTI_SEVERITY_MAP
        mapped = INVICTI_SEVERITY_MAP.get(raw_severity, "unknown")
        return normalize_severity(mapped)
    return normalize_severity(str(raw_severity))


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _as_str_list(val: Any) -> list[str]:
    if val is None:
        return []
    if isinstance(val, list):
        return [str(v) for v in val if v is not None]
    return [str(val)]


def _as_int(val: Any) -> int | None:
    if val is None:
        return None
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


def _as_float(val: Any) -> float | None:
    if val is None:
        return None
    try:
        return float(val)
    except (TypeError, ValueError):
        return None

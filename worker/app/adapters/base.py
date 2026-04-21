from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict


# ---------------------------------------------------------------------------
# Transform
# ---------------------------------------------------------------------------

class Transform(BaseModel):
    """One step in a field mapping transform pipeline."""
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    type: str

    # integer_map / string_map
    map: dict | None = None

    # regex_extract / regex_replace
    pattern: str | None = None
    group: int = 1
    replacement: str | None = None
    uppercase_match: bool = False   # if True, .upper() the captured group

    # prefix for slugify, regex_extract
    prefix: str | None = None

    # regex_extract fallback when pattern has no match
    fallback_source: str | None = None
    fallback_prefix: str | None = None

    # filter_by_prefix reuses prefix field above

    # split / join delimiter
    delimiter: str = ","

    # omit_keys
    keys: list[str] = []


# ---------------------------------------------------------------------------
# FieldMapping
# ---------------------------------------------------------------------------

class FieldMapping(BaseModel):
    """Represents one field mapping after parsing from YAML."""
    model_config = ConfigDict(populate_by_name=True)

    # JSONPath source candidates
    sources: list[str] = []

    # True  → collect values from ALL sources (source: [list] in YAML)
    # False → first non-null wins (sources: [list] in YAML)
    collect_all: bool = False

    # Static values appended/merged with dynamic results
    static: list[Any] | None = None

    # Transform pipeline applied to the resolved value
    transform: list[Transform] = []


# ---------------------------------------------------------------------------
# Sub-configs
# ---------------------------------------------------------------------------

class LookupConfig(BaseModel):
    """Configuration for a JOIN lookup table in nested_join mode."""
    source_path:         str            # JSONPath to all lookup items in the full document
    key_field:           str = ""       # single field primary key (mutually exclusive with compound_key_fields)
    compound_key_fields: list[str] = [] # multi-field compound key: joins values with "|"
    join_on:             str = ""       # JSONPath within each finding to get the join value (single key)
    compound_join_on:    list[str] = [] # JSONPath list for compound key (parallel to compound_key_fields)


class ExtractionConfig(BaseModel):
    """How to extract findings from the scanner report."""
    mode:           str = "flat"    # "flat" | "nested_join" | "envelope"
    findings_path:  str = "$[*]"    # JSONPath to iterate for findings
    lookups:        dict[str, LookupConfig] = {}   # for nested_join
    context_inject: dict[str, str]          = {}   # name → JSONPath (root doc)


class InputConfig(BaseModel):
    """Scanner report file format."""
    format: str = "auto"  # "auto" | "json_array" | "jsonl" | "json_object"


class FindingTypeRule(BaseModel):
    """One conditional rule in the finding_type_rules list."""
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    if_tag_contains:    list[str] | None = None
    if_category_equals: list[str] | None = None
    if_name_contains:   list[str] | None = None
    default:            str | None = None  # fallback type (always matches)
    set_type:           str | None = None  # type to set when this rule matches


class InputValidationConfig(BaseModel):
    """
    Structural fingerprint checks run BEFORE extraction.

    All `required_paths` must resolve to a non-null value in the document;
    if any fail the file is quarantined with reason 'wrong_scanner'.

    Example YAML:
        input_validation:
          required_paths:
            - "$.export.scans[0].info.host"   # Invicti-specific top-level key
          forbidden_paths:
            - "$.template-id"                 # would indicate a Nuclei file
    """
    required_paths: list[str] = []   # paths that MUST exist and be non-null
    forbidden_paths: list[str] = []  # paths that MUST NOT exist (indicate wrong scanner)


class EvidenceLimitsConfig(BaseModel):
    """Controls evidence storage size limits to stay within MongoDB 16 MB doc limit."""
    max_response_size_kb: int  = 512
    skip_binary_content:  bool = True
    binary_types: list[str] = [
        "application/zip",
        "application/octet-stream",
        "application/pdf",
        "application/x-executable",
    ]
    max_raw_size_kb: int = 1024


# ---------------------------------------------------------------------------
# AdapterConfig — root model
# ---------------------------------------------------------------------------

class AdapterConfig(BaseModel):
    """
    Complete adapter configuration loaded from a YAML file.
    `mappings` holds raw YAML values; pass individual values to
    `parse_field_mapping()` to get a typed FieldMapping.
    """
    model_config = ConfigDict(populate_by_name=True)

    scanner:              str
    finding_type_default: str = "vulnerability"
    input:                InputConfig           = InputConfig()
    extraction:           ExtractionConfig
    input_validation:     InputValidationConfig = InputValidationConfig()
    finding_type_rules:   list[FindingTypeRule] = []
    # Raw mappings dict — values are str | list | dict | None
    mappings:             dict[str, Any]        = {}
    required_fields:      list[str]             = []
    evidence_limits:      EvidenceLimitsConfig  = EvidenceLimitsConfig()


# ---------------------------------------------------------------------------
# Error type
# ---------------------------------------------------------------------------

class AdapterConfigError(Exception):
    """Raised when an adapter YAML config is missing or invalid."""


# ---------------------------------------------------------------------------
# parse_field_mapping — normalise raw YAML value → FieldMapping
# ---------------------------------------------------------------------------

def parse_field_mapping(raw: Any) -> FieldMapping:
    """
    Parse a raw YAML mapping value into a FieldMapping object.

    Supported shorthand forms in YAML:
        target.hostname: "$.host"              → single JSONPath source
        tags: ["val1", "val2"]                 → static list literal
        target.hostname: null                  → no-op (value will be None)
        target.hostname:                       → full dict form
          source: "$.host"
          transform: [{type: cast_int}]

    Multi-source variants:
        target.url:                            → first non-null wins
          sources:
            - "$.matched-at"
            - "$.url"
        tags:                                  → collect ALL values from all paths
          source: ["$.service.product", "$.service.extrainfo"]
          static: ["extra_tag"]
    """
    if raw is None:
        return FieldMapping()

    if isinstance(raw, str):
        return FieldMapping(sources=[raw])

    if isinstance(raw, list):
        # Bare YAML list = static list literal
        return FieldMapping(static=[v for v in raw if v is not None])

    if isinstance(raw, dict):
        d = dict(raw)
        sources:     list[str] = []
        collect_all: bool      = False
        static_val             = d.pop("static", None)
        transforms_raw         = d.pop("transform", [])

        if "sources" in d:
            # Ordered aliases — first non-null wins
            sources     = list(d.pop("sources"))
            collect_all = False
        elif "source" in d:
            src = d.pop("source")
            if isinstance(src, list):
                # Collect-all from multiple paths
                sources     = list(src)
                collect_all = True
            else:
                sources     = [str(src)]
                collect_all = False

        transforms = [
            Transform(**t) if isinstance(t, dict) else t
            for t in transforms_raw
        ]

        static: list[Any] | None = None
        if static_val is not None:
            static = list(static_val) if isinstance(static_val, list) else [static_val]

        return FieldMapping(
            sources=sources,
            collect_all=collect_all,
            static=static,
            transform=transforms,
        )

    # Scalar value → treat as static
    return FieldMapping(static=[raw])

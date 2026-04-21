from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterator

from app.adapters.base import AdapterConfig, ExtractionConfig
from app.core.jsonpath_utils import extract, extract_all


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def extract_findings(file_path: Path, config: AdapterConfig) -> Iterator[dict]:
    """
    Parse a scanner report file and yield one raw dict per finding.

    For nested_join and envelope modes, each yielded dict is enriched with:
    - Context fields injected as ctx_<name>
    - Lookup fields injected as lkp_<lookup_name>_<field>
    """
    mode = config.extraction.mode
    fmt  = config.input.format

    if mode == "flat":
        yield from _extract_flat(file_path, fmt, config.extraction)
    elif mode == "nested_join":
        yield from _extract_nested_join(file_path, config.extraction)
    elif mode == "envelope":
        yield from _extract_envelope(file_path, config.extraction)
    else:
        raise ValueError(f"Unknown extraction mode: {mode!r}")


# ---------------------------------------------------------------------------
# File loading
# ---------------------------------------------------------------------------

def _load_doc(file_path: Path, fmt: str) -> Any:
    """Load the full document from file according to format hint."""
    content = file_path.read_text(encoding="utf-8").strip()

    if fmt == "jsonl":
        return [json.loads(line) for line in content.splitlines() if line.strip()]

    if fmt in ("json_array", "json_object"):
        return json.loads(content)

    # auto-detect: try full JSON parse first, fall back to JSONL
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        # Multiple JSON objects on separate lines (JSONL)
        return [json.loads(line) for line in content.splitlines() if line.strip()]


# ---------------------------------------------------------------------------
# Mode: flat
# ---------------------------------------------------------------------------

def _extract_flat(
    file_path: Path,
    fmt: str,
    config: ExtractionConfig,
) -> Iterator[dict]:
    """One JSON object = one finding."""
    doc = _load_doc(file_path, fmt)
    path = config.findings_path

    if path == "$":
        # Root is already the finding (JSONL → doc is a list of dicts)
        if isinstance(doc, list):
            for item in doc:
                if isinstance(item, dict):
                    yield item
        elif isinstance(doc, dict):
            yield doc
    else:
        # JSONPath expression — extract findings from the document
        for item in extract_all(doc, path):
            if isinstance(item, dict):
                yield item


# ---------------------------------------------------------------------------
# Mode: nested_join
# ---------------------------------------------------------------------------

def _make_lookup_key(item: dict, lookup_cfg) -> Any | None:
    """Build a lookup key from an item dict: single field or compound."""
    if lookup_cfg.compound_key_fields:
        parts = [str(item.get(f, "")) for f in lookup_cfg.compound_key_fields]
        if any(p for p in parts):
            return "|".join(parts)
        return None
    key_val = item.get(lookup_cfg.key_field)
    return key_val


def _make_join_key(finding: dict, lookup_cfg) -> Any | None:
    """Build the join key from a finding: single or compound."""
    if lookup_cfg.compound_join_on:
        parts = [str(extract(finding, path) or "") for path in lookup_cfg.compound_join_on]
        if any(p for p in parts):
            return "|".join(parts)
        return None
    return extract(finding, lookup_cfg.join_on)


def _build_lookup_tables(
    doc: Any,
    config: ExtractionConfig,
) -> dict[str, dict[Any, dict]]:
    """Build in-memory lookup indexes for nested_join mode."""
    tables: dict[str, dict[Any, dict]] = {}
    for name, lookup_cfg in config.lookups.items():
        items = extract_all(doc, lookup_cfg.source_path)
        index: dict[Any, dict] = {}
        for item in items:
            if isinstance(item, dict):
                key_val = _make_lookup_key(item, lookup_cfg)
                if key_val is not None:
                    index[key_val] = item
        tables[name] = index
    return tables


def _build_context(doc: Any, context_inject: dict[str, str]) -> dict[str, Any]:
    """Evaluate context_inject paths against the root document."""
    ctx: dict[str, Any] = {}
    for field_name, path in context_inject.items():
        ctx[f"ctx_{field_name}"] = extract(doc, path)
    return ctx


def _enrich_finding(
    finding: dict,
    lookup_tables: dict[str, dict],
    config: ExtractionConfig,
    context: dict[str, Any],
) -> dict:
    """Inject context and resolved lookup fields into a finding dict."""
    enriched = dict(finding)

    # Inject context (ctx_ prefix)
    enriched.update(context)

    # Inject lookup fields (lkp_<name>_<field> prefix)
    for lookup_name, table in lookup_tables.items():
        lookup_cfg = config.lookups[lookup_name]
        join_val   = _make_join_key(finding, lookup_cfg)
        matched    = table.get(join_val)
        if matched:
            for field_key, field_val in matched.items():
                enriched[f"lkp_{lookup_name}_{field_key}"] = field_val

    return enriched


def _extract_nested_join(
    file_path: Path,
    config: ExtractionConfig,
) -> Iterator[dict]:
    """Findings live in one array; metadata lives in another. JOIN on a key."""
    doc = json.loads(file_path.read_text(encoding="utf-8"))

    lookup_tables = _build_lookup_tables(doc, config)
    context       = _build_context(doc, config.context_inject)
    findings      = extract_all(doc, config.findings_path)

    for finding in findings:
        if isinstance(finding, dict):
            yield _enrich_finding(finding, lookup_tables, config, context)


# ---------------------------------------------------------------------------
# Mode: envelope
# ---------------------------------------------------------------------------

def _extract_envelope(
    file_path: Path,
    config: ExtractionConfig,
) -> Iterator[dict]:
    """Report wraps findings in a top-level envelope. No JOIN needed."""
    doc = json.loads(file_path.read_text(encoding="utf-8"))

    context  = _build_context(doc, config.context_inject)
    findings = extract_all(doc, config.findings_path)

    for finding in findings:
        if isinstance(finding, dict):
            enriched = dict(finding)
            enriched.update(context)
            yield enriched

import json
import logging
from pathlib import Path
from typing import Iterator

logger = logging.getLogger("ingestion-worker")


def detect_input_format(file_path: Path) -> str:
    raw_text = file_path.read_text(encoding="utf-8").lstrip()
    if raw_text.startswith("["):
        return "json-array"
    return "jsonl"


def _load_json_array(file_path: Path) -> list[dict]:
    with file_path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, list):
        raise ValueError("Expected a JSON array payload.")
    return payload


def _iter_jsonl(file_path: Path) -> Iterator[dict]:
    with file_path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError as exc:
                logger.warning("Skipping invalid JSON line %s in %s: %s", line_number, file_path.name, exc)
                continue
            if not isinstance(payload, dict):
                logger.warning("Skipping non-object JSON line %s in %s", line_number, file_path.name)
                continue
            yield payload


def iter_raw_findings(file_path: Path) -> Iterator[dict]:
    if detect_input_format(file_path) == "json-array":
        raw_payloads = _load_json_array(file_path)
        for index, payload in enumerate(raw_payloads, start=1):
            if not isinstance(payload, dict):
                logger.warning("Skipping non-object JSON item %s in %s", index, file_path.name)
                continue
            yield payload
        return

    for payload in _iter_jsonl(file_path):
        yield payload

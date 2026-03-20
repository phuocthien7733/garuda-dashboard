import json
from pathlib import Path
from typing import Iterator


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
                raise ValueError(f"Invalid JSON on line {line_number}: {exc}") from exc
            if not isinstance(payload, dict):
                raise ValueError(f"Expected JSON object on line {line_number}.")
            yield payload


def iter_raw_findings(file_path: Path) -> Iterator[dict]:
    payloads: Iterator[dict]
    if detect_input_format(file_path) == "json-array":
        payloads = iter(_load_json_array(file_path))
    else:
        payloads = _iter_jsonl(file_path)

    for payload in payloads:
        if not isinstance(payload, dict):
            raise ValueError("Expected every finding payload to be a JSON object.")
        yield payload

from __future__ import annotations

from typing import Any

from jsonpath_ng import parse as _parse
from jsonpath_ng.exceptions import JsonPathParserError


# Cache compiled expressions to avoid re-parsing the same path repeatedly.
_CACHE: dict[str, Any] = {}


def _compiled(path: str):
    if path not in _CACHE:
        _CACHE[path] = _parse(path)
    return _CACHE[path]


def extract(obj: Any, path: str) -> Any | None:
    """
    Evaluate a JSONPath expression against *obj* and return the first match.
    Returns None if there are no matches or the path is invalid.

    Example:
        extract({"info": {"severity": "high"}}, "$.info.severity")
        → "high"
    """
    if obj is None or not path:
        return None
    try:
        matches = _compiled(path).find(obj)
        return matches[0].value if matches else None
    except (JsonPathParserError, Exception):
        return None


def extract_all(obj: Any, path: str) -> list[Any]:
    """
    Evaluate a JSONPath expression against *obj* and return all matches as a list.
    Returns an empty list if there are no matches or the path is invalid.

    Example:
        extract_all({"tags": ["cve", "rce"]}, "$.tags[*]")
        → ["cve", "rce"]
    """
    if obj is None or not path:
        return []
    try:
        matches = _compiled(path).find(obj)
        return [m.value for m in matches]
    except (JsonPathParserError, Exception):
        return []

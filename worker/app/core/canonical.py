SEVERITY_VALUES = {"critical", "high", "medium", "low", "info", "unknown"}
STATUS_VALUES = {"Open", "Investigating", "Accepted Risk", "Resolved"}


def normalize_severity(value: str | None) -> str:
    normalized = (value or "unknown").strip().lower()
    if normalized in SEVERITY_VALUES:
        return normalized
    return "unknown"


def normalize_status(value: str | None) -> str:
    normalized = (value or "Open").strip()
    if normalized in STATUS_VALUES:
        return normalized
    return "Open"

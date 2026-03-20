import hashlib


def build_fingerprint(template_id: str, matched_at: str) -> str:
    raw_value = f"{template_id}{matched_at}".encode("utf-8")
    return hashlib.md5(raw_value, usedforsecurity=False).hexdigest()

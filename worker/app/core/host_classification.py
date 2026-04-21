import ipaddress

import tldextract

_extractor = tldextract.TLDExtract(suffix_list_urls=None)


def extract_apex_domain(hostname: str | None) -> str:
    """
    Return the apex (registrable) domain for a hostname.
    Examples:
        api.example.com  → example.com
        example.com      → example.com
        1.2.3.4          → 1.2.3.4  (IPs returned as-is)
        ""               → "unknown"
    """
    normalized = str(hostname or "").strip().lower().rstrip(".")
    if not normalized:
        return "unknown"
    # Pass through raw IPs
    try:
        ipaddress.ip_address(normalized)
        return normalized
    except ValueError:
        pass
    extracted = _extractor(normalized)
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"
    # No recognised TLD — return as-is (covers internal hostnames)
    return normalized or "unknown"


def classify_host_type(host: str | None) -> str:
    normalized = str(host or "").strip().lower().rstrip(".")
    if not normalized:
        return "unknown"

    try:
        ipaddress.ip_address(normalized)
        return "ip"
    except ValueError:
        pass

    extracted = _extractor(normalized)
    if not extracted.suffix:
        return "domain"

    if extracted.subdomain:
        return "subdomain"

    return "domain"

import ipaddress

import tldextract

_extractor = tldextract.TLDExtract(suffix_list_urls=None)


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

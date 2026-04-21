from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from app.adapters.base import AdapterConfig, AdapterConfigError
from app.adapters.loader import CONFIGS_DIR, load_adapter


@lru_cache(maxsize=64)
def get_adapter(scanner_name: str) -> AdapterConfig:
    """
    Return the loaded and validated AdapterConfig for *scanner_name*.
    Results are cached in-process (per scanner_name).

    Raises:
        AdapterConfigError — if no YAML config exists for this scanner.
    """
    return load_adapter(scanner_name)


def has_adapter(scanner_name: str) -> bool:
    """Return True if an adapter config exists for *scanner_name*."""
    try:
        get_adapter(scanner_name)
        return True
    except AdapterConfigError:
        return False


def list_adapters() -> list[str]:
    """Return the scanner names for all YAML configs present in the configs directory."""
    return [p.stem for p in sorted(CONFIGS_DIR.glob("*.yaml"))]


def clear_cache() -> None:
    """Clear the adapter config cache (useful for tests or config reloads)."""
    get_adapter.cache_clear()

from __future__ import annotations

from pathlib import Path

import yaml

from app.adapters.base import AdapterConfig, AdapterConfigError

# YAML adapter files live in this directory
CONFIGS_DIR = Path(__file__).parent / "configs"


def load_adapter(scanner_name: str) -> AdapterConfig:
    """
    Load and validate the YAML adapter config for *scanner_name*.

    Looks for: worker/app/adapters/configs/<scanner_name>.yaml

    Raises:
        AdapterConfigError — if the file is missing, invalid YAML, or fails
                             Pydantic validation.
    """
    config_path = CONFIGS_DIR / f"{scanner_name}.yaml"

    if not config_path.exists():
        raise AdapterConfigError(
            f"No adapter config found for scanner {scanner_name!r}. "
            f"Expected file: {config_path}"
        )

    try:
        with config_path.open("r", encoding="utf-8") as f:
            raw = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        raise AdapterConfigError(
            f"Invalid YAML in adapter config {config_path}: {exc}"
        ) from exc

    if not isinstance(raw, dict):
        raise AdapterConfigError(
            f"Adapter config {config_path} must be a YAML mapping (dict), got {type(raw).__name__}"
        )

    try:
        return AdapterConfig.model_validate(raw)
    except Exception as exc:
        raise AdapterConfigError(
            f"Adapter config validation failed for {scanner_name!r}: {exc}"
        ) from exc

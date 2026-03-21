from dataclasses import dataclass, field

from pydantic import BaseModel, ConfigDict, Field


class FindingInfo(BaseModel):
    name: str | None = None
    severity: str | None = None
    author: list[str] | None = None
    tags: list[str] | None = None
    description: str | None = None
    reference: list[str] | None = None
    metadata: dict | None = None

    model_config = ConfigDict(extra="allow")


class IngestedVulnerability(BaseModel):
    template_id: str = Field(alias="template-id")
    matched_at: str = Field(alias="matched-at")
    host: str
    name: str
    severity: str
    info: FindingInfo | None = None
    template_path: str | None = Field(default=None, alias="template-path")
    type: str | None = None
    port: str | None = None
    scheme: str | None = None
    url: str | None = None
    ip: str | None = None
    timestamp: str | None = None
    extracted_results: list[str] | None = Field(default=None, alias="extracted-results")
    curl_command: str | None = Field(default=None, alias="curl-command")
    request: str | None = None
    response: str | None = None
    matcher_name: str | None = Field(default=None, alias="matcher-name")
    extractor_name: str | None = Field(default=None, alias="extractor-name")
    matcher_status: bool | None = Field(default=None, alias="matcher-status")
    meta: dict | None = None

    model_config = ConfigDict(populate_by_name=True, extra="allow")

    def normalized_severity(self) -> str:
        return self.severity.lower()


@dataclass(slots=True)
class ProcessingSummary:
    file_name: str
    processed: int = 0
    inserted: int = 0
    updated: int = 0
    resolved: int = 0
    skipped: int = 0
    assets_updated: int = 0
    severities_seen: set[str] = field(default_factory=set)


def normalize_finding_payload(payload: dict) -> dict:
    normalized = dict(payload)
    info = normalized.get("info")
    if not isinstance(info, dict):
        info = {}
        normalized["info"] = info

    normalized["name"] = normalized.get("name") or info.get("name")
    normalized["severity"] = (normalized.get("severity") or info.get("severity") or "unknown").lower()

    return normalized

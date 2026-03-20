from typing import Any

from pydantic import BaseModel, Field


class AssetResponse(BaseModel):
    id: str
    host: str
    ip_addresses: list[str] = Field(default_factory=list)
    open_ports: list[str] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    template_ids: list[str] = Field(default_factory=list)
    highest_severity: str | None = None
    vulnerability_count: int = 0
    type: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None


class AssetListResponse(BaseModel):
    items: list[AssetResponse]
    total: int


class AssetDetailResponse(BaseModel):
    asset: dict[str, Any]


class AssetVulnerabilitiesResponse(BaseModel):
    asset_id: str
    asset_host: str
    items: list[dict[str, Any]]
    total: int


class AssetBulkTriageRequest(BaseModel):
    hosts: list[str] = Field(default_factory=list)
    status: str | None = None
    override_severity: str | None = None


class GraphResponse(BaseModel):
    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]

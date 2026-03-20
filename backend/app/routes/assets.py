from datetime import datetime, timezone
import ipaddress
import re

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.encoders import jsonable_encoder

from app.core.rbac import require_role
from app.db.mongo import get_database
from app.schemas.asset import (
    AssetBulkTriageRequest,
    AssetDetailResponse,
    AssetListResponse,
    AssetResponse,
    AssetVulnerabilitiesResponse,
)
from app.schemas.auth import CurrentUser
from app.services.assets_inventory import ensure_asset_inventory, recalculate_asset

router = APIRouter()
VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
MAX_NETWORK_NEIGHBORS = 36
MAX_NETWORK_IP_NODES = 12


def _serialize_mongo_document(document: dict) -> dict:
    normalized = dict(document)
    mongo_id = normalized.pop("_id", None)
    payload = jsonable_encoder(normalized)
    if mongo_id is not None:
        payload["id"] = str(mongo_id)
    return payload


def _normalize_asset(document: dict) -> dict:
    payload = _serialize_mongo_document(document)
    payload["host"] = payload.get("host") or payload.get("id") or ""
    payload["ip_addresses"] = sorted({item for item in payload.get("ip_addresses", []) if item})
    payload["open_ports"] = sorted({str(item) for item in payload.get("open_ports", []) if item})
    payload["services"] = sorted({item for item in payload.get("services", []) if item})
    payload["template_ids"] = sorted({item for item in payload.get("template_ids", []) if item})
    payload["vulnerability_count"] = int(payload.get("vulnerability_count", 0) or 0)
    return payload


def _normalize_vulnerability(document: dict) -> dict:
    payload = _serialize_mongo_document(document)
    if payload.get("port") is not None:
        payload["port"] = str(payload["port"])
    return payload


def _extract_root_domain(host: str) -> str:
    normalized = str(host or "").strip().lower().rstrip(".")
    if not normalized:
        return ""

    try:
        ipaddress.ip_address(normalized)
        return normalized
    except ValueError:
        pass

    parts = [part for part in normalized.split(".") if part]
    if len(parts) < 2:
        return normalized
    return ".".join(parts[-2:])


def _format_detail_list(values: list[str]) -> str:
    cleaned = [str(value) for value in values if value]
    return ", ".join(cleaned) if cleaned else "--"


def _asset_graph_detail(asset: dict) -> dict:
    return {
        "asset_id": asset.get("id"),
        "ip": _format_detail_list(asset.get("ip_addresses", [])),
        "host": asset.get("host") or "--",
        "ports": _format_detail_list(asset.get("open_ports", [])),
        "services": _format_detail_list(asset.get("services", [])),
        "tech": _format_detail_list(asset.get("template_ids", [])),
        "highest_severity": asset.get("highest_severity") or "--",
    }


def _build_asset_graph_node(asset: dict, category: str) -> dict:
    return {
        "id": str(asset.get("id") or asset.get("host") or "unknown-asset"),
        "name": str(asset.get("host") or asset.get("id") or "unknown"),
        "category": category,
        "detail": _asset_graph_detail(asset),
    }


async def _get_asset_by_id(asset_id: str):
    if not ObjectId.is_valid(asset_id):
        raise HTTPException(status_code=404, detail="Asset not found.")

    db = get_database()
    await ensure_asset_inventory(db)
    asset = await db.assets.find_one({"_id": ObjectId(asset_id)})
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found.")
    return db, asset


@router.get("/assets", response_model=AssetListResponse)
async def list_assets(
    search: str | None = Query(default=None),
    limit: int = Query(default=250, ge=1, le=1000),
    _: CurrentUser = Depends(require_role("admin", "viewer")),
):
    db = get_database()
    await ensure_asset_inventory(db)

    query: dict[str, object] = {}
    if search:
        query["$or"] = [
            {"host": {"$regex": search, "$options": "i"}},
            {"ip_addresses": {"$elemMatch": {"$regex": search, "$options": "i"}}},
            {"services": {"$elemMatch": {"$regex": search, "$options": "i"}}},
            {"template_ids": {"$elemMatch": {"$regex": search, "$options": "i"}}},
        ]

    cursor = db.assets.find(query).sort([("vulnerability_count", -1), ("host", 1)]).limit(limit)
    items = [_normalize_asset(document) async for document in cursor]
    return AssetListResponse(items=[AssetResponse(**item) for item in items], total=len(items))


@router.get("/assets/{asset_id}/detail", response_model=AssetDetailResponse)
async def get_asset_detail(asset_id: str, _: CurrentUser = Depends(require_role("admin", "viewer"))):
    _, asset = await _get_asset_by_id(asset_id)
    return AssetDetailResponse(asset=_normalize_asset(asset))


@router.get("/assets/{asset_id}/vulnerabilities", response_model=AssetVulnerabilitiesResponse)
async def get_asset_vulnerabilities(asset_id: str, _: CurrentUser = Depends(require_role("admin", "viewer"))):
    db, asset = await _get_asset_by_id(asset_id)
    host = asset.get("host")
    cursor = db.vulnerabilities.find({"host": host}).sort("last_seen", -1)
    items = [_normalize_vulnerability(document) async for document in cursor]
    return AssetVulnerabilitiesResponse(
        asset_id=str(asset.get("_id")),
        asset_host=str(host or ""),
        items=items,
        total=len(items),
    )


@router.get("/assets/{asset_id}/network")
async def get_asset_network(asset_id: str, _: CurrentUser = Depends(require_role("admin", "viewer"))):
    db, asset_document = await _get_asset_by_id(asset_id)
    focus_asset = _normalize_asset(asset_document)
    focus_host = str(focus_asset.get("host") or "")
    focus_root_domain = _extract_root_domain(focus_host)
    focus_ip_addresses = focus_asset.get("ip_addresses", [])[:MAX_NETWORK_IP_NODES]
    focus_ip_set = set(focus_ip_addresses)

    nodes: list[dict] = []
    links: list[dict] = []
    node_ids: set[str] = set()
    link_ids: set[tuple[str, str, str]] = set()

    def add_node(node: dict) -> None:
        node_id = str(node.get("id") or "")
        if not node_id or node_id in node_ids:
            return
        node_ids.add(node_id)
        nodes.append(node)

    def add_link(source: str, target: str, relation: str) -> None:
        if not source or not target:
            return
        link_key = (source, target, relation)
        if link_key in link_ids:
            return
        link_ids.add(link_key)
        links.append({"source": source, "target": target, "relation": relation})

    add_node(_build_asset_graph_node(focus_asset, "focus_host"))

    root_node_id = ""
    if focus_root_domain:
        root_node_id = f"domain::{focus_root_domain}"
        add_node(
            {
                "id": root_node_id,
                "name": focus_root_domain,
                "category": "root_domain",
                "detail": {
                    "asset_id": None,
                    "ip": _format_detail_list(focus_ip_addresses),
                    "host": focus_root_domain,
                    "ports": "--",
                    "services": "--",
                    "tech": "Related root domain cluster",
                    "highest_severity": "--",
                },
            }
        )
        add_link(str(focus_asset.get("id")), root_node_id, "root-domain")

    for ip_address_value in focus_ip_addresses:
        ip_node_id = f"ip::{ip_address_value}"
        add_node(
            {
                "id": ip_node_id,
                "name": ip_address_value,
                "category": "shared_ip",
                "detail": {
                    "asset_id": None,
                    "ip": ip_address_value,
                    "host": "Shared infrastructure",
                    "ports": _format_detail_list(focus_asset.get("open_ports", [])),
                    "services": _format_detail_list(focus_asset.get("services", [])),
                    "tech": _format_detail_list(focus_asset.get("template_ids", [])),
                    "highest_severity": focus_asset.get("highest_severity") or "--",
                },
            }
        )
        add_link(str(focus_asset.get("id")), ip_node_id, "shared-ip")

    match_conditions: list[dict] = [{"_id": {"$ne": ObjectId(asset_id)}}]
    match_or_conditions: list[dict] = []

    if focus_root_domain:
        root_regex = rf"(^|\\.){re.escape(focus_root_domain)}$"
        match_or_conditions.append({"host": {"$regex": root_regex, "$options": "i"}})
    else:
        root_regex = ""

    if focus_ip_addresses:
        match_or_conditions.append({"ip_addresses": {"$in": focus_ip_addresses}})

    if not match_or_conditions:
        return {"nodes": nodes, "links": links}

    match_conditions.append({"$or": match_or_conditions})

    pipeline = [
        {"$match": {"$and": match_conditions}},
        {
            "$project": {
                "host": 1,
                "ip_addresses": 1,
                "open_ports": 1,
                "services": 1,
                "template_ids": 1,
                "highest_severity": 1,
                "vulnerability_count": 1,
                "shared_ips": {"$setIntersection": ["$ip_addresses", focus_ip_addresses]},
                "shares_root_domain": (
                    {"$regexMatch": {"input": "$host", "regex": root_regex, "options": "i"}}
                    if focus_root_domain
                    else False
                ),
            }
        },
        {"$sort": {"vulnerability_count": -1, "host": 1}},
        {"$limit": MAX_NETWORK_NEIGHBORS},
    ]

    neighbors = await db.assets.aggregate(pipeline).to_list(length=MAX_NETWORK_NEIGHBORS)

    for neighbor_document in neighbors:
        neighbor = _normalize_asset(neighbor_document)
        shared_ips = [ip for ip in neighbor_document.get("shared_ips", []) if ip in focus_ip_set]
        shares_root = bool(neighbor_document.get("shares_root_domain"))

        if shared_ips and shares_root:
            category = "related_both"
        elif shared_ips:
            category = "related_ip"
        else:
            category = "related_domain"

        neighbor_node = _build_asset_graph_node(neighbor, category)
        add_node(neighbor_node)

        neighbor_id = str(neighbor.get("id"))
        if shares_root and root_node_id:
            add_link(root_node_id, neighbor_id, "root-domain")

        for shared_ip in shared_ips[:MAX_NETWORK_IP_NODES]:
            ip_node_id = f"ip::{shared_ip}"
            if ip_node_id not in node_ids:
                add_node(
                    {
                        "id": ip_node_id,
                        "name": shared_ip,
                        "category": "shared_ip",
                        "detail": {
                            "asset_id": None,
                            "ip": shared_ip,
                            "host": "Shared infrastructure",
                            "ports": _format_detail_list(neighbor.get("open_ports", [])),
                            "services": _format_detail_list(neighbor.get("services", [])),
                            "tech": _format_detail_list(neighbor.get("template_ids", [])),
                            "highest_severity": neighbor.get("highest_severity") or "--",
                        },
                    }
                )
            add_link(ip_node_id, neighbor_id, "shared-ip")

    return {"nodes": nodes[:70], "links": links[:140]}


@router.post("/assets/bulk-triage")
async def bulk_triage_assets(
    payload: AssetBulkTriageRequest,
    _: CurrentUser = Depends(require_role("admin")),
):
    db = get_database()
    hosts = sorted({host.strip() for host in payload.hosts if host.strip()})
    if not hosts:
        raise HTTPException(status_code=400, detail="No assets selected.")

    update_fields = {
        key: value
        for key, value in {
            "status": payload.status,
            "override_severity": payload.override_severity,
        }.items()
        if value is not None
    }
    if not update_fields:
        raise HTTPException(status_code=400, detail="No update payload provided.")

    update_fields["last_seen"] = datetime.now(timezone.utc)
    result = await db.vulnerabilities.update_many(
        {"host": {"$in": hosts}},
        {"$set": update_fields},
    )

    for host in hosts:
        await recalculate_asset(db, host)

    return {
        "updated": True,
        "assets": len(hosts),
        "vulnerabilities": result.modified_count,
    }


@router.get("/assets/top")
async def top_assets(
    severity: str = Query(default="all"),
    _: CurrentUser = Depends(require_role("admin", "viewer")),
):
    db = get_database()
    await ensure_asset_inventory(db)
    normalized_severity = severity.lower()
    match_stage: dict[str, object] = {"status": "Open"}

    if normalized_severity != "all":
        if normalized_severity not in VALID_SEVERITIES:
            return []
        match_stage["severity"] = normalized_severity

    pipeline = [
        {"$match": match_stage},
        {
            "$addFields": {
                "severity_rank": {
                    "$switch": {
                        "branches": [
                            {"case": {"$eq": ["$severity", "critical"]}, "then": 5},
                            {"case": {"$eq": ["$severity", "high"]}, "then": 4},
                            {"case": {"$eq": ["$severity", "medium"]}, "then": 3},
                            {"case": {"$eq": ["$severity", "low"]}, "then": 2},
                            {"case": {"$eq": ["$severity", "info"]}, "then": 1},
                        ],
                        "default": 0,
                    }
                }
            }
        },
        {
            "$group": {
                "_id": "$host",
                "count": {"$sum": 1},
                "highest_severity_rank": {"$max": "$severity_rank"},
            }
        },
        {"$sort": {"count": -1, "_id": 1}},
        {"$limit": 5},
    ]

    results = await db.vulnerabilities.aggregate(pipeline).to_list(length=5)
    enriched_results = []
    for document in results:
        asset = await db.assets.find_one({"host": document["_id"]}, {"_id": 1})
        enriched_results.append(
            {
                "id": str(asset.get("_id")) if asset else None,
                "host": document["_id"],
                "count": document["count"],
                "highest_severity": (
                    "critical"
                    if document.get("highest_severity_rank") == 5
                    else "high"
                    if document.get("highest_severity_rank") == 4
                    else "medium"
                    if document.get("highest_severity_rank") == 3
                    else "low"
                    if document.get("highest_severity_rank") == 2
                    else "info"
                    if document.get("highest_severity_rank") == 1
                    else None
                ),
            }
        )
    return enriched_results


@router.get("/assets/{asset_id}", response_model=AssetResponse)
async def get_asset(asset_id: str, _: CurrentUser = Depends(require_role("admin", "viewer"))):
    _, asset = await _get_asset_by_id(asset_id)
    return AssetResponse(**_normalize_asset(asset))

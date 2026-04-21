"""Hunting Maps — persistent Red Team campaign maps with multi-asset graph."""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.core.rbac import require_role
from app.db.mongo import get_database
from app.schemas.auth import CurrentUser

router = APIRouter()

# ── Constants ────────────────────────────────────────────────────────────────

MAX_MAP_ASSETS = 200
MAX_GRAPH_NODES = 300
MAX_GRAPH_LINKS = 600
MAX_NEIGHBOR_PER_ASSET = 6
MAX_IP_NODES_PER_ASSET = 4
SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

# ── Request / Response schemas ───────────────────────────────────────────────


class CreateMapRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: str = Field("", max_length=2000)
    asset_ids: list[str] = Field(default_factory=list)


class UpdateMapRequest(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=200)
    description: str | None = Field(None, max_length=2000)


class AddAssetsRequest(BaseModel):
    asset_ids: list[str] = Field(..., min_items=1)


class RemoveAssetsRequest(BaseModel):
    asset_ids: list[str] = Field(..., min_items=1)


# ── Helpers ──────────────────────────────────────────────────────────────────


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


def _format_list(values: list) -> str:
    cleaned = [str(v) for v in values if v]
    return ", ".join(cleaned) if cleaned else "--"


def _serialize_doc(doc: dict) -> dict:
    result = {}
    for key, value in doc.items():
        if key == "_id":
            result["id"] = str(value)
        elif isinstance(value, ObjectId):
            result[key] = str(value)
        elif isinstance(value, datetime):
            result[key] = value.isoformat()
        else:
            result[key] = value
    return result


def _normalize_asset(doc: dict) -> dict:
    payload = _serialize_doc(doc)
    port_metadata = payload.get("port_metadata") or {}
    if port_metadata:
        payload["open_ports"] = sorted({str(k).split("/")[0] for k in port_metadata})
        payload["services"] = sorted({
            m.get("service", "") for m in port_metadata.values()
            if isinstance(m, dict) and m.get("service")
        })
    else:
        payload["open_ports"] = sorted({str(p) for p in payload.get("open_ports", []) if p})
        payload["services"] = sorted({str(s) for s in payload.get("services", []) if s})
    payload["ip_addresses"] = [str(ip) for ip in payload.get("ip_addresses", []) if ip]
    payload["vulnerability_count"] = int(payload.get("vulnerability_count", 0) or 0)
    payload["host"] = payload.get("host_normalized") or payload.get("host") or ""
    return payload


def _map_summary(doc: dict) -> dict:
    return {
        "id": str(doc["_id"]),
        "name": doc.get("name", ""),
        "description": doc.get("description", ""),
        "asset_count": len(doc.get("asset_ids", [])),
        "created_by": doc.get("created_by", ""),
        "created_at": doc.get("created_at").isoformat() if isinstance(doc.get("created_at"), datetime) else None,
        "updated_at": doc.get("updated_at").isoformat() if isinstance(doc.get("updated_at"), datetime) else None,
    }


# ── CRUD endpoints ───────────────────────────────────────────────────────────


@router.get("/hunting-maps")
async def list_maps(_: CurrentUser = Depends(require_role("admin"))):
    db = get_database()
    cursor = db.hunting_maps.find().sort("updated_at", -1)
    docs = await cursor.to_list(length=200)
    return {"items": [_map_summary(d) for d in docs]}


@router.post("/hunting-maps", status_code=201)
async def create_map(
    body: CreateMapRequest,
    user: CurrentUser = Depends(require_role("admin")),
):
    db = get_database()
    valid_ids = [ObjectId(aid) for aid in body.asset_ids if ObjectId.is_valid(aid)]
    valid_ids = valid_ids[:MAX_MAP_ASSETS]
    now = datetime.now(timezone.utc)
    result = await db.hunting_maps.insert_one({
        "name": body.name.strip(),
        "description": body.description.strip(),
        "asset_ids": valid_ids,
        "created_by": user.username,
        "created_at": now,
        "updated_at": now,
    })
    return {"id": str(result.inserted_id)}


@router.get("/hunting-maps/{map_id}")
async def get_map(map_id: str, _: CurrentUser = Depends(require_role("admin"))):
    db = get_database()
    if not ObjectId.is_valid(map_id):
        raise HTTPException(404, "Hunting map not found.")
    doc = await db.hunting_maps.find_one({"_id": ObjectId(map_id)})
    if not doc:
        raise HTTPException(404, "Hunting map not found.")
    summary = _map_summary(doc)
    summary["asset_ids"] = [str(aid) for aid in doc.get("asset_ids", [])]
    return summary


@router.patch("/hunting-maps/{map_id}")
async def update_map(
    map_id: str,
    body: UpdateMapRequest,
    _: CurrentUser = Depends(require_role("admin")),
):
    if not ObjectId.is_valid(map_id):
        raise HTTPException(404, "Hunting map not found.")
    db = get_database()
    updates: dict = {"updated_at": datetime.now(timezone.utc)}
    if body.name is not None:
        updates["name"] = body.name.strip()
    if body.description is not None:
        updates["description"] = body.description.strip()
    result = await db.hunting_maps.update_one({"_id": ObjectId(map_id)}, {"$set": updates})
    if result.matched_count == 0:
        raise HTTPException(404, "Hunting map not found.")
    return {"ok": True}


@router.delete("/hunting-maps/{map_id}")
async def delete_map(map_id: str, _: CurrentUser = Depends(require_role("admin"))):
    if not ObjectId.is_valid(map_id):
        raise HTTPException(404, "Hunting map not found.")
    db = get_database()
    result = await db.hunting_maps.delete_one({"_id": ObjectId(map_id)})
    if result.deleted_count == 0:
        raise HTTPException(404, "Hunting map not found.")
    return {"ok": True}


# ── Asset membership ─────────────────────────────────────────────────────────


@router.post("/hunting-maps/{map_id}/assets")
async def add_assets(
    map_id: str,
    body: AddAssetsRequest,
    _: CurrentUser = Depends(require_role("admin")),
):
    if not ObjectId.is_valid(map_id):
        raise HTTPException(404, "Hunting map not found.")
    db = get_database()
    new_ids = [ObjectId(aid) for aid in body.asset_ids if ObjectId.is_valid(aid)]
    if not new_ids:
        raise HTTPException(400, "No valid asset IDs provided.")
    result = await db.hunting_maps.update_one(
        {"_id": ObjectId(map_id)},
        {
            "$addToSet": {"asset_ids": {"$each": new_ids}},
            "$set": {"updated_at": datetime.now(timezone.utc)},
        },
    )
    if result.matched_count == 0:
        raise HTTPException(404, "Hunting map not found.")
    return {"ok": True}


@router.delete("/hunting-maps/{map_id}/assets")
async def remove_assets(
    map_id: str,
    body: RemoveAssetsRequest,
    _: CurrentUser = Depends(require_role("admin")),
):
    if not ObjectId.is_valid(map_id):
        raise HTTPException(404, "Hunting map not found.")
    db = get_database()
    remove_ids = [ObjectId(aid) for aid in body.asset_ids if ObjectId.is_valid(aid)]
    if not remove_ids:
        raise HTTPException(400, "No valid asset IDs provided.")
    result = await db.hunting_maps.update_one(
        {"_id": ObjectId(map_id)},
        {
            "$pull": {"asset_ids": {"$in": remove_ids}},
            "$set": {"updated_at": datetime.now(timezone.utc)},
        },
    )
    if result.matched_count == 0:
        raise HTTPException(404, "Hunting map not found.")
    return {"ok": True}


# ── Graph data ───────────────────────────────────────────────────────────────


@router.get("/hunting-maps/{map_id}/graph")
async def get_map_graph(map_id: str, _: CurrentUser = Depends(require_role("admin"))):
    """Build a force-directed graph for all assets in a hunting map.

    Nodes are colored by highest_severity. Neighbors sharing root domain
    with selected assets are auto-included but marked as ``is_neighbor``.
    """
    if not ObjectId.is_valid(map_id):
        raise HTTPException(404, "Hunting map not found.")

    db = get_database()
    map_doc = await db.hunting_maps.find_one({"_id": ObjectId(map_id)})
    if not map_doc:
        raise HTTPException(404, "Hunting map not found.")

    asset_oids = list(map_doc.get("asset_ids", []))[:MAX_MAP_ASSETS]
    if not asset_oids:
        return {"nodes": [], "links": [], "stats": _empty_stats()}

    # Fetch selected assets
    selected_docs = await db.assets.find({"_id": {"$in": asset_oids}}).to_list(length=MAX_MAP_ASSETS)
    selected_assets = [_normalize_asset(d) for d in selected_docs]
    selected_id_set = {a["id"] for a in selected_assets}

    nodes: list[dict] = []
    links: list[dict] = []
    node_ids: set[str] = set()
    link_ids: set[tuple[str, str, str]] = set()

    def add_node(node: dict) -> None:
        nid = str(node.get("id") or "")
        if not nid or nid in node_ids:
            return
        node_ids.add(nid)
        nodes.append(node)

    def add_link(source: str, target: str, relation: str) -> None:
        if not source or not target or source == target:
            return
        key = tuple(sorted([source, target])) + (relation,)
        if key in link_ids:
            return
        link_ids.add(key)
        links.append({"source": source, "target": target, "relation": relation})

    # Root domain clusters: group assets by root domain
    root_domain_map: dict[str, list[dict]] = {}
    all_ip_addresses: set[str] = set()

    for asset in selected_assets:
        host = asset.get("host", "")
        root = _extract_root_domain(host)
        severity = asset.get("highest_severity", "info")
        add_node({
            "id": asset["id"],
            "name": host or asset["id"],
            "severity": severity,
            "is_neighbor": False,
            "detail": {
                "asset_id": asset["id"],
                "host": host,
                "ip": _format_list(asset.get("ip_addresses", [])),
                "ports": _format_list(asset.get("open_ports", [])),
                "services": _format_list(asset.get("services", [])),
                "open_finding_types": _format_list(asset.get("open_finding_types") or asset.get("template_ids", [])),
                "highest_severity": severity or "--",
                "vulnerability_count": asset.get("vulnerability_count", 0),
            },
        })
        if root:
            root_domain_map.setdefault(root, []).append(asset)
        for ip in asset.get("ip_addresses", []):
            all_ip_addresses.add(ip)

    # Add root domain hub nodes + links
    for root, assets_in_root in root_domain_map.items():
        root_node_id = f"domain::{root}"
        add_node({
            "id": root_node_id,
            "name": root,
            "severity": None,
            "is_neighbor": False,
            "detail": None,
        })
        for a in assets_in_root:
            add_link(a["id"], root_node_id, "root-domain")

    # IP hub nodes: if 2+ selected assets share an IP, add an IP hub
    ip_to_assets: dict[str, list[str]] = {}
    for asset in selected_assets:
        for ip in asset.get("ip_addresses", [])[:MAX_IP_NODES_PER_ASSET]:
            ip_to_assets.setdefault(ip, []).append(asset["id"])
    for ip, asset_ids_for_ip in ip_to_assets.items():
        if len(asset_ids_for_ip) < 2:
            continue
        ip_node_id = f"ip::{ip}"
        add_node({
            "id": ip_node_id,
            "name": ip,
            "severity": None,
            "is_neighbor": False,
            "detail": None,
        })
        for aid in asset_ids_for_ip:
            add_link(aid, ip_node_id, "shared-ip")

    # Auto-discover neighbors (same root domain, NOT already selected)
    neighbor_match_conditions: list[dict] = []
    for root in root_domain_map:
        root_regex = rf"(^|\\.){re.escape(root)}$"
        neighbor_match_conditions.append({"host_normalized": {"$regex": root_regex, "$options": "i"}})
        neighbor_match_conditions.append({"host": {"$regex": root_regex, "$options": "i"}})

    if neighbor_match_conditions:
        neighbor_limit = min(MAX_NEIGHBOR_PER_ASSET * len(selected_assets), 80)
        pipeline = [
            {"$match": {
                "$and": [
                    {"_id": {"$nin": asset_oids}},
                    {"$or": neighbor_match_conditions},
                ],
            }},
            {"$sort": {"vulnerability_count": -1, "host_normalized": 1}},
            {"$limit": neighbor_limit},
        ]
        neighbor_docs = await db.assets.aggregate(pipeline).to_list(length=neighbor_limit)

        for ndoc in neighbor_docs:
            neighbor = _normalize_asset(ndoc)
            if neighbor["id"] in node_ids:
                continue
            host = neighbor.get("host", "")
            severity = neighbor.get("highest_severity", "info")
            root = _extract_root_domain(host)
            add_node({
                "id": neighbor["id"],
                "name": host or neighbor["id"],
                "severity": severity,
                "is_neighbor": True,
                "detail": {
                    "asset_id": neighbor["id"],
                    "host": host,
                    "ip": _format_list(neighbor.get("ip_addresses", [])),
                    "ports": _format_list(neighbor.get("open_ports", [])),
                    "services": _format_list(neighbor.get("services", [])),
                    "open_finding_types": _format_list(neighbor.get("open_finding_types") or neighbor.get("template_ids", [])),
                    "highest_severity": severity or "--",
                    "vulnerability_count": neighbor.get("vulnerability_count", 0),
                },
            })
            # Link neighbor to its root domain hub
            if root:
                root_node_id = f"domain::{root}"
                if root_node_id in node_ids:
                    add_link(neighbor["id"], root_node_id, "root-domain")

    # Compute aggregate stats
    stats = _compute_stats(nodes)

    return {
        "nodes": nodes[:MAX_GRAPH_NODES],
        "links": links[:MAX_GRAPH_LINKS],
        "stats": stats,
    }


def _empty_stats() -> dict:
    return {"total_assets": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}


def _compute_stats(nodes: list[dict]) -> dict:
    stats = _empty_stats()
    for node in nodes:
        sev = (node.get("severity") or "").lower()
        if node.get("detail") and node["detail"].get("asset_id"):
            stats["total_assets"] += 1
            if sev in stats:
                stats[sev] += 1
    return stats


# ── Vulnerabilities for an asset within the map ──────────────────────────────


@router.get("/hunting-maps/{map_id}/assets/{asset_id}/vulnerabilities")
async def get_asset_vulnerabilities(
    map_id: str,
    asset_id: str,
    severity: str | None = Query(default=None),
    search: str | None = Query(default=None),
    cursor: str | None = Query(default=None),
    page_size: int = Query(default=50, ge=1, le=200),
    _: CurrentUser = Depends(require_role("admin")),
):
    """Return Open vulnerabilities for a specific asset within the hunting map."""
    if not ObjectId.is_valid(map_id) or not ObjectId.is_valid(asset_id):
        raise HTTPException(404, "Not found.")

    db = get_database()
    map_doc = await db.hunting_maps.find_one({"_id": ObjectId(map_id)})
    if not map_doc:
        raise HTTPException(404, "Hunting map not found.")

    asset_doc = await db.assets.find_one({"_id": ObjectId(asset_id)})
    if not asset_doc:
        raise HTTPException(404, "Asset not found.")

    host = str(asset_doc.get("host_normalized") or asset_doc.get("host") or "")
    if not host:
        return {"items": [], "total": 0, "next_cursor": None}

    # Match vulns by host, status=Open only
    match_filter: dict = {
        "$or": [
            {"target.host_normalized": host},
            {"host": host},
        ],
        "status": {"$in": ["Open", "open", None]},
    }

    if severity and severity.lower() != "all":
        match_filter["$or"] = [
            {"target.host_normalized": host, "severity": severity.lower()},
            {"host": host, "severity": severity.lower()},
        ]

    if search:
        safe_search = re.escape(search.strip())[:200]
        match_filter["$or"] = [
            {"target.host_normalized": host, "name": {"$regex": safe_search, "$options": "i"}},
            {"host": host, "name": {"$regex": safe_search, "$options": "i"}},
            {"target.host_normalized": host, "template_id": {"$regex": safe_search, "$options": "i"}},
            {"host": host, "template_id": {"$regex": safe_search, "$options": "i"}},
        ]
        match_filter["status"] = {"$in": ["Open", "open", None]}

    total = await db.vulnerabilities.count_documents(match_filter)

    sort_spec = [("severity", 1), ("last_seen", -1), ("_id", -1)]
    find_cursor = db.vulnerabilities.find(match_filter).sort(sort_spec).limit(page_size)

    if cursor:
        try:
            cursor_oid = ObjectId(cursor)
            find_cursor = db.vulnerabilities.find(
                {**match_filter, "_id": {"$lt": cursor_oid}}
            ).sort(sort_spec).limit(page_size)
        except Exception:
            pass

    docs = await find_cursor.to_list(length=page_size)
    items = [_serialize_vulnerability(d) for d in docs]

    next_cursor = str(docs[-1]["_id"]) if len(docs) == page_size else None

    return {"items": items, "total": total, "next_cursor": next_cursor}


def _serialize_vulnerability(doc: dict) -> dict:
    payload = _serialize_doc(doc)
    target = payload.get("target") or {}
    identity = payload.get("identity") or {}
    evidence = payload.get("evidence") or {}

    if not payload.get("host"):
        payload["host"] = target.get("host_normalized") or target.get("hostname") or ""
    if not payload.get("name"):
        payload["name"] = identity.get("name") or ""
    if not payload.get("severity"):
        payload["severity"] = identity.get("severity") or payload.get("severity") or ""
    if not payload.get("template_id"):
        payload["template_id"] = (
            identity.get("standardized_rule_id")
            or identity.get("raw_rule_id")
            or payload.get("template-id")
            or ""
        )
    if not payload.get("matched_at"):
        payload["matched_at"] = evidence.get("matched_at") or payload.get("matched-at") or ""
    if not payload.get("ip"):
        payload["ip"] = target.get("ip") or ""
    if not payload.get("request"):
        payload["request"] = evidence.get("request") or ""
    if not payload.get("response"):
        payload["response"] = evidence.get("response") or ""
    if not payload.get("curl_command"):
        payload["curl_command"] = (
            evidence.get("curl_command") or evidence.get("curl-command")
            or payload.get("curl-command") or ""
        )
    raw_port = target.get("port") or payload.get("port")
    payload["port"] = str(raw_port) if raw_port is not None else None
    return payload


# ── Refresh: re-compute stats (clients re-fetch graph after this) ────────────


@router.post("/hunting-maps/{map_id}/refresh")
async def refresh_map(map_id: str, _: CurrentUser = Depends(require_role("admin"))):
    if not ObjectId.is_valid(map_id):
        raise HTTPException(404, "Hunting map not found.")
    db = get_database()
    result = await db.hunting_maps.update_one(
        {"_id": ObjectId(map_id)},
        {"$set": {"updated_at": datetime.now(timezone.utc)}},
    )
    if result.matched_count == 0:
        raise HTTPException(404, "Hunting map not found.")
    return {"ok": True, "refreshed_at": datetime.now(timezone.utc).isoformat()}

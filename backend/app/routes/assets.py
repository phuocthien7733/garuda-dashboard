import base64
from datetime import datetime, timezone
import ipaddress
import json
import re

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.encoders import jsonable_encoder

from app.core.config import get_settings
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
from app.services.dashboard_snapshots import mark_dashboard_snapshot_dirty

router = APIRouter()
settings = get_settings()
VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
MAX_NETWORK_NEIGHBORS = 36
MAX_NETWORK_IP_NODES = 12
ASSET_DEFAULT_LAST_SEEN = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _encode_cursor(payload: dict[str, object]) -> str:
    return base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8")


def _decode_cursor(cursor: str) -> dict[str, object]:
    try:
        decoded = base64.urlsafe_b64decode(cursor.encode("utf-8")).decode("utf-8")
        payload = json.loads(decoded)
        if not isinstance(payload, dict):
            raise ValueError("invalid cursor payload")
        return payload
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail="Invalid cursor.") from exc


def _parse_date_boundary(value: str | None, boundary: str) -> datetime | None:
    if not value:
        return None
    try:
        if boundary == "start":
            return datetime.fromisoformat(f"{value}T00:00:00+00:00")
        return datetime.fromisoformat(f"{value}T23:59:59.999000+00:00")
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid date value: {value}") from exc


def _sanitize_search_query(search: str | None) -> str | None:
    if not search:
        return None

    normalized = search.strip()
    if not normalized:
        return None

    max_length = max(1, int(settings.search_query_max_length))
    if len(normalized) > max_length:
        raise HTTPException(
            status_code=422,
            detail=f"Search query is too long (max {max_length} characters).",
        )

    return re.escape(normalized)


def _parse_cursor_datetime(value: object) -> datetime:
    if not isinstance(value, str):
        raise HTTPException(status_code=400, detail="Invalid cursor.")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid cursor.") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _asset_list_cursor_filter(cursor_payload: dict[str, object]) -> dict:
    vulnerability_count = cursor_payload.get("vulnerability_count")
    last_seen = _parse_cursor_datetime(cursor_payload.get("last_seen"))
    mongo_id_raw = cursor_payload.get("id")
    if not isinstance(vulnerability_count, int) or not isinstance(mongo_id_raw, str):
        raise HTTPException(status_code=400, detail="Invalid cursor.")
    try:
        mongo_id = ObjectId(mongo_id_raw)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail="Invalid cursor.") from exc

    return {
        "$or": [
            {"vulnerability_count": {"$lt": vulnerability_count}},
            {
                "$and": [
                    {"vulnerability_count": vulnerability_count},
                    {"last_seen": {"$lt": last_seen}},
                ]
            },
            {
                "$and": [
                    {"vulnerability_count": vulnerability_count},
                    {"last_seen": last_seen},
                    {"_id": {"$lt": mongo_id}},
                ]
            },
        ]
    }


def _asset_vuln_cursor_filter(cursor_payload: dict[str, object]) -> dict:
    severity_rank = cursor_payload.get("severity_rank")
    last_seen = _parse_cursor_datetime(cursor_payload.get("last_seen"))
    mongo_id_raw = cursor_payload.get("id")
    if not isinstance(severity_rank, int) or not isinstance(mongo_id_raw, str):
        raise HTTPException(status_code=400, detail="Invalid cursor.")
    try:
        mongo_id = ObjectId(mongo_id_raw)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail="Invalid cursor.") from exc

    return {
        "$or": [
            {"severity_rank": {"$lt": severity_rank}},
            {
                "$and": [
                    {"severity_rank": severity_rank},
                    {"last_seen": {"$lt": last_seen}},
                ]
            },
            {
                "$and": [
                    {"severity_rank": severity_rank},
                    {"last_seen": last_seen},
                    {"_id": {"$lt": mongo_id}},
                ]
            },
        ]
    }


def _serialize_mongo_document(document: dict) -> dict:
    normalized = dict(document)
    mongo_id = normalized.pop("_id", None)
    payload = jsonable_encoder(normalized)
    if mongo_id is not None:
        payload["id"] = str(mongo_id)
    return payload


def _normalize_asset(document: dict) -> dict:
    payload = _serialize_mongo_document(document)
    # Resolve canonical host key: v2 uses host_normalized, v1 used host.
    # Explicitly skip empty strings so we never fall back to the raw ObjectId.
    def _first_truthy(*values: object) -> str:
        for v in values:
            s = str(v).strip() if v else ""
            if s and s != "unknown":
                return s
        # Last resort: return "unknown" rather than the ObjectId
        for v in values:
            s = str(v).strip() if v else ""
            if s:
                return s
        return ""

    payload["host"] = _first_truthy(
        payload.get("host_normalized"),
        payload.get("host"),
    ) or str(payload.get("id") or "")
    payload["ip_addresses"] = sorted({item for item in payload.get("ip_addresses", []) if item})

    # Derive open_ports from v2 port_metadata — return full "port/protocol" keys
    # (e.g. "443/https", "22/tcp") so the port filter can do an exact key lookup.
    # For v1 documents the flat open_ports list (port numbers) is preserved as-is.
    port_metadata: dict = payload.get("port_metadata") or {}
    if port_metadata:
        open_ports = sorted(
            {
                key
                for key, meta in port_metadata.items()
                if isinstance(meta, dict) and meta.get("status") == "open"
            },
            key=lambda p: (
                not p.split("/")[0].isdigit(),
                int(p.split("/")[0]) if p.split("/")[0].isdigit() else 0,
                p,
            ),
        )
    else:
        open_ports = sorted({str(item) for item in payload.get("open_ports", []) if item})
    payload["open_ports"] = open_ports

    # Derive services from v2 port_metadata or v1 services list
    if port_metadata:
        payload["services"] = sorted({
            meta.get("service", "")
            for meta in port_metadata.values()
            if isinstance(meta, dict) and meta.get("service")
        })
    else:
        payload["services"] = sorted({item for item in payload.get("services", []) if item})

    # template_ids not present in v2; provide empty list for API compatibility
    payload["template_ids"] = sorted({item for item in payload.get("template_ids", []) if item})
    payload["vulnerability_count"] = int(payload.get("vulnerability_count", 0) or 0)
    return payload


def _normalize_vulnerability(document: dict) -> dict:
    payload = _serialize_mongo_document(document)

    # Flatten v2 UDM nested fields into top-level keys (mirrors _serialize_vulnerability in vulns.py)
    target = payload.get("target") or {}
    identity = payload.get("identity") or {}
    evidence = payload.get("evidence") or {}

    if not payload.get("host"):
        payload["host"] = (
            target.get("host_normalized")
            or target.get("hostname")
            or ""
        )
    if not payload.get("name"):
        payload["name"] = identity.get("name") or ""
    if not payload.get("template_id"):
        payload["template_id"] = (
            identity.get("standardized_rule_id")
            or identity.get("raw_rule_id")
            or payload.get("template-id")
            or ""
        )
    if not payload.get("matched_at"):
        payload["matched_at"] = (
            evidence.get("matched_at")
            or payload.get("matched-at")
            or ""
        )
    if not payload.get("ip"):
        payload["ip"] = target.get("ip") or ""
    # Preserve request/response/curl from evidence for the detail modal
    if not payload.get("request"):
        payload["request"] = evidence.get("request") or payload.get("request") or ""
    if not payload.get("response"):
        payload["response"] = evidence.get("response") or payload.get("response") or ""
    if not payload.get("curl_command"):
        payload["curl_command"] = (
            evidence.get("curl_command")
            or evidence.get("curl-command")
            or payload.get("curl-command")
            or ""
        )

    raw_port = target.get("port") or payload.get("port")
    payload["port"] = str(raw_port) if raw_port is not None else None

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
        "host": asset.get("host") or asset.get("host_normalized") or "--",
        "ports": _format_detail_list(asset.get("open_ports", [])),
        "services": _format_detail_list(asset.get("services", [])),
        "tech": _format_detail_list(asset.get("open_finding_types") or asset.get("template_ids", [])),
        "highest_severity": asset.get("highest_severity") or "--",
    }


def _build_asset_graph_node(asset: dict, category: str) -> dict:
    host = asset.get("host") or asset.get("host_normalized") or asset.get("id") or "unknown"
    return {
        "id": str(asset.get("id") or host),
        "name": str(host),
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
    severity: str | None = Query(default=None),
    port: str | None = Query(default=None),
    time_field: str | None = Query(default="last_seen"),
    date_from: str | None = Query(default=None),
    date_to: str | None = Query(default=None),
    cursor: str | None = Query(default=None),
    page_size: int = Query(default=20, ge=1, le=200),
    _: CurrentUser = Depends(require_role("admin", "viewer")),
):
    db = get_database()
    await ensure_asset_inventory(db)

    safe_search = _sanitize_search_query(search)
    conditions: list[dict[str, object]] = []
    if safe_search:
        conditions.append({
            "$or": [
                # v2 field paths
                {"host_normalized": {"$regex": safe_search, "$options": "i"}},
                {"ip_addresses": {"$elemMatch": {"$regex": safe_search, "$options": "i"}}},
                {"services": {"$elemMatch": {"$regex": safe_search, "$options": "i"}}},
                # v1 field paths (backward compat)
                {"host": {"$regex": safe_search, "$options": "i"}},
                {"template_ids": {"$elemMatch": {"$regex": safe_search, "$options": "i"}}},
            ]
        })
    if severity:
        normalized_severity = severity.strip().lower()
        if normalized_severity in VALID_SEVERITIES:
            conditions.append({"highest_severity": normalized_severity})
    if port:
        normalized_port = port.strip()
        if normalized_port:
            # Build the port filter to cover:
            #   - Exact key match (e.g. "443/https" or "22/tcp") from v2 port_metadata
            #   - Port-number-only input fallback: check common protocol suffixes
            #   - v1 backward compat: flat open_ports list
            port_or_clauses: list[dict] = [
                # v2 exact key — covers full "port/protocol" selections from the dropdown
                {f"port_metadata.{normalized_port}": {"$exists": True}},
                # v1 backward compat
                {"open_ports": normalized_port},
            ]
            # If the input is a bare port number also check all common protocol suffixes
            if normalized_port.isdigit():
                for proto in ("tcp", "udp", "https", "http", "ssl", "tls", "ftp", "ssh"):
                    port_or_clauses.append(
                        {f"port_metadata.{normalized_port}/{proto}": {"$exists": True}}
                    )
            conditions.append({"$or": port_or_clauses})
    query: dict[str, object] = {"$and": conditions} if conditions else {}

    normalized_time_field = (time_field or "last_seen").strip()
    if normalized_time_field not in {"first_seen", "last_seen"}:
        normalized_time_field = "last_seen"

    from_boundary = _parse_date_boundary(date_from, "start")
    to_boundary = _parse_date_boundary(date_to, "end")
    if from_boundary or to_boundary:
        time_filter: dict[str, datetime] = {}
        if from_boundary:
            time_filter["$gte"] = from_boundary
        if to_boundary:
            time_filter["$lte"] = to_boundary
        # Add time range as an additional $and condition
        time_condition: dict[str, object] = {normalized_time_field: time_filter}
        if conditions:
            query = {"$and": conditions + [time_condition]}
        else:
            query = time_condition

    final_query = query
    if cursor:
        cursor_payload = _decode_cursor(cursor)
        cursor_filter = _asset_list_cursor_filter(cursor_payload)
        final_query = {"$and": [query, cursor_filter]} if query else cursor_filter

    total = await db.assets.count_documents(query)
    documents = await db.assets.find(final_query).sort(
        [("vulnerability_count", -1), ("last_seen", -1), ("_id", -1)]
    ).limit(page_size).to_list(length=page_size)

    items = [_normalize_asset(document) for document in documents]
    next_cursor = None
    if len(documents) == page_size:
        last_document = documents[-1]
        last_seen = last_document.get("last_seen")
        if not isinstance(last_seen, datetime):
            last_seen = ASSET_DEFAULT_LAST_SEEN
        next_cursor = _encode_cursor(
            {
                "vulnerability_count": int(last_document.get("vulnerability_count", 0) or 0),
                "last_seen": last_seen.isoformat(),
                "id": str(last_document.get("_id")),
            }
        )

    return AssetListResponse(
        items=[AssetResponse(**item) for item in items],
        total=total,
        next_cursor=next_cursor,
        page_size=page_size,
    )


@router.get("/assets/{asset_id}/detail", response_model=AssetDetailResponse)
async def get_asset_detail(asset_id: str, _: CurrentUser = Depends(require_role("admin", "viewer"))):
    _, asset = await _get_asset_by_id(asset_id)
    return AssetDetailResponse(asset=_normalize_asset(asset))


@router.get("/assets/{asset_id}/vulnerabilities", response_model=AssetVulnerabilitiesResponse)
async def get_asset_vulnerabilities(
    asset_id: str,
    search: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    port: str | None = Query(default=None),
    cursor: str | None = Query(default=None),
    page_size: int = Query(default=20, ge=1, le=200),
    _: CurrentUser = Depends(require_role("admin", "viewer")),
):
    db, asset = await _get_asset_by_id(asset_id)
    # Resolve canonical host from v2 host_normalized or v1 host
    host = asset.get("host_normalized") or asset.get("host")
    safe_search = _sanitize_search_query(search)

    # Query both v2 (target.host_normalized) and v1 (host) documents
    query: dict[str, object] = {
        "$or": [
            {"target.host_normalized": host},
            {"host": host},
        ]
    }
    if severity:
        normalized_severity = severity.strip().lower()
        if normalized_severity in VALID_SEVERITIES:
            query["$and"] = [
                {"$or": query.pop("$or")},
                {"$or": [
                    {"override_severity": normalized_severity},
                    {"severity": normalized_severity},
                ]},
            ]
    if port:
        normalized_port = port.strip()
        if normalized_port:
            try:
                port_int = int(normalized_port)
                port_condition: dict[str, object] = {
                    "$or": [
                        {"target.port": port_int},
                        {"port": normalized_port},
                    ]
                }
            except ValueError:
                port_condition = {"port": normalized_port}
            if "$and" in query:
                query["$and"].append(port_condition)  # type: ignore[union-attr]
            else:
                existing_or = query.pop("$or", [])
                query["$and"] = [{"$or": existing_or}, port_condition]
    if safe_search:
        search_condition: dict[str, object] = {
            "$or": [
                # v2 paths
                {"identity.name": {"$regex": safe_search, "$options": "i"}},
                {"identity.standardized_rule_id": {"$regex": safe_search, "$options": "i"}},
                {"target.host_normalized": {"$regex": safe_search, "$options": "i"}},
                {"target.hostname": {"$regex": safe_search, "$options": "i"}},
                # v1 paths
                {"name": {"$regex": safe_search, "$options": "i"}},
                {"host": {"$regex": safe_search, "$options": "i"}},
                {"ip": {"$regex": safe_search, "$options": "i"}},
                {"template_id": {"$regex": safe_search, "$options": "i"}},
                {"template-id": {"$regex": safe_search, "$options": "i"}},
            ]
        }
        if "$and" in query:
            query["$and"].append(search_condition)  # type: ignore[union-attr]
        else:
            existing_or = query.pop("$or", [])
            query["$and"] = [{"$or": existing_or}, search_condition]

    total = await db.vulnerabilities.count_documents(query)

    cursor_filter = None
    if cursor:
        cursor_filter = _asset_vuln_cursor_filter(_decode_cursor(cursor))

    pipeline: list[dict] = [
        {"$match": query},
        {
            "$addFields": {
                "severity_rank": {
                    "$switch": {
                        "branches": [
                            {
                                "case": {
                                    "$eq": [{"$toLower": {"$ifNull": ["$override_severity", "$severity"]}}, "critical"]
                                },
                                "then": 5,
                            },
                            {
                                "case": {
                                    "$eq": [{"$toLower": {"$ifNull": ["$override_severity", "$severity"]}}, "high"]
                                },
                                "then": 4,
                            },
                            {
                                "case": {
                                    "$eq": [{"$toLower": {"$ifNull": ["$override_severity", "$severity"]}}, "medium"]
                                },
                                "then": 3,
                            },
                            {
                                "case": {
                                    "$eq": [{"$toLower": {"$ifNull": ["$override_severity", "$severity"]}}, "low"]
                                },
                                "then": 2,
                            },
                            {
                                "case": {
                                    "$eq": [{"$toLower": {"$ifNull": ["$override_severity", "$severity"]}}, "info"]
                                },
                                "then": 1,
                            },
                        ],
                        "default": 0,
                    }
                }
            }
        },
    ]

    if cursor_filter:
        pipeline.append({"$match": cursor_filter})

    pipeline.extend(
        [
            {"$sort": {"severity_rank": -1, "last_seen": -1, "_id": -1}},
            {"$limit": page_size},
        ]
    )
    documents = await db.vulnerabilities.aggregate(pipeline).to_list(length=page_size)
    items = [_normalize_vulnerability(document) for document in documents]

    next_cursor = None
    if len(documents) == page_size:
        last_document = documents[-1]
        last_seen = last_document.get("last_seen")
        if not isinstance(last_seen, datetime):
            last_seen = ASSET_DEFAULT_LAST_SEEN
        next_cursor = _encode_cursor(
            {
                "severity_rank": int(last_document.get("severity_rank", 0) or 0),
                "last_seen": last_seen.isoformat(),
                "id": str(last_document.get("_id")),
            }
        )

    return AssetVulnerabilitiesResponse(
        asset_id=str(asset.get("_id")),
        asset_host=str(host or ""),
        items=items,
        total=total,
        next_cursor=next_cursor,
        page_size=page_size,
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
                    "ip": "--",
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
                    "tech": _format_detail_list(focus_asset.get("open_finding_types") or focus_asset.get("template_ids", [])),
                    "highest_severity": focus_asset.get("highest_severity") or "--",
                },
            }
        )
        add_link(str(focus_asset.get("id")), ip_node_id, "shared-ip")

    match_conditions: list[dict] = [{"_id": {"$ne": ObjectId(asset_id)}}]
    match_or_conditions: list[dict] = []

    if focus_root_domain:
        root_regex = rf"(^|\\.){re.escape(focus_root_domain)}$"
        # v2 assets use host_normalized, v1 used host
        match_or_conditions.append({"host_normalized": {"$regex": root_regex, "$options": "i"}})
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
                "host_normalized": 1,
                "ip_addresses": 1,
                "port_metadata": 1,
                "open_ports": 1,
                "services": 1,
                "open_finding_types": 1,
                "template_ids": 1,
                "highest_severity": 1,
                "vulnerability_count": 1,
                "shared_ips": {"$setIntersection": ["$ip_addresses", focus_ip_addresses]},
                "shares_root_domain": (
                    {
                        "$or": [
                            {"$regexMatch": {"input": "$host_normalized", "regex": root_regex, "options": "i"}},
                            {"$regexMatch": {"input": "$host", "regex": root_regex, "options": "i"}},
                        ]
                    }
                    if focus_root_domain
                    else False
                ),
            }
        },
        {"$sort": {"vulnerability_count": -1, "host_normalized": 1, "host": 1}},
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
                            "tech": _format_detail_list(neighbor.get("open_finding_types") or neighbor.get("template_ids", [])),
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
    await mark_dashboard_snapshot_dirty(db, "asset-bulk-triage")

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
    if normalized_severity != "all" and normalized_severity not in VALID_SEVERITIES:
        return []

    pipeline = [
        {"$match": {"status": "Open"}},
        {
            # Stage 1: compute effective_host and effective_severity
            "$addFields": {
                # v2: target.host_normalized → v2: target.hostname → v1: host
                "effective_host": {
                    "$ifNull": ["$target.host_normalized", "$target.hostname", "$host", ""]
                },
                "effective_severity": {"$toLower": {"$ifNull": ["$override_severity", "$severity"]}},
            }
        },
        {
            # Stage 2: severity_rank MUST be a separate stage so it can reference
            # the effective_severity field computed above.
            "$addFields": {
                "severity_rank": {
                    "$switch": {
                        "branches": [
                            {"case": {"$eq": ["$effective_severity", "critical"]}, "then": 5},
                            {"case": {"$eq": ["$effective_severity", "high"]}, "then": 4},
                            {"case": {"$eq": ["$effective_severity", "medium"]}, "then": 3},
                            {"case": {"$eq": ["$effective_severity", "low"]}, "then": 2},
                            {"case": {"$eq": ["$effective_severity", "info"]}, "then": 1},
                        ],
                        "default": 0,
                    }
                }
            }
        },
    ]
    if normalized_severity != "all":
        pipeline.append({"$match": {"effective_severity": normalized_severity}})
    pipeline.extend(
        [
        {
            "$group": {
                "_id": "$effective_host",
                "count": {"$sum": 1},
                "highest_severity_rank": {"$max": "$severity_rank"},
            }
        },
        {"$sort": {"count": -1, "_id": 1}},
        {"$limit": 5},
        ]
    )

    results = await db.vulnerabilities.aggregate(pipeline).to_list(length=5)
    enriched_results = []
    for document in results:
        host_val = document["_id"]
        asset = await db.assets.find_one(
            {"$or": [{"host_normalized": host_val}, {"host": host_val}]},
            {"_id": 1},
        )
        enriched_results.append(
            {
                "id": str(asset.get("_id")) if asset else None,
                "host": host_val,
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

import asyncio
import base64
from datetime import datetime, timezone
import json
import re

from fastapi import APIRouter, Depends, Query
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import HTTPException
from bson import ObjectId
from pymongo import DESCENDING

from app.core.config import get_settings
from app.core.rbac import require_role
from app.db.mongo import get_database
from app.schemas.auth import CurrentUser
from app.schemas.vulnerability import (
    VulnerabilityArchiveRestoreRequest,
    VulnerabilityBulkPatchRequest,
    VulnerabilityListResponse,
    VulnerabilityPatchRequest,
)
from app.services.assets_inventory import recalculate_asset
from app.services.dashboard_snapshots import mark_dashboard_snapshot_dirty

router = APIRouter()
settings = get_settings()


def _serialize_vulnerability(document: dict) -> dict:
    normalized = dict(document)
    mongo_id = normalized.pop("_id", None)
    payload = jsonable_encoder(normalized)
    if mongo_id is not None:
        payload["id"] = str(mongo_id)

    # Flatten v2 UDM nested fields into top-level keys for API consumers.
    # Falls back to v1 flat fields when schema_version < 2 or field is absent.
    target = payload.get("target") or {}
    identity = payload.get("identity") or {}
    evidence = payload.get("evidence") or {}

    # Canonical host surface (v2: target.host_normalized / v1: host)
    if "host" not in payload or not payload["host"]:
        payload["host"] = (
            target.get("host_normalized")
            or target.get("hostname")
            or payload.get("host")
            or ""
        )

    # v1 compatibility aliases surfaced at top level
    if "name" not in payload or not payload["name"]:
        payload["name"] = identity.get("name") or ""
    if "template_id" not in payload or not payload["template_id"]:
        payload["template_id"] = (
            identity.get("standardized_rule_id")
            or identity.get("raw_rule_id")
            or payload.get("template-id")
            or ""
        )
    if "matched_at" not in payload or not payload["matched_at"]:
        payload["matched_at"] = (
            evidence.get("matched_at")
            or payload.get("matched-at")
            or ""
        )
    if "ip" not in payload or not payload["ip"]:
        payload["ip"] = target.get("ip") or payload.get("ip") or ""
    if "port" not in payload or payload["port"] is None:
        raw_port = target.get("port") or payload.get("port")
        payload["port"] = str(raw_port) if raw_port is not None else None
    else:
        payload["port"] = str(payload["port"])

    # Flatten evidence fields (v2: evidence.request/response/curl_command → top-level)
    # Falls back to v1 hyphenated keys when evidence object is absent.
    if not payload.get("request"):
        payload["request"] = evidence.get("request") or payload.get("request") or None
    if not payload.get("response"):
        payload["response"] = evidence.get("response") or payload.get("response") or None
    if not payload.get("curl_command"):
        payload["curl_command"] = (
            evidence.get("curl_command")
            or payload.get("curl-command")
            or None
        )

    return payload


def _encode_cursor(severity_rank: int, last_seen: datetime, mongo_id: ObjectId) -> str:
    payload = {
        "severity_rank": severity_rank,
        "last_seen": last_seen.isoformat(),
        "id": str(mongo_id),
    }
    return base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8")


def _decode_cursor(cursor: str) -> tuple[int, datetime, ObjectId]:
    try:
        decoded = base64.urlsafe_b64decode(cursor.encode("utf-8")).decode("utf-8")
        payload = json.loads(decoded)
        severity_rank_raw = payload.get("severity_rank")
        last_seen_raw = payload.get("last_seen")
        mongo_id_raw = payload.get("id")
        if (
            not isinstance(severity_rank_raw, int)
            or not isinstance(last_seen_raw, str)
            or not isinstance(mongo_id_raw, str)
        ):
            raise ValueError("invalid cursor payload")
        last_seen = datetime.fromisoformat(last_seen_raw)
        if last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=timezone.utc)
        mongo_id = ObjectId(mongo_id_raw)
        return severity_rank_raw, last_seen, mongo_id
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


async def _list_vulnerabilities_internal(
    *,
    include_archive: bool,
    severity: str | None,
    status_filter: str | None,
    search: str | None,
    archived_reason: str | None,
    port: str | None,
    time_field: str | None,
    date_from: str | None,
    date_to: str | None,
    cursor: str | None,
    page_size: int,
) -> VulnerabilityListResponse:
    db = get_database()
    collection = db.vulnerabilities_archive if include_archive else db.vulnerabilities
    safe_search = _sanitize_search_query(search)

    conditions: list[dict[str, object]] = []
    if severity:
        normalized_severity = severity.strip().lower()
        conditions.append({"$or": [{"override_severity": normalized_severity}, {"severity": normalized_severity}]})
    if status_filter:
        conditions.append({"status": status_filter})
    if include_archive and archived_reason:
        conditions.append({"archived_reason": archived_reason.strip()})

    if port:
        normalized_port = port.strip()
        if normalized_port:
            try:
                port_int = int(normalized_port)
                conditions.append({
                    "$or": [
                        {"target.port": port_int},
                        {"port": normalized_port},
                    ]
                })
            except ValueError:
                conditions.append({"port": normalized_port})

    if safe_search:
        conditions.append(
            {
                "$or": [
                    # v2 UDM field paths
                    {"target.host_normalized": {"$regex": safe_search, "$options": "i"}},
                    {"target.hostname": {"$regex": safe_search, "$options": "i"}},
                    {"identity.name": {"$regex": safe_search, "$options": "i"}},
                    {"identity.standardized_rule_id": {"$regex": safe_search, "$options": "i"}},
                    # v1 backward-compat field paths
                    {"host": {"$regex": safe_search, "$options": "i"}},
                    {"name": {"$regex": safe_search, "$options": "i"}},
                    {"template_id": {"$regex": safe_search, "$options": "i"}},
                    {"template-id": {"$regex": safe_search, "$options": "i"}},
                ]
            }
        )

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
        conditions.append({normalized_time_field: time_filter})

    if not conditions:
        query: dict[str, object] = {}
    elif len(conditions) == 1:
        query = conditions[0]
    else:
        query = {"$and": conditions}

    cursor_filter = None
    if cursor:
        cursor_severity_rank, cursor_last_seen, cursor_id = _decode_cursor(cursor)
        cursor_filter = {
            "$or": [
                {"severity_rank": {"$lt": cursor_severity_rank}},
                {"$and": [{"severity_rank": cursor_severity_rank}, {"last_seen": {"$lt": cursor_last_seen}}]},
                {
                    "$and": [
                        {"severity_rank": cursor_severity_rank},
                        {"last_seen": cursor_last_seen},
                        {"_id": {"$lt": cursor_id}},
                    ]
                },
            ]
        }

    total = await collection.count_documents(query)

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
            {"$sort": {"severity_rank": -1, "last_seen": DESCENDING, "_id": DESCENDING}},
            {"$limit": page_size},
        ]
    )

    documents = await collection.aggregate(pipeline).to_list(length=page_size)

    items = [_serialize_vulnerability(document) for document in documents]

    next_cursor = None
    if len(documents) == page_size:
        last_document = documents[-1]
        last_seen = last_document.get("last_seen")
        severity_rank = int(last_document.get("severity_rank", 0) or 0)
        mongo_id = last_document.get("_id")
        if isinstance(last_seen, datetime) and isinstance(mongo_id, ObjectId):
            next_cursor = _encode_cursor(severity_rank, last_seen, mongo_id)

    return VulnerabilityListResponse(
        items=items,
        total=total,
        next_cursor=next_cursor,
        page_size=page_size,
    )


@router.get("/vulns", response_model=VulnerabilityListResponse)
async def list_vulnerabilities(
    severity: str | None = Query(default=None),
    status_filter: str | None = Query(default=None, alias="status"),
    search: str | None = Query(default=None),
    include_archive: bool = Query(default=False),
    archived_reason: str | None = Query(default=None),
    port: str | None = Query(default=None),
    time_field: str | None = Query(default="last_seen"),
    date_from: str | None = Query(default=None),
    date_to: str | None = Query(default=None),
    cursor: str | None = Query(default=None),
    page_size: int = Query(default=20, ge=1, le=200),
    _: CurrentUser = Depends(require_role("admin", "viewer")),
):
    return await _list_vulnerabilities_internal(
        include_archive=include_archive,
        severity=severity,
        status_filter=status_filter,
        search=search,
        archived_reason=archived_reason,
        port=port,
        time_field=time_field,
        date_from=date_from,
        date_to=date_to,
        cursor=cursor,
        page_size=page_size,
    )


@router.get("/vulns/archive", response_model=VulnerabilityListResponse)
async def list_archived_vulnerabilities(
    severity: str | None = Query(default=None),
    status_filter: str | None = Query(default=None, alias="status"),
    search: str | None = Query(default=None),
    archived_reason: str | None = Query(default=None),
    port: str | None = Query(default=None),
    time_field: str | None = Query(default="last_seen"),
    date_from: str | None = Query(default=None),
    date_to: str | None = Query(default=None),
    cursor: str | None = Query(default=None),
    page_size: int = Query(default=20, ge=1, le=200),
    _: CurrentUser = Depends(require_role("admin", "viewer")),
):
    return await _list_vulnerabilities_internal(
        include_archive=True,
        severity=severity,
        status_filter=status_filter,
        search=search,
        archived_reason=archived_reason,
        port=port,
        time_field=time_field,
        date_from=date_from,
        date_to=date_to,
        cursor=cursor,
        page_size=page_size,
    )


@router.get("/vulns/recent")
async def recent_high_priority(_: CurrentUser = Depends(require_role("admin", "viewer"))):
    db = get_database()
    query = {
        "status": "Open",
        "$expr": {
            "$in": [
                {"$toLower": {"$ifNull": ["$override_severity", "$severity"]}},
                ["high", "critical"],
            ]
        },
    }
    cursor = db.vulnerabilities.find(query).sort("last_seen", DESCENDING).limit(10)
    return [_serialize_vulnerability(document) async for document in cursor]


@router.patch("/vulns/{vuln_id}")
async def patch_vulnerability(
    vuln_id: str,
    payload: VulnerabilityPatchRequest,
    _: CurrentUser = Depends(require_role("admin")),
):
    db = get_database()
    existing_vulnerability = await db.vulnerabilities.find_one(
        {"fingerprint": vuln_id},
        {"host": 1, "target": 1},
    )
    if not existing_vulnerability:
        raise HTTPException(status_code=404, detail="Vulnerability not found.")

    update_fields = payload.model_dump(exclude_none=True)
    if not update_fields:
        raise HTTPException(status_code=400, detail="No update payload provided.")

    update_fields["last_seen"] = datetime.now(timezone.utc)
    await db.vulnerabilities.update_one({"fingerprint": vuln_id}, {"$set": update_fields})

    # Resolve host_normalized from v2 target or v1 flat field
    host = (
        (existing_vulnerability.get("target") or {}).get("host_normalized")
        or existing_vulnerability.get("host")
    )
    if host:
        await recalculate_asset(db, str(host))
    await mark_dashboard_snapshot_dirty(db, "vulnerability-patch")

    return {"updated": True}


@router.post("/vulns/{vuln_id}/archive")
async def archive_vulnerability(
    vuln_id: str,
    _: CurrentUser = Depends(require_role("admin")),
):
    db = get_database()
    vulnerability = await db.vulnerabilities.find_one({"fingerprint": vuln_id})
    if not vulnerability:
        raise HTTPException(status_code=404, detail="Vulnerability not found.")

    archived = dict(vulnerability)
    archived_id = archived.pop("_id", None)
    archive_time = datetime.now(timezone.utc)
    archived["archived_at"] = archive_time
    archived["archived_reason"] = "manual-action"

    await db.vulnerabilities_archive.update_one(
        {"fingerprint": vuln_id},
        {"$set": archived},
        upsert=True,
    )
    if archived_id is not None:
        await db.vulnerabilities.delete_one({"_id": archived_id})
    else:
        await db.vulnerabilities.delete_one({"fingerprint": vuln_id})

    host = (
        archived.get("target", {}).get("host_normalized")
        or archived.get("host")
    )
    if host:
        await recalculate_asset(db, str(host))
    await mark_dashboard_snapshot_dirty(db, "vulnerability-archive")

    return {"archived": True}


@router.post("/vulns/bulk-triage")
async def bulk_patch_vulnerabilities(
    payload: VulnerabilityBulkPatchRequest,
    _: CurrentUser = Depends(require_role("admin")),
):
    db = get_database()
    fingerprints = sorted({item.strip() for item in payload.fingerprints if item.strip()})
    if not fingerprints:
        raise HTTPException(status_code=400, detail="No vulnerabilities selected.")

    update_fields = payload.model_dump(exclude_none=True, exclude={"fingerprints"})
    if not update_fields:
        raise HTTPException(status_code=400, detail="No update payload provided.")

    matched_vulnerabilities = await db.vulnerabilities.find(
        {"fingerprint": {"$in": fingerprints}},
        {"host": 1, "target": 1, "fingerprint": 1},
    ).to_list(length=None)
    if not matched_vulnerabilities:
        raise HTTPException(status_code=404, detail="No matching vulnerabilities found.")

    update_fields["last_seen"] = datetime.now(timezone.utc)
    result = await db.vulnerabilities.update_many(
        {"fingerprint": {"$in": fingerprints}},
        {"$set": update_fields},
    )

    affected_hosts = sorted({
        str(
            (item.get("target") or {}).get("host_normalized")
            or item.get("host")
            or ""
        )
        for item in matched_vulnerabilities
        if (item.get("target") or {}).get("host_normalized") or item.get("host")
    })
    for host in affected_hosts:
        await recalculate_asset(db, host)
    await mark_dashboard_snapshot_dirty(db, "vulnerability-bulk-triage")

    return {
        "updated": True,
        "vulnerabilities": result.modified_count,
        "assets": len(affected_hosts),
    }


@router.post("/vulns/archive/{vuln_id}/restore")
async def restore_archived_vulnerability(
    vuln_id: str,
    _: CurrentUser = Depends(require_role("admin")),
):
    db = get_database()
    archived = await db.vulnerabilities_archive.find_one({"fingerprint": vuln_id})
    if not archived:
        raise HTTPException(status_code=404, detail="Archived vulnerability not found.")

    restored = dict(archived)
    archived_id = restored.pop("_id", None)
    restored.pop("archived_at", None)
    restored.pop("archived_reason", None)
    restored["status"] = "Open"
    restored["last_seen"] = datetime.now(timezone.utc)

    await db.vulnerabilities.update_one(
        {"fingerprint": vuln_id},
        {"$set": restored},
        upsert=True,
    )
    if archived_id is not None:
        await db.vulnerabilities_archive.delete_one({"_id": archived_id})
    else:
        await db.vulnerabilities_archive.delete_one({"fingerprint": vuln_id})

    host = restored.get("host")
    if host:
        await recalculate_asset(db, str(host))
    await mark_dashboard_snapshot_dirty(db, "vulnerability-restore")

    return {"restored": True}


@router.delete("/vulns/archive/{vuln_id}")
async def delete_archived_vulnerability(
    vuln_id: str,
    _: CurrentUser = Depends(require_role("admin")),
):
    db = get_database()
    result = await db.vulnerabilities_archive.delete_one({"fingerprint": vuln_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Archived vulnerability not found.")
    return {"deleted": True}


@router.post("/vulns/archive/restore-bulk")
async def restore_archived_vulnerabilities_bulk(
    payload: VulnerabilityArchiveRestoreRequest,
    _: CurrentUser = Depends(require_role("admin")),
):
    db = get_database()
    fingerprints = sorted({item.strip() for item in payload.fingerprints if item.strip()})
    if not fingerprints:
        raise HTTPException(status_code=400, detail="No archived vulnerabilities selected.")

    archived_documents = await db.vulnerabilities_archive.find(
        {"fingerprint": {"$in": fingerprints}},
    ).to_list(length=None)
    if not archived_documents:
        raise HTTPException(status_code=404, detail="No matching archived vulnerabilities found.")

    now = datetime.now(timezone.utc)
    upsert_tasks = []
    host_set: set[str] = set()
    archive_ids = []

    for document in archived_documents:
        archived_id = document.get("_id")
        if archived_id is not None:
            archive_ids.append(archived_id)

        restored = dict(document)
        restored.pop("_id", None)
        restored.pop("archived_at", None)
        restored.pop("archived_reason", None)
        restored["status"] = "Open"
        restored["last_seen"] = now

        fingerprint = restored.get("fingerprint")
        if not fingerprint:
            continue
        upsert_tasks.append(
            db.vulnerabilities.update_one(
                {"fingerprint": fingerprint},
                {"$set": restored},
                upsert=True,
            )
        )
        host = restored.get("host")
        if host:
            host_set.add(str(host))

    if upsert_tasks:
        await asyncio.gather(*upsert_tasks)

    if archive_ids:
        await db.vulnerabilities_archive.delete_many({"_id": {"$in": archive_ids}})
    else:
        await db.vulnerabilities_archive.delete_many({"fingerprint": {"$in": fingerprints}})

    for host in sorted(host_set):
        await recalculate_asset(db, host)
    await mark_dashboard_snapshot_dirty(db, "vulnerability-restore-bulk")

    return {
        "restored": True,
        "vulnerabilities": len(archived_documents),
        "assets": len(host_set),
    }


@router.post("/vulns/archive/delete-bulk")
async def delete_archived_vulnerabilities_bulk(
    payload: VulnerabilityArchiveRestoreRequest,
    _: CurrentUser = Depends(require_role("admin")),
):
    db = get_database()
    fingerprints = sorted({item.strip() for item in payload.fingerprints if item.strip()})
    if not fingerprints:
        raise HTTPException(status_code=400, detail="No archived vulnerabilities selected.")

    result = await db.vulnerabilities_archive.delete_many({"fingerprint": {"$in": fingerprints}})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="No matching archived vulnerabilities found.")

    return {
        "deleted": True,
        "vulnerabilities": int(result.deleted_count or 0),
    }

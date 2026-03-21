from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import HTTPException
from pymongo import DESCENDING

from app.core.rbac import require_role
from app.db.mongo import get_database
from app.schemas.auth import CurrentUser
from app.schemas.vulnerability import (
    VulnerabilityBulkPatchRequest,
    VulnerabilityListResponse,
    VulnerabilityPatchRequest,
)
from app.services.assets_inventory import recalculate_asset

router = APIRouter()


def _serialize_vulnerability(document: dict) -> dict:
    normalized = dict(document)
    mongo_id = normalized.pop("_id", None)
    payload = jsonable_encoder(normalized)
    if mongo_id is not None:
        payload["id"] = str(mongo_id)
    if payload.get("port") is not None:
        payload["port"] = str(payload["port"])
    return payload


@router.get("/vulns", response_model=VulnerabilityListResponse)
async def list_vulnerabilities(
    severity: str | None = Query(default=None),
    status_filter: str | None = Query(default=None, alias="status"),
    search: str | None = Query(default=None),
    limit: int = Query(default=5000, ge=1, le=20000),
    _: CurrentUser = Depends(require_role("admin", "viewer")),
):
    db = get_database()
    query: dict[str, object] = {}
    if severity:
        query["severity"] = severity
    if status_filter:
        query["status"] = status_filter
    if search:
        query["$or"] = [
            {"host": {"$regex": search, "$options": "i"}},
            {"name": {"$regex": search, "$options": "i"}},
            {"template-id": {"$regex": search, "$options": "i"}},
        ]

    cursor = db.vulnerabilities.find(query).sort("last_seen", DESCENDING).limit(limit)
    items = [_serialize_vulnerability(document) async for document in cursor]
    return VulnerabilityListResponse(items=items, total=len(items))


@router.get("/vulns/recent")
async def recent_high_priority(_: CurrentUser = Depends(require_role("admin", "viewer"))):
    db = get_database()
    query = {"severity": {"$in": ["high", "critical"]}}
    cursor = db.vulnerabilities.find(query).sort("last_seen", DESCENDING).limit(10)
    return [_serialize_vulnerability(document) async for document in cursor]


@router.patch("/vulns/{vuln_id}")
async def patch_vulnerability(
    vuln_id: str,
    payload: VulnerabilityPatchRequest,
    _: CurrentUser = Depends(require_role("admin")),
):
    db = get_database()
    existing_vulnerability = await db.vulnerabilities.find_one({"fingerprint": vuln_id}, {"host": 1})
    if not existing_vulnerability:
        raise HTTPException(status_code=404, detail="Vulnerability not found.")

    update_fields = payload.model_dump(exclude_none=True)
    if not update_fields:
        raise HTTPException(status_code=400, detail="No update payload provided.")

    update_fields["last_seen"] = datetime.now(timezone.utc)
    await db.vulnerabilities.update_one({"fingerprint": vuln_id}, {"$set": update_fields})

    host = existing_vulnerability.get("host")
    if host:
        await recalculate_asset(db, str(host))

    return {"updated": True}


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
        {"host": 1, "fingerprint": 1},
    ).to_list(length=None)
    if not matched_vulnerabilities:
        raise HTTPException(status_code=404, detail="No matching vulnerabilities found.")

    update_fields["last_seen"] = datetime.now(timezone.utc)
    result = await db.vulnerabilities.update_many(
        {"fingerprint": {"$in": fingerprints}},
        {"$set": update_fields},
    )

    affected_hosts = sorted({str(item.get("host")) for item in matched_vulnerabilities if item.get("host")})
    for host in affected_hosts:
        await recalculate_asset(db, host)

    return {
        "updated": True,
        "vulnerabilities": result.modified_count,
        "assets": len(affected_hosts),
    }

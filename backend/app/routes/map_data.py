import asyncio
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query

from app.core.config import get_settings
from app.core.rbac import require_role
from app.db.mongo import get_database
from app.schemas.auth import CurrentUser
from app.services.dashboard_snapshots import get_snapshot_payload, is_dashboard_snapshot_dirty
from app.services.geoip import lookup_geoip, map_payload_node

router = APIRouter()
settings = get_settings()

RANK_TO_SEVERITY = {
    4: "Critical",
    3: "High",
    2: "Medium",
    1: "Low",
}

_snapshot_refresh_tasks: dict[str, asyncio.Task] = {}
_snapshot_refresh_guard = asyncio.Lock()


def _snapshot_key(limit: int) -> str:
    return f"map_data_{limit}"


async def _build_map_nodes(limit: int) -> list[dict]:
    db = get_database()
    prefetch_limit = min(2500, max(limit * 3, 320))

    # Query vulnerabilities directly — more accurate than stale `highest_severity` on assets.
    # Only Critical / High / Medium open findings; v2 UDM + v1 flat field compatibility.
    pipeline = [
        {"$match": {"status": "Open"}},
        {
            # Stage 1: resolve canonical fields (cannot self-reference in same stage)
            "$addFields": {
                "effective_severity": {"$toLower": {"$ifNull": ["$override_severity", "$severity"]}},
                # v2: target.ip → v1: ip
                "effective_ip": {"$ifNull": ["$target.ip", "$ip", ""]},
                # v2: target.host_normalized → v2: target.hostname → v1: host
                "effective_host": {
                    "$ifNull": ["$target.host_normalized", "$target.hostname", "$host", ""]
                },
            }
        },
        {
            "$match": {
                "effective_severity": {"$in": ["critical", "high", "medium"]},
                "effective_ip": {"$nin": [None, ""]},
            }
        },
        {
            # Stage 2: severity_rank uses effective_severity from stage 1
            "$addFields": {
                "severity_rank": {
                    "$switch": {
                        "branches": [
                            {"case": {"$eq": ["$effective_severity", "critical"]}, "then": 4},
                            {"case": {"$eq": ["$effective_severity", "high"]}, "then": 3},
                            {"case": {"$eq": ["$effective_severity", "medium"]}, "then": 2},
                        ],
                        "default": 0,
                    }
                }
            }
        },
        {
            "$group": {
                "_id": "$effective_ip",
                "max_severity_rank": {"$max": "$severity_rank"},
                "hosts": {"$addToSet": "$effective_host"},
            }
        },
        {
            "$project": {
                "_id": 0,
                "ip": "$_id",
                "max_severity_rank": 1,
                "asset_count": {"$size": "$hosts"},
            }
        },
        {"$sort": {"max_severity_rank": -1, "asset_count": -1, "ip": 1}},
        {"$limit": prefetch_limit},
    ]

    raw_nodes = await db.vulnerabilities.aggregate(pipeline).to_list(length=prefetch_limit)
    nodes: list[dict] = []
    for document in raw_nodes:
        ip_value = str(document.get("ip", "")).strip()
        severity_rank = int(document.get("max_severity_rank", 0) or 0)
        asset_count = int(document.get("asset_count", 0) or 0)
        if not ip_value or severity_rank < 2:
            continue

        geoip_record = lookup_geoip(ip_value)
        if geoip_record is None:
            continue

        severity = RANK_TO_SEVERITY.get(severity_rank, "Medium")
        nodes.append(
            map_payload_node(
                ip_value=ip_value,
                severity=severity,
                asset_count=max(asset_count, 1),
                geoip_record=geoip_record,
            )
        )
        if len(nodes) >= limit:
            break

    return nodes


async def _store_snapshot(limit: int, nodes: list[dict]) -> datetime:
    db = get_database()
    generated_at = datetime.now(timezone.utc)
    await db.dashboard_snapshots.update_one(
        {"_id": _snapshot_key(limit)},
        {
            "$set": {
                "payload": {"nodes": nodes},
                "generated_at": generated_at,
            }
        },
        upsert=True,
    )
    return generated_at


async def _refresh_snapshot(limit: int) -> None:
    try:
        nodes = await _build_map_nodes(limit)
        await _store_snapshot(limit, nodes)
    except Exception:
        # Snapshot refresh should never break API responses.
        return


async def _schedule_snapshot_refresh(limit: int) -> None:
    key = _snapshot_key(limit)
    async with _snapshot_refresh_guard:
        task = _snapshot_refresh_tasks.get(key)
        if task and not task.done():
            return
        task = asyncio.create_task(_refresh_snapshot(limit))
        _snapshot_refresh_tasks[key] = task

        def _cleanup(_: asyncio.Task) -> None:
            _snapshot_refresh_tasks.pop(key, None)

        task.add_done_callback(_cleanup)


@router.get("/map-data")
async def get_map_data(
    limit: int = Query(default=300, ge=50, le=1200),
    _: CurrentUser = Depends(require_role("admin", "viewer")),
):
    db = get_database()
    snapshot = await get_snapshot_payload(
        db,
        _snapshot_key(limit),
        settings.dashboard_snapshot_max_age_seconds,
        allow_stale=True,
    )

    if snapshot:
        if snapshot.get("is_stale") or await is_dashboard_snapshot_dirty(db):
            await _schedule_snapshot_refresh(limit)
        return {
            **snapshot["payload"],
            "generated_at": snapshot["generated_at"],
            "snapshot_generated_at": snapshot["generated_at"],
            "snapshot_stale": bool(snapshot.get("is_stale")),
        }

    nodes = await _build_map_nodes(limit)
    generated_at = await _store_snapshot(limit, nodes)
    return {
        "nodes": nodes,
        "generated_at": generated_at,
        "snapshot_generated_at": generated_at,
        "snapshot_stale": False,
    }

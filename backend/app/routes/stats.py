from fastapi import APIRouter, Depends, Query

from app.core.config import get_settings
from app.core.rbac import require_role
from app.db.mongo import get_database
from app.schemas.auth import CurrentUser
from app.services.dashboard_snapshots import (
    SEVERITIES,
    build_live_stats,
    build_live_tech_stack,
    build_live_trend,
    get_snapshot_payload,
    is_dashboard_snapshot_dirty,
    mark_dashboard_snapshot_dirty,
)

router = APIRouter()
settings = get_settings()


@router.get("/stats")
async def get_stats(_: CurrentUser = Depends(require_role("admin", "viewer"))):
    db = get_database()
    snapshot = await get_snapshot_payload(
        db,
        "stats",
        settings.dashboard_snapshot_max_age_seconds,
        allow_stale=True,
    )
    if snapshot:
        if snapshot.get("is_stale") or await is_dashboard_snapshot_dirty(db):
            await mark_dashboard_snapshot_dirty(db, "stats-read-stale")
        return {
            **snapshot["payload"],
            "snapshot_generated_at": snapshot["generated_at"],
        }

    payload = await build_live_stats(db)
    return {
        **payload,
        "snapshot_generated_at": None,
    }


@router.get("/stats/trend")
async def get_attack_surface_trend(
    days: int = Query(default=7, ge=7, le=30),
    _: CurrentUser = Depends(require_role("admin", "viewer")),
):
    db = get_database()
    snapshot = await get_snapshot_payload(
        db,
        f"trend_{days}",
        settings.dashboard_snapshot_max_age_seconds,
        allow_stale=True,
    )
    if snapshot:
        if snapshot.get("is_stale") or await is_dashboard_snapshot_dirty(db):
            await mark_dashboard_snapshot_dirty(db, f"trend-{days}-read-stale")
        return {
            **snapshot["payload"],
            "snapshot_generated_at": snapshot["generated_at"],
        }

    payload = await build_live_trend(db, days)
    return {
        **payload,
        "snapshot_generated_at": None,
    }


@router.get("/stats/tech-stack")
async def get_exposed_tech_stack(_: CurrentUser = Depends(require_role("admin", "viewer"))):
    db = get_database()
    snapshot = await get_snapshot_payload(
        db,
        "tech_stack",
        settings.dashboard_snapshot_max_age_seconds,
        allow_stale=True,
    )
    if snapshot:
        if snapshot.get("is_stale") or await is_dashboard_snapshot_dirty(db):
            await mark_dashboard_snapshot_dirty(db, "tech-stack-read-stale")
        return snapshot["payload"]
    return await build_live_tech_stack(db, 40)

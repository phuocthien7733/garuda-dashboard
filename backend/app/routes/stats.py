from datetime import datetime, timezone

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
    clear_dashboard_snapshot_dirty,
    get_snapshot_payload,
    is_dashboard_snapshot_dirty,
)

router = APIRouter()
settings = get_settings()


async def _rebuild_stats_snapshot(db) -> tuple[dict, datetime]:
    """Recompute live stats, persist to dashboard_snapshots, clear dirty flag."""
    payload = await build_live_stats(db)
    generated_at = datetime.now(timezone.utc)
    await db.dashboard_snapshots.update_one(
        {"_id": "stats"},
        {"$set": {"payload": payload, "generated_at": generated_at}},
        upsert=True,
    )
    await clear_dashboard_snapshot_dirty(db)
    return payload, generated_at


async def _rebuild_trend_snapshot(db, days: int) -> tuple[dict, datetime]:
    """Recompute live trend, persist to dashboard_snapshots."""
    payload = await build_live_trend(db, days)
    generated_at = datetime.now(timezone.utc)
    await db.dashboard_snapshots.update_one(
        {"_id": f"trend_{days}"},
        {"$set": {"payload": payload, "generated_at": generated_at}},
        upsert=True,
    )
    return payload, generated_at


async def _rebuild_tech_stack_snapshot(db) -> tuple[list, datetime]:
    """Recompute live tech stack, persist to dashboard_snapshots."""
    payload = await build_live_tech_stack(db, 40)
    generated_at = datetime.now(timezone.utc)
    await db.dashboard_snapshots.update_one(
        {"_id": "tech_stack"},
        {"$set": {"payload": payload, "generated_at": generated_at}},
        upsert=True,
    )
    return payload, generated_at


@router.get("/stats")
async def get_stats(_: CurrentUser = Depends(require_role("admin", "viewer"))):
    db = get_database()

    # Only serve from cache when nothing has changed since the snapshot was built.
    if not await is_dashboard_snapshot_dirty(db):
        snapshot = await get_snapshot_payload(
            db,
            "stats",
            settings.dashboard_snapshot_max_age_seconds,
        )
        if snapshot:
            return {
                **snapshot["payload"],
                "snapshot_generated_at": snapshot["generated_at"],
            }

    # Dirty or no fresh snapshot → recompute, persist, clear dirty flag.
    payload, generated_at = await _rebuild_stats_snapshot(db)
    return {
        **payload,
        "snapshot_generated_at": generated_at,
    }


@router.get("/stats/trend")
async def get_attack_surface_trend(
    days: int = Query(default=7, ge=7, le=30),
    _: CurrentUser = Depends(require_role("admin", "viewer")),
):
    db = get_database()

    if not await is_dashboard_snapshot_dirty(db):
        snapshot = await get_snapshot_payload(
            db,
            f"trend_{days}",
            settings.dashboard_snapshot_max_age_seconds,
        )
        if snapshot:
            return {
                **snapshot["payload"],
                "snapshot_generated_at": snapshot["generated_at"],
            }

    payload, generated_at = await _rebuild_trend_snapshot(db, days)
    return {
        **payload,
        "snapshot_generated_at": generated_at,
    }


@router.get("/stats/tech-stack")
async def get_exposed_tech_stack(_: CurrentUser = Depends(require_role("admin", "viewer"))):
    db = get_database()

    if not await is_dashboard_snapshot_dirty(db):
        snapshot = await get_snapshot_payload(
            db,
            "tech_stack",
            settings.dashboard_snapshot_max_age_seconds,
        )
        if snapshot:
            return snapshot["payload"]

    payload, _ = await _rebuild_tech_stack_snapshot(db)
    return payload

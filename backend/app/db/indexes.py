from pymongo import ASCENDING, DESCENDING

from app.core.config import get_settings
from app.db.mongo import get_database


async def ensure_indexes() -> None:
    db = get_database()
    settings = get_settings()
    retention_seconds = max(1, int(settings.vulnerability_archive_retention_days)) * 24 * 60 * 60
    await db.vulnerabilities.create_index([("fingerprint", ASCENDING)], unique=True)
    await db.vulnerabilities.create_index([("status", ASCENDING), ("severity", ASCENDING), ("last_seen", DESCENDING)])
    await db.vulnerabilities.create_index([("status", ASCENDING), ("last_seen", DESCENDING)])
    await db.vulnerabilities.create_index([("host", ASCENDING), ("status", ASCENDING), ("last_seen", DESCENDING)])
    await db.vulnerabilities.create_index([("asset_id", ASCENDING), ("status", ASCENDING), ("severity", ASCENDING), ("last_seen", DESCENDING)])
    await db.vulnerabilities.create_index([("first_seen", DESCENDING)])
    await db.vulnerabilities.create_index([("last_seen", DESCENDING)])
    await db.vulnerabilities.create_index([("template_id", ASCENDING)])
    await db.vulnerabilities.create_index([("scanner", ASCENDING), ("status", ASCENDING), ("last_seen", DESCENDING)])
    await db.vulnerabilities.create_index([("target.host_normalized", ASCENDING), ("status", ASCENDING)])
    await db.vulnerabilities.create_index([("host_normalized", ASCENDING), ("last_seen", DESCENDING)])
    await db.vulnerabilities.create_index([("asset_id", ASCENDING)])

    # ── Assets: migrate old non-sparse unique index on 'host' if it exists ────
    # v2 assets use host_normalized as the unique key; the old v1 'host' unique
    # non-sparse index blocks all v2 inserts because null counts as a unique value.
    try:
        index_info = await db.assets.index_information()
        old_host_idx = index_info.get("host_1", {})
        if old_host_idx.get("unique") and not old_host_idx.get("sparse"):
            await db.assets.drop_index("host_1")
    except Exception:
        pass  # index may not exist or already correct — safe to ignore

    # Non-unique sparse index on 'host' for backward-compat v1 queries
    await db.assets.create_index([("host", ASCENDING)], sparse=True)
    # Primary dedup key for v2 assets
    await db.assets.create_index([("host_normalized", ASCENDING)], unique=True, sparse=True)
    await db.assets.create_index([("highest_severity", ASCENDING), ("vulnerability_count", DESCENDING), ("last_seen", DESCENDING)])
    await db.assets.create_index([("last_seen", DESCENDING)])
    await db.assets.create_index([("type", ASCENDING), ("highest_severity", ASCENDING)])
    await db.vulnerabilities_archive.create_index([("fingerprint", ASCENDING)], unique=True)
    await db.vulnerabilities_archive.create_index([("status", ASCENDING), ("severity", ASCENDING), ("last_seen", DESCENDING)])
    await db.vulnerabilities_archive.create_index([("host", ASCENDING), ("last_seen", DESCENDING)])
    archive_index_info = await db.vulnerabilities_archive.index_information()
    ttl_index_name = "archived_at_ttl"
    existing_ttl = archive_index_info.get(ttl_index_name)
    if existing_ttl and existing_ttl.get("expireAfterSeconds") != retention_seconds:
        await db.vulnerabilities_archive.drop_index(ttl_index_name)
        existing_ttl = None
    if not existing_ttl:
        await db.vulnerabilities_archive.create_index(
            [("archived_at", ASCENDING)],
            name=ttl_index_name,
            expireAfterSeconds=retention_seconds,
        )
    await db.dashboard_snapshots.create_index([("generated_at", DESCENDING)])
    await db.users.create_index([("username", ASCENDING)], unique=True)
    await db.users.create_index([("email", ASCENDING)], unique=True, sparse=True)
    await db.mfa_challenges.create_index([("challenge_id", ASCENDING)], unique=True)
    await db.mfa_challenges.create_index([("expires_at", ASCENDING)], expireAfterSeconds=0)
    await db.auth_rate_limits.create_index([("expires_at", ASCENDING)], expireAfterSeconds=0)
    await db.revoked_tokens.create_index([("token_id", ASCENDING)], unique=True)
    await db.revoked_tokens.create_index([("expires_at", ASCENDING)], expireAfterSeconds=0)

    # Hunting Maps
    await db.hunting_maps.create_index([("updated_at", DESCENDING)])
    await db.hunting_maps.create_index([("created_by", ASCENDING)])

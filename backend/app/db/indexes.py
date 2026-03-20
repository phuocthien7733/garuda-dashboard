from pymongo import ASCENDING

from app.db.mongo import get_database


async def ensure_indexes() -> None:
    db = get_database()
    await db.vulnerabilities.create_index([("fingerprint", ASCENDING)], unique=True)
    await db.vulnerabilities.create_index([("status", ASCENDING), ("severity", ASCENDING)])
    await db.vulnerabilities.create_index([("asset_id", ASCENDING)])
    await db.assets.create_index([("host", ASCENDING)], unique=True)
    await db.users.create_index([("username", ASCENDING)], unique=True)
    await db.revoked_tokens.create_index([("token_id", ASCENDING)], unique=True)
    await db.revoked_tokens.create_index([("expires_at", ASCENDING)], expireAfterSeconds=0)

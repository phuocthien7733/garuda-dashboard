import hashlib
from datetime import datetime, timezone

from fastapi import HTTPException, Request, status
from pymongo import ReturnDocument


def extract_client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        first_ip = forwarded_for.split(",")[0].strip()
        if first_ip:
            return first_ip

    real_ip = request.headers.get("x-real-ip", "").strip()
    if real_ip:
        return real_ip

    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def _build_limit_bucket_id(scope: str, identifier: str, window_seconds: int, now: datetime) -> str:
    bucket = int(now.timestamp()) // window_seconds
    identifier_hash = hashlib.sha256(identifier.encode("utf-8")).hexdigest()[:20]
    return f"{scope}:{window_seconds}:{bucket}:{identifier_hash}"


async def consume_rate_limit(
    db,
    *,
    scope: str,
    identifier: str,
    limit: int,
    window_seconds: int,
) -> None:
    if limit <= 0 or window_seconds <= 0:
        return

    now = datetime.now(timezone.utc)
    bucket = int(now.timestamp()) // window_seconds
    bucket_end_epoch = (bucket + 1) * window_seconds
    retry_after_seconds = max(1, bucket_end_epoch - int(now.timestamp()))
    document_id = _build_limit_bucket_id(scope, identifier, window_seconds, now)
    expires_at = datetime.fromtimestamp(bucket_end_epoch + window_seconds, tz=timezone.utc)

    document = await db.auth_rate_limits.find_one_and_update(
        {"_id": document_id},
        {
            "$inc": {"count": 1},
            "$set": {"updated_at": now},
            "$setOnInsert": {
                "scope": scope,
                "window_seconds": window_seconds,
                "bucket": bucket,
                "created_at": now,
                "expires_at": expires_at,
            },
        },
        upsert=True,
        return_document=ReturnDocument.AFTER,
    )
    current_count = int((document or {}).get("count", 0))

    if current_count > limit:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests. Please try again later.",
            headers={"Retry-After": str(retry_after_seconds)},
        )

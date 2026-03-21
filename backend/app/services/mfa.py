from datetime import datetime, timedelta, timezone
from uuid import uuid4

from app.core.config import get_settings
from app.core.security import generate_mfa_code, hash_mfa_code, verify_mfa_code


def mask_email(email: str | None) -> str:
    if not email or "@" not in email:
        return "--"

    local_part, domain = email.split("@", 1)
    visible = local_part[:2]
    masked_local = visible + "*" * max(len(local_part) - len(visible), 1)
    return f"{masked_local}@{domain}"


async def issue_mfa_challenge(db, username: str, email: str) -> tuple[dict, str]:
    settings = get_settings()
    challenge_id = uuid4().hex
    code = generate_mfa_code(settings.mfa_code_length)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=settings.mfa_code_expiration_minutes)

    document = {
        "challenge_id": challenge_id,
        "username": username,
        "email": email,
        "code_hash": hash_mfa_code(challenge_id, code),
        "created_at": datetime.now(timezone.utc),
        "expires_at": expires_at,
    }

    await db.mfa_challenges.insert_one(document)
    return document, code


async def refresh_mfa_challenge(db, challenge: dict) -> tuple[dict, str]:
    settings = get_settings()
    code = generate_mfa_code(settings.mfa_code_length)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=settings.mfa_code_expiration_minutes)
    update = {
        "code_hash": hash_mfa_code(challenge["challenge_id"], code),
        "created_at": datetime.now(timezone.utc),
        "expires_at": expires_at,
    }
    await db.mfa_challenges.update_one({"challenge_id": challenge["challenge_id"]}, {"$set": update})
    challenge.update(update)
    return challenge, code


def is_mfa_code_valid(challenge: dict, code: str) -> bool:
    expires_at = challenge.get("expires_at")
    if expires_at and expires_at < datetime.now(timezone.utc):
        return False
    return verify_mfa_code(challenge["challenge_id"], code, challenge["code_hash"])

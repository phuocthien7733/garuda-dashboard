import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import bcrypt
import jwt

from app.core.config import get_settings


def verify_password(plain_password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        return False


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def create_access_token(subject: str, role: str) -> str:
    settings = get_settings()
    expires_at = datetime.now(timezone.utc) + timedelta(hours=settings.jwt_expiration_hours)
    payload = {
        "sub": subject,
        "role": role.lower(),
        "exp": expires_at,
        "jti": uuid4().hex,
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def generate_mfa_code(length: int | None = None) -> str:
    settings = get_settings()
    code_length = length or settings.mfa_code_length
    return "".join(secrets.choice("0123456789") for _ in range(code_length))


def hash_mfa_code(challenge_id: str, code: str) -> str:
    settings = get_settings()
    payload = f"{settings.jwt_secret}:{challenge_id}:{code}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def verify_mfa_code(challenge_id: str, code: str, expected_hash: str) -> bool:
    return hmac.compare_digest(hash_mfa_code(challenge_id, code), expected_hash)

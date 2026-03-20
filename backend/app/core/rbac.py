from datetime import datetime, timezone
from typing import Callable

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.config import get_settings
from app.db.mongo import get_database
from app.schemas.auth import CurrentUser

bearer_scheme = HTTPBearer(auto_error=True)
VALID_ROLES = {"admin", "viewer"}


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> CurrentUser:
    settings = get_settings()
    token = credentials.credentials

    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token.",
        ) from exc

    subject = payload.get("sub")
    token_role = str(payload.get("role", "")).lower()
    token_id = str(payload.get("jti", ""))
    if not subject or not token_role or not token_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token is missing required claims.",
        )

    if token_role not in VALID_ROLES:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token contains an invalid role.",
        )

    db = get_database()
    revoked_token = await db.revoked_tokens.find_one({"token_id": token_id})
    if revoked_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token has been revoked.",
        )

    user = await db.users.find_one({"username": subject})
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authenticated user no longer exists.",
        )

    current_role = str(user.get("role", "")).lower()
    if current_role not in VALID_ROLES:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authenticated user has an invalid role.",
        )

    if current_role != token_role:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token is stale. Please sign in again.",
        )

    expires_at = payload.get("exp")
    expires_at_datetime = None
    if isinstance(expires_at, (int, float)):
        expires_at_datetime = datetime.fromtimestamp(expires_at, tz=timezone.utc)

    return CurrentUser(
        username=subject,
        role=current_role,
        token_id=token_id,
        expires_at=expires_at_datetime,
    )


def require_role(*allowed_roles: str) -> Callable[[CurrentUser], CurrentUser]:
    async def dependency(current_user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to access this resource.",
            )
        return current_user

    return dependency

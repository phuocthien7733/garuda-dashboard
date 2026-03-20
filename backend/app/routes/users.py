from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException

from app.core.rbac import require_role
from app.core.security import hash_password
from app.db.mongo import get_database
from app.schemas.auth import CurrentUser
from app.schemas.user import PasswordResetRequest, UserCreate

router = APIRouter()
VALID_ROLES = {"admin", "viewer"}


@router.post("/users")
async def create_user(
    payload: UserCreate,
    _: CurrentUser = Depends(require_role("admin")),
):
    db = get_database()
    normalized_role = payload.role.lower()
    if normalized_role not in VALID_ROLES:
        raise HTTPException(status_code=422, detail="Role must be either admin or viewer.")

    existing_user = await db.users.find_one({"username": payload.username})
    if existing_user:
        raise HTTPException(status_code=409, detail="Username already exists.")

    document = {
        "username": payload.username,
        "password_hash": hash_password(payload.password),
        "role": normalized_role,
        "created_at": datetime.now(timezone.utc),
    }
    await db.users.insert_one(document)
    return {"created": True}


@router.patch("/users/{username}/password")
async def reset_password(
    username: str,
    payload: PasswordResetRequest,
    _: CurrentUser = Depends(require_role("admin")),
):
    db = get_database()
    result = await db.users.update_one(
        {"username": username},
        {"$set": {"password_hash": hash_password(payload.password)}},
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="User not found.")
    return {"updated": True}

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException

from app.core.rbac import require_role
from app.core.security import hash_password
from app.db.mongo import get_database
from app.schemas.auth import CurrentUser
from app.schemas.user import PasswordResetRequest, UserCreate, UserResponse, UserUpdate

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

    normalized_email = payload.email.strip().lower()
    existing_email = await db.users.find_one({"email": normalized_email})
    if existing_email:
        raise HTTPException(status_code=409, detail="Email already exists.")

    document = {
        "username": payload.username,
        "email": normalized_email,
        "password_hash": hash_password(payload.password),
        "role": normalized_role,
        "mfa_enabled": bool(payload.mfa_enabled),
        "created_at": datetime.now(timezone.utc),
    }
    await db.users.insert_one(document)
    return {"created": True}


@router.get("/users", response_model=list[UserResponse])
async def list_users(
    _: CurrentUser = Depends(require_role("admin")),
) -> list[UserResponse]:
    db = get_database()
    users = await db.users.find({}, {"password_hash": 0}).sort("created_at", -1).to_list(length=None)
    return [
        UserResponse(
            username=user.get("username", ""),
            email=user.get("email"),
            role=user.get("role", "viewer"),
            mfa_enabled=bool(user.get("mfa_enabled")),
            created_at=user.get("created_at"),
            updated_at=user.get("updated_at"),
        )
        for user in users
    ]


@router.patch("/users/{username}", response_model=UserResponse)
async def update_user(
    username: str,
    payload: UserUpdate,
    current_user: CurrentUser = Depends(require_role("admin")),
) -> UserResponse:
    db = get_database()
    user = await db.users.find_one({"username": username})
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    normalized_username = payload.username.strip()
    normalized_email = payload.email.strip().lower()
    normalized_role = payload.role.lower()

    if normalized_role not in VALID_ROLES:
        raise HTTPException(status_code=422, detail="Role must be either admin or viewer.")

    if username == current_user.username and normalized_role != current_user.role:
        raise HTTPException(status_code=400, detail="You cannot change your own role here.")

    existing_username = await db.users.find_one(
        {"username": normalized_username, "_id": {"$ne": user["_id"]}},
        {"_id": 1},
    )
    if existing_username:
        raise HTTPException(status_code=409, detail="Username already exists.")

    existing_email = await db.users.find_one(
        {"email": normalized_email, "_id": {"$ne": user["_id"]}},
        {"_id": 1},
    )
    if existing_email:
        raise HTTPException(status_code=409, detail="Email already exists.")

    update_fields = {
        "username": normalized_username,
        "email": normalized_email,
        "role": normalized_role,
        "mfa_enabled": bool(payload.mfa_enabled),
        "updated_at": datetime.now(timezone.utc),
    }
    if payload.password:
        update_fields["password_hash"] = hash_password(payload.password)

    await db.users.update_one({"_id": user["_id"]}, {"$set": update_fields})
    updated_user = await db.users.find_one({"_id": user["_id"]}, {"password_hash": 0})
    return UserResponse(
        username=updated_user.get("username", ""),
        email=updated_user.get("email"),
        role=updated_user.get("role", "viewer"),
        mfa_enabled=bool(updated_user.get("mfa_enabled")),
        created_at=updated_user.get("created_at"),
        updated_at=updated_user.get("updated_at"),
    )


@router.delete("/users/{username}")
async def delete_user(
    username: str,
    current_user: CurrentUser = Depends(require_role("admin")),
):
    if username == current_user.username:
        raise HTTPException(status_code=400, detail="You cannot delete your own account.")

    db = get_database()
    result = await db.users.delete_one({"username": username})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="User not found.")
    return {"deleted": True}


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

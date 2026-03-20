from fastapi import APIRouter, Depends, HTTPException, status

from app.core.rbac import get_current_user
from app.core.security import create_access_token, verify_password
from app.db.mongo import get_database
from app.schemas.auth import CurrentUser, LoginRequest, SessionResponse, TokenResponse

router = APIRouter()


@router.post("/login", response_model=TokenResponse)
async def login(payload: LoginRequest) -> TokenResponse:
    db = get_database()
    user = await db.users.find_one({"username": payload.username})
    if not user or not verify_password(payload.password, user.get("password_hash", "")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
        )

    role = str(user.get("role", "viewer")).lower()
    if role not in {"admin", "viewer"}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User role is not allowed to sign in.",
        )

    token = create_access_token(payload.username, role)
    return TokenResponse(access_token=token, username=payload.username, role=role)


@router.get("/me", response_model=SessionResponse)
async def get_session(current_user: CurrentUser = Depends(get_current_user)) -> SessionResponse:
    return SessionResponse(username=current_user.username, role=current_user.role)


@router.post("/logout")
async def logout(current_user: CurrentUser = Depends(get_current_user)):
    db = get_database()
    revoke_document = {
        "token_id": current_user.token_id,
        "username": current_user.username,
    }
    if current_user.expires_at is not None:
        revoke_document["expires_at"] = current_user.expires_at

    await db.revoked_tokens.update_one(
        {"token_id": current_user.token_id},
        {"$set": revoke_document},
        upsert=True,
    )
    return {"logged_out": True}

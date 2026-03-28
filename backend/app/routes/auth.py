import asyncio
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.core.rbac import get_current_user
from app.core.security import create_access_token, hash_password, verify_password
from app.db.mongo import get_database
from app.schemas.auth import (
    CurrentUser,
    LoginRequest,
    LoginResponse,
    MfaChallengeResponse,
    MfaResendRequest,
    MfaVerifyRequest,
    ProfileUpdateRequest,
    SessionResponse,
    TokenResponse,
)
from app.services.mailer import send_mfa_email
from app.services.mfa import issue_mfa_challenge, is_mfa_code_valid, mask_email, refresh_mfa_challenge
from app.services.rate_limiter import consume_rate_limit, extract_client_ip
from app.core.config import get_settings

router = APIRouter()
settings = get_settings()


@router.post("/login", response_model=LoginResponse)
async def login(payload: LoginRequest, request: Request) -> LoginResponse:
    db = get_database()
    normalized_username = payload.username.strip()
    username = normalized_username.lower()
    client_ip = extract_client_ip(request)
    await consume_rate_limit(
        db,
        scope="auth-login-ip",
        identifier=client_ip,
        limit=settings.auth_login_rate_limit_per_ip,
        window_seconds=settings.auth_login_rate_limit_window_seconds,
    )
    await consume_rate_limit(
        db,
        scope="auth-login-username",
        identifier=username or "empty",
        limit=settings.auth_login_rate_limit_per_username,
        window_seconds=settings.auth_login_rate_limit_window_seconds,
    )

    user = await db.users.find_one({"username": normalized_username})
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

    email = user.get("email")
    if user.get("mfa_enabled"):
        if not email:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="MFA is enabled for this account, but no email is configured.",
            )

        challenge, otp_code = await issue_mfa_challenge(db, normalized_username, email)
        try:
            await asyncio.to_thread(
                send_mfa_email,
                email,
                normalized_username,
                otp_code,
                settings.mfa_code_expiration_minutes,
            )
        except RuntimeError as exc:
            await db.mfa_challenges.delete_one({"challenge_id": challenge["challenge_id"]})
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=str(exc),
            ) from exc
        except Exception as exc:
            await db.mfa_challenges.delete_one({"challenge_id": challenge["challenge_id"]})
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Failed to deliver the MFA email challenge.",
            ) from exc

        return LoginResponse(
            username=normalized_username,
            email=email,
            mfa_required=True,
            challenge_id=challenge["challenge_id"],
            challenge_expires_in_seconds=settings.mfa_code_expiration_minutes * 60,
            masked_email=mask_email(email),
        )

    token = create_access_token(normalized_username, role)
    return LoginResponse(
        access_token=token,
        username=normalized_username,
        role=role,
        email=email,
    )


@router.get("/me", response_model=SessionResponse)
async def get_session(current_user: CurrentUser = Depends(get_current_user)) -> SessionResponse:
    db = get_database()
    user = await db.users.find_one({"username": current_user.username})
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authenticated user no longer exists.",
        )

    return SessionResponse(
        username=current_user.username,
        email=user.get("email"),
        role=current_user.role,
        created_at=user.get("created_at"),
        mfa_enabled=bool(user.get("mfa_enabled")),
    )


@router.patch("/me", response_model=TokenResponse)
async def update_profile(
    payload: ProfileUpdateRequest,
    current_user: CurrentUser = Depends(get_current_user),
) -> TokenResponse:
    db = get_database()
    user = await db.users.find_one({"username": current_user.username})
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Authenticated user no longer exists.",
        )

    normalized_username = payload.username.strip()
    normalized_email = payload.email.strip().lower()

    if not normalized_username:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Username is required.")

    existing_username = await db.users.find_one(
        {"username": normalized_username, "_id": {"$ne": user["_id"]}},
        {"_id": 1},
    )
    if existing_username:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already exists.")

    existing_email = await db.users.find_one(
        {"email": normalized_email, "_id": {"$ne": user["_id"]}},
        {"_id": 1},
    )
    if existing_email:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already exists.")

    if payload.current_password and not payload.new_password:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="No protected profile change requested for the provided current password.",
        )

    if payload.new_password and not payload.current_password:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Current password is required to change password.",
        )

    update_fields = {
        "username": normalized_username,
        "email": normalized_email,
        "mfa_enabled": bool(payload.mfa_enabled),
        "updated_at": datetime.now(timezone.utc),
    }

    if payload.new_password:
        current_password = payload.current_password or ""
        if not verify_password(current_password, user.get("password_hash", "")):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Current password is incorrect.",
            )
    if payload.new_password:
        update_fields["password_hash"] = hash_password(payload.new_password)

    await db.users.update_one({"_id": user["_id"]}, {"$set": update_fields})
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

    access_token = create_access_token(normalized_username, current_user.role)
    return TokenResponse(
        access_token=access_token,
        username=normalized_username,
        role=current_user.role,
        email=normalized_email,
    )


@router.post("/mfa/verify", response_model=TokenResponse)
async def verify_mfa(payload: MfaVerifyRequest, request: Request) -> TokenResponse:
    db = get_database()
    client_ip = extract_client_ip(request)
    await consume_rate_limit(
        db,
        scope="auth-mfa-verify-ip",
        identifier=client_ip,
        limit=settings.auth_mfa_verify_rate_limit_per_ip,
        window_seconds=settings.auth_mfa_verify_rate_limit_window_seconds,
    )

    challenge = await db.mfa_challenges.find_one({"challenge_id": payload.challenge_id})
    if not challenge:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="MFA challenge not found or already expired.",
        )

    if not is_mfa_code_valid(challenge, payload.code.strip()):
        failed_attempts = int(challenge.get("failed_attempts", 0)) + 1
        if failed_attempts >= settings.mfa_verify_max_attempts:
            await db.mfa_challenges.delete_one({"challenge_id": payload.challenge_id})
        else:
            await db.mfa_challenges.update_one(
                {"challenge_id": payload.challenge_id},
                {"$set": {"failed_attempts": failed_attempts}},
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired MFA code.",
        )

    user = await db.users.find_one({"username": challenge["username"]})
    if not user:
        await db.mfa_challenges.delete_one({"challenge_id": payload.challenge_id})
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    role = str(user.get("role", "viewer")).lower()
    if role not in {"admin", "viewer"}:
        await db.mfa_challenges.delete_one({"challenge_id": payload.challenge_id})
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User role is not allowed to sign in.")

    await db.mfa_challenges.delete_one({"challenge_id": payload.challenge_id})
    token = create_access_token(user["username"], role)
    return TokenResponse(
        access_token=token,
        username=user["username"],
        role=role,
        email=user.get("email"),
    )


@router.post("/mfa/resend", response_model=MfaChallengeResponse)
async def resend_mfa(payload: MfaResendRequest, request: Request) -> MfaChallengeResponse:
    db = get_database()
    client_ip = extract_client_ip(request)
    await consume_rate_limit(
        db,
        scope="auth-mfa-resend-ip",
        identifier=client_ip,
        limit=settings.auth_mfa_resend_rate_limit_per_ip,
        window_seconds=settings.auth_mfa_resend_rate_limit_window_seconds,
    )

    challenge = await db.mfa_challenges.find_one({"challenge_id": payload.challenge_id})
    if not challenge:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="MFA challenge not found or already expired.",
        )

    now = datetime.now(timezone.utc)
    last_sent_at = challenge.get("last_sent_at") or challenge.get("created_at")
    if isinstance(last_sent_at, datetime):
        if last_sent_at.tzinfo is None:
            last_sent_at = last_sent_at.replace(tzinfo=timezone.utc)
        cooldown_seconds = max(0, settings.mfa_resend_cooldown_seconds)
        elapsed = (now - last_sent_at).total_seconds()
        if cooldown_seconds and elapsed < cooldown_seconds:
            retry_after = int(cooldown_seconds - elapsed) + 1
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Please wait before requesting another MFA code.",
                headers={"Retry-After": str(max(1, retry_after))},
            )

    challenge, otp_code = await refresh_mfa_challenge(db, challenge)
    try:
        await asyncio.to_thread(
            send_mfa_email,
            challenge["email"],
            challenge["username"],
            otp_code,
            settings.mfa_code_expiration_minutes,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to deliver the MFA email challenge.",
        ) from exc

    return MfaChallengeResponse(
        challenge_id=challenge["challenge_id"],
        username=challenge["username"],
        masked_email=mask_email(challenge["email"]),
        challenge_expires_in_seconds=settings.mfa_code_expiration_minutes * 60,
    )


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

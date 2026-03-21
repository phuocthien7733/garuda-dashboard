from datetime import datetime

from pydantic import BaseModel, EmailStr


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str | None = None
    token_type: str = "bearer"
    username: str
    role: str | None = None
    email: str | None = None
    expires_in_hours: int | None = 18
    mfa_required: bool = False
    challenge_id: str | None = None
    challenge_expires_in_seconds: int | None = None
    masked_email: str | None = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    role: str
    email: str | None = None
    expires_in_hours: int = 18


class CurrentUser(BaseModel):
    username: str
    role: str
    token_id: str
    expires_at: datetime | None = None


class SessionResponse(BaseModel):
    username: str
    email: str | None = None
    role: str
    created_at: datetime | None = None
    mfa_enabled: bool = False


class ProfileUpdateRequest(BaseModel):
    username: str
    email: EmailStr
    mfa_enabled: bool = False
    current_password: str | None = None
    new_password: str | None = None


class MfaVerifyRequest(BaseModel):
    challenge_id: str
    code: str


class MfaResendRequest(BaseModel):
    challenge_id: str


class MfaChallengeResponse(BaseModel):
    challenge_id: str
    username: str
    masked_email: str
    challenge_expires_in_seconds: int

from datetime import datetime

from pydantic import BaseModel, EmailStr


class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    role: str
    mfa_enabled: bool = False


class PasswordResetRequest(BaseModel):
    password: str


class UserUpdate(BaseModel):
    username: str
    email: EmailStr
    role: str
    mfa_enabled: bool = False
    password: str | None = None


class UserResponse(BaseModel):
    username: str
    email: str | None = None
    role: str
    mfa_enabled: bool = False
    created_at: datetime | None = None
    updated_at: datetime | None = None

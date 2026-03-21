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


class UserResponse(BaseModel):
    username: str
    email: EmailStr | None = None
    role: str
    mfa_enabled: bool = False
    created_at: datetime | None = None

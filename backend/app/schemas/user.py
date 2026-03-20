from datetime import datetime

from pydantic import BaseModel


class UserCreate(BaseModel):
    username: str
    password: str
    role: str


class PasswordResetRequest(BaseModel):
    password: str


class UserResponse(BaseModel):
    username: str
    role: str
    created_at: datetime | None = None

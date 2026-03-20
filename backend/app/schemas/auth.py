from datetime import datetime

from pydantic import BaseModel


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    role: str
    expires_in_hours: int = 18


class CurrentUser(BaseModel):
    username: str
    role: str
    token_id: str
    expires_at: datetime | None = None


class SessionResponse(BaseModel):
    username: str
    role: str

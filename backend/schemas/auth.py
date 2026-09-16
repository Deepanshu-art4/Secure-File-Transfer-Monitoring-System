from pydantic import BaseModel, Field


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    username: str


class TokenPayload(BaseModel):
    sub: str
    role: str
    exp: int


class UserLogin(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, description="Username or email for authentication")
    password: str = Field(..., min_length=6, max_length=128, description="Plaintext password")

from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field
from backend.models.user import UserRole

EMAIL_REGEX = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"


class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_-]+$")
    email: str = Field(..., max_length=120, pattern=EMAIL_REGEX)


class UserCreate(UserBase):
    password: str = Field(..., min_length=8, max_length=128, description="Minimum 8 characters password")
    role: Optional[UserRole] = UserRole.USER


class UserUpdate(BaseModel):
    email: Optional[str] = Field(None, max_length=120, pattern=EMAIL_REGEX)
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None


class UserOut(UserBase):
    id: int
    role: UserRole
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime] = None

    model_config = {
        "from_attributes": True
    }


class UserListOut(BaseModel):
    total: int
    items: List[UserOut]

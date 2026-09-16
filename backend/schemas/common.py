from typing import Optional, Any
from pydantic import BaseModel


class MessageResponse(BaseModel):
    message: str
    detail: Optional[str] = None
    data: Optional[Any] = None


class ErrorResponse(BaseModel):
    error: str
    detail: Optional[str] = None

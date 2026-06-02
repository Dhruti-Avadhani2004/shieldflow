from pydantic import BaseModel
from typing import Optional


class Finding(BaseModel):
    tool: str
    type: str
    title: str
    severity: str

    file: Optional[str] = None
    line: Optional[int] = None
    description: Optional[str] = None

    status: str = "OPEN"
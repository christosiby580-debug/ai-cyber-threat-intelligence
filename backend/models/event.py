from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class SecurityEvent(BaseModel):
    """
    Normalized security event format shared between
    Member 1 (Backend) and Member 2 (Detection).
    """

    event_id: str
    timestamp: datetime
    event_type: str

    user: Optional[str] = None
    device: Optional[str] = None

    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None

    file: Optional[str] = None
    application: Optional[str] = None
    process: Optional[str] = None

    usb_id: Optional[str] = None
    domain: Optional[str] = None

    action: Optional[str] = None
    success: Optional[bool] = None

    # Original log source
    raw_source: Optional[str] = None
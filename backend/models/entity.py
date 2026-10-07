from typing import Optional

from pydantic import BaseModel


class Entity(BaseModel):
    """
    Represents an entity involved in a security event.

    Examples:
    user, device, IP address, file, USB device, domain
    """

    entity_id: str
    entity_type: str
    name: Optional[str] = None
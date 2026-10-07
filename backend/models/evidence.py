from typing import Optional

from pydantic import BaseModel


class Evidence(BaseModel):
    """
    Represents evidence supporting a detected attack stage.
    """

    evidence_id: str
    event_id: str
    stage: str
    description: str
    confidence: Optional[float] = None
from typing import List, Optional

from pydantic import BaseModel

from backend.models.event import SecurityEvent


class AttackStage(BaseModel):
    """
    Represents one stage of a detected attack.
    """

    stage: str
    description: Optional[str] = None
    event_ids: List[str] = []
    evidence: List[str] = []


class Attack(BaseModel):
    """
    Represents a complete detected attack chain.
    """

    attack_id: str
    severity: str
    risk_score: float

    user: Optional[str] = None
    device: Optional[str] = None

    timeline: List[SecurityEvent] = []
    stages: List[AttackStage] = []
    evidence: List[str] = []
    entities: List[str] = []
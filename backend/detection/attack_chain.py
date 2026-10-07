
from typing import Dict, Any, List


STAGE_ORDER = [
    "SUSPICIOUS_LOGIN",
    "SENSITIVE_FILE_ACCESS",
    "DATA_EXFILTRATION"
]


def build_attack_chain(
    correlated_events: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Convert correlated detection events into an attack chain.
    """

    stages = []
    evidence = []

    detected_stage_names = []

    for item in correlated_events:

        stage = item.get("stage")
        event = item.get("event", {})
        reason = item.get("reason", "")

        if stage and stage not in detected_stage_names:
            detected_stage_names.append(stage)

            stages.append({
                "stage": stage,
                "timestamp": event.get("timestamp"),
                "event_id": event.get("event_id"),
                "reason": reason
            })

        evidence.append({
            "event_id": event.get("event_id"),
            "event_type": event.get("event_type"),
            "timestamp": event.get("timestamp"),
            "reason": reason
        })

    # Sort stages according to the expected attack progression.
    stages.sort(
        key=lambda item: (
            STAGE_ORDER.index(item["stage"])
            if item["stage"] in STAGE_ORDER
            else len(STAGE_ORDER)
        )
    )

    detected_stage_names = [stage["stage"] for stage in stages]

    # The MVP requires at least two different stages
    # before calling the activity an attack chain.
    is_attack = len(detected_stage_names) >= 2

    return {
        "is_attack": is_attack,
        "stages": stages,
        "evidence": evidence,
        "stage_count": len(stages)
    }

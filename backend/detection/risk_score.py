from typing import Dict, Any


STAGE_SCORES = {
    "SUSPICIOUS_LOGIN": 25,
    "SENSITIVE_FILE_ACCESS": 30,
    "DATA_EXFILTRATION": 45
}


def calculate_risk_score(attack_chain: Dict[str, Any]) -> int:
    """
    Calculate an explainable risk score from detected stages.
    """

    score = 0

    for stage in attack_chain.get("stages", []):
        stage_name = stage.get("stage")
        score += STAGE_SCORES.get(stage_name, 0)

    # Cap the score at 100.
    return min(score, 100)


def get_severity(risk_score: int) -> str:
    """
    Convert the numerical risk score into a severity level.
    """

    if risk_score >= 80:
        return "CRITICAL"

    if risk_score >= 60:
        return "HIGH"

    if risk_score >= 40:
        return "MEDIUM"

    if risk_score >= 20:
        return "LOW"

    return "INFO"


def add_risk_score(
    attack_chain: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Add risk score and severity to the attack-chain result.
    """

    risk_score = calculate_risk_score(attack_chain)

    attack_chain["risk_score"] = risk_score
    attack_chain["severity"] = get_severity(risk_score)

    return attack_chain

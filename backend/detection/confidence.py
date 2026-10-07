id="2qgq3l"
from typing import Dict, Any, List


def calculate_confidence(
    attack_chain: Dict[str,Any]
) -> int:
    """
    Calculate a confidence score based on the strength
    of the detected attack chain.

    This is an explainable MVP score, not a probability.
    """

    stages = attack_chain.get("stages", [])

    stage_count = len(stages)

    confidence = 0

    # Multiple stages provide stronger evidence.
    if stage_count >= 1:
        confidence += 20

    if stage_count >= 2:
        confidence += 25

    if stage_count >= 3:
        confidence += 30

    # A detected attack chain increases confidence.
    if attack_chain.get("is_attack") is True:
        confidence += 15

    # Risk score provides additional supporting evidence.
    risk_score = attack_chain.get("risk_score", 0)

    if risk_score >= 60:
        confidence += 10

    return min(confidence, 100)


def build_explanation(
    attack_chain: Dict[str, Any]
) -> List[str]:
    """
    Generate human-readable explanations for the
    detected attack chain.
    """

    explanations = []

    stages = attack_chain.get("stages", [])

    stage_names = {
        stage.get("stage")
        for stage in stages
    }

    if "SUSPICIOUS_LOGIN" in stage_names:
        explanations.append(
            "Anomalous successful login detected."
        )

    if "SENSITIVE_FILE_ACCESS" in stage_names:
        explanations.append(
            "Sensitive file access detected."
        )

    if "DATA_EXFILTRATION" in stage_names:
        explanations.append(
            "Potential data-transfer activity detected."
        )

    if len(stages) >= 2:
        explanations.append(
            "Multiple suspicious stages were correlated "
            "into a single activity chain."
        )

    if attack_chain.get("is_attack") is True:
        explanations.append(
            "The correlated activity meets the minimum "
            "criteria for an attack chain."
        )

    if not explanations:
        explanations.append(
            "No significant attack evidence detected."
        )

    return explanations


def add_confidence_and_explanation(
    attack_chain: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Add confidence and human-readable explanations.
    """

    attack_chain["confidence"] = calculate_confidence(
        attack_chain
    )

    attack_chain["explanation"] = build_explanation(
        attack_chain
    )

    return attack_chain


from backend.detection.confidence import (
    calculate_confidence,
    build_explanation,
)


def test_attack_confidence():

    attack_chain = {
        "is_attack": True,
        "risk_score": 100,
        "stages": [
            {
                "stage": "SUSPICIOUS_LOGIN"
            },
            {
                "stage": "SENSITIVE_FILE_ACCESS"
            },
            {
                "stage": "DATA_EXFILTRATION"
            },
        ],
    }

    confidence = calculate_confidence(
        attack_chain
    )

    assert confidence == 100


def test_attack_explanation():

    attack_chain = {
        "is_attack": True,
        "risk_score": 100,
        "stages": [
            {
                "stage": "SUSPICIOUS_LOGIN"
            },
            {
                "stage": "SENSITIVE_FILE_ACCESS"
            },
            {
                "stage": "DATA_EXFILTRATION"
            },
        ],
    }

    explanations = build_explanation(
        attack_chain
    )

    assert len(explanations) >= 3

    assert any(
        "login" in explanation.lower()
        for explanation in explanations
    )

    assert any(
        "sensitive" in explanation.lower()
        for explanation in explanations
    )

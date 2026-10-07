from typing import Dict, Any, List

from backend.detection.anomaly_detector import EventAnomalyDetector
from backend.detection.rules import detect_suspicious_events
from backend.detection.correlation_engine import correlate_events
from backend.detection.attack_chain import build_attack_chain
from backend.detection.risk_score import add_risk_score
from backend.detection.confidence import add_confidence_and_explanation
from backend.graph.graph_context import build_graph_context

class DetectionPipeline:

def __init__(self):
    self.anomaly_detector = EventAnomalyDetector()

def analyze(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:

    if not events:
        return {
            "is_attack": False,
            "risk_score": 0,
            "severity": "INFO",
            "confidence": 0,
            "stages": [],
            "evidence": [],
            "entities": [],
            "relationships": []
        }

    self.anomaly_detector.fit(events)

    scored_events = self.anomaly_detector.score_events(
        events
    )

    suspicious_events = detect_suspicious_events(
        scored_events
    )

    if not suspicious_events:
        return {
            "is_attack": False,
            "risk_score": 0,
            "severity": "INFO",
            "confidence": 0,
            "stages": [],
            "evidence": [],
            "entities": [],
            "relationships": []
        }

    detection_events = [
        item["event"]
        for item in suspicious_events
    ]

    groups = correlate_events(detection_events)

    best_chain = {
        "is_attack": False,
        "stages": [],
        "evidence": [],
        "stage_count": 0
    }

    for group in groups:

        group_event_ids = {
            event.get("event_id")
            for event in group
        }

        correlated_detections = [
            item
            for item in suspicious_events
            if item["event"].get("event_id")
            in group_event_ids
        ]

        attack_chain = build_attack_chain(
            correlated_detections
        )

        if (
            attack_chain["stage_count"]
            > best_chain["stage_count"]
        ):
            best_chain = attack_chain

    best_chain = add_risk_score(
        best_chain
    )

    best_chain = add_confidence_and_explanation(
        best_chain
    )

    if events:
        first_event = events[0]

        best_chain["user"] = first_event.get(
            "user"
        )

        best_chain["device"] = first_event.get(
            "device"
        )

    graph_context = build_graph_context(
        events
    )

    best_chain["entities"] = graph_context[
        "entities"
    ]

    best_chain["relationships"] = graph_context[
        "relationships"
    ]

    return best_chain

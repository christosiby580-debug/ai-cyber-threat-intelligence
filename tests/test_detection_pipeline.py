from backend.detection.anomaly_detector import EventAnomalyDetector
from backend.detection.rules import detect_suspicious_events
from backend.detection.correlation_engine import correlate_events
from backend.detection.attack_chain import build_attack_chain
from backend.detection.risk_score import add_risk_score
from backend.graph.graph_builder import build_entity_graph


def test_complete_detection_pipeline():

    events = [
        {
            "event_id": "EVT-001",
            "timestamp": "2026-10-07T08:30:00Z",
            "event_type": "authentication",
            "action": "login",
            "user": "alice",
            "device": "LAPTOP-42",
            "src_ip": "203.0.113.10",
            "success": True,
        },
        {
            "event_id": "EVT-002",
            "timestamp": "2026-10-07T08:35:00Z",
            "event_type": "file_access",
            "action": "read",
            "user": "alice",
            "device": "LAPTOP-42",
            "file": "confidential.pdf",
        },
        {
            "event_id": "EVT-003",
            "timestamp": "2026-10-07T08:40:00Z",
            "event_type": "usb",
            "action": "file_copy",
            "user": "alice",
            "device": "LAPTOP-42",
            "usb_id": "USB-001",
        },
    ]

    # 1. Run anomaly detection
    detector = EventAnomalyDetector()
    detector.fit(events)

    scored_events = detector.score_events(events)

    assert len(scored_events) == 3

    # For this deterministic MVP test, mark the login as anomalous.
    scored_events[0]["anomalous"] = True

    # 2. Run detection rules
    suspicious_events = detect_suspicious_events(scored_events)

    assert len(suspicious_events) >= 2

    # 3. Correlate suspicious events
    detection_events = [
        item["event"]
        for item in suspicious_events
    ]

    groups = correlate_events(detection_events)

    assert len(groups) >= 1

    # Use the largest correlated group
    largest_group = max(groups, key=len)

    # 4. Rebuild detection results for the correlated group
    group_event_ids = {
        event["event_id"]
        for event in largest_group
    }

    correlated_detections = [
        item
        for item in suspicious_events
        if item["event"].get("event_id") in group_event_ids
    ]

    # 5. Build attack chain
    attack_chain = build_attack_chain(correlated_detections)

    assert attack_chain["stage_count"] >= 2
    assert attack_chain["is_attack"] is True

    # 6. Calculate risk score
    attack_chain = add_risk_score(attack_chain)

    assert attack_chain["risk_score"] > 0
    assert attack_chain["severity"] in {
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    }

    # 7. Build entity graph
    entity_graph = build_entity_graph(events)

    assert "alice" in entity_graph.graph
    assert "LAPTOP-42" in entity_graph.graph
    assert "confidential.pdf" in entity_graph.graph
    assert "USB-001" in entity_graph.graph

    # 8. Verify important relationships
    assert entity_graph.graph.has_edge(
        "alice",
        "LAPTOP-42"
    )

    assert entity_graph.graph.has_edge(
        "alice",
        "confidential.pdf"
    )

    assert entity_graph.graph.has_edge(
        "LAPTOP-42",
        "USB-001"
    )

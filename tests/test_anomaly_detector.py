from backend.detection.anomaly_detector import EventAnomalyDetector


def test_anomaly_detector():
    events = [
        {
            "event_id": "EVT-001",
            "event_type": "authentication",
            "action": "login",
            "user": "alice",
            "device": "LAPTOP-42",
            "src_ip": "203.0.113.10",
            "success": True,
        },
        {
            "event_id": "EVT-002",
            "event_type": "file_access",
            "action": "read",
            "user": "alice",
            "device": "LAPTOP-42",
            "file": "confidential.pdf",
        },
        {
            "event_id": "EVT-003",
            "event_type": "usb",
            "action": "connect",
            "user": "alice",
            "device": "LAPTOP-42",
            "usb_id": "USB-001",
        },
    ]

    detector = EventAnomalyDetector()

    detector.fit(events)

    results = detector.score_events(events)

    assert len(results) == 3

    for event in results:
        assert "anomalous" in event
        assert "anomaly_score" in event

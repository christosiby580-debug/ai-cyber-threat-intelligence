from backend.detection.detection_pipeline import DetectionPipeline


def test_detection_pipeline_orchestrator():

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

    pipeline = DetectionPipeline()

    result = pipeline.analyze(events)

    assert "is_attack" in result
    assert "risk_score" in result
    assert "severity" in result
    assert "stages" in result
    assert "evidence" in result

    assert result["risk_score"] >= 0
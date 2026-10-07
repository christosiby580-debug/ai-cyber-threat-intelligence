from backend.detection.detection_pipeline import DetectionPipeline


def test_multi_stage_attack_is_detected():

    events = [
        {
            "event_id": "ATTACK-001",
            "timestamp": "2026-10-07T10:00:00Z",
            "event_type": "authentication",
            "action": "login",
            "user": "alice",
            "device": "LAPTOP-42",
            "src_ip": "203.0.113.10",
            "success": True,
        },
        {
            "event_id": "ATTACK-002",
            "timestamp": "2026-10-07T10:05:00Z",
            "event_type": "file_access",
            "action": "read",
            "user": "alice",
            "device": "LAPTOP-42",
            "file": "confidential.pdf",
        },
        {
            "event_id": "ATTACK-003",
            "timestamp": "2026-10-07T10:10:00Z",
            "event_type": "usb",
            "action": "file_copy",
            "user": "alice",
            "device": "LAPTOP-42",
            "usb_id": "USB-001",
        },
    ]

    pipeline = DetectionPipeline()

    result = pipeline.analyze(events)

    assert result["is_attack"] is True
    assert result["risk_score"] >= 40
    assert len(result["stages"]) >= 2

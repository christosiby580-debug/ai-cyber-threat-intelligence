from backend.detection.detection_pipeline import DetectionPipeline


def test_clean_activity_is_not_attack():

    events = [
        {
            "event_id": "CLEAN-001",
            "timestamp": "2026-10-07T09:00:00Z",
            "event_type": "authentication",
            "action": "login",
            "user": "bob",
            "device": "LAPTOP-10",
            "src_ip": "192.0.2.10",
            "success": True,
        },
        {
            "event_id": "CLEAN-002",
            "timestamp": "2026-10-07T09:10:00Z",
            "event_type": "file_access",
            "action": "read",
            "user": "bob",
            "device": "LAPTOP-10",
            "file": "project_notes.txt",
        },
    ]

    pipeline = DetectionPipeline()

    result = pipeline.analyze(events)

    assert result["is_attack"] is False
    assert result["risk_score"] < 40

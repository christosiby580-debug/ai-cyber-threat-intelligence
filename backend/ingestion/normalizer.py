from datetime import datetime
from typing import Any, Dict

from backend.models.event import SecurityEvent


def parse_timestamp(value: Any) -> datetime:
    """
    Convert a timestamp string into a Python datetime.
    """

    if isinstance(value, datetime):
        return value

    timestamp = str(value).replace("Z", "+00:00")

    return datetime.fromisoformat(timestamp)


def normalize_authentication(row: Dict[str, Any]) -> SecurityEvent:
    """
    Convert an authentication log into a SecurityEvent.
    """

    return SecurityEvent(
        event_id=str(row.get("event_id")),
        timestamp=parse_timestamp(row["timestamp"]),
        event_type="authentication",
        user=row.get("user"),
        device=row.get("device"),
        src_ip=row.get("src_ip"),
        action=row.get("action") or row.get("event"),
        success=(
    str(row.get("success") or row.get("result", "")).lower()
    in ["true", "success", "1", "yes"]
),
        raw_source="authentication_logs",
    )


def normalize_file_access(row: Dict[str, Any]) -> SecurityEvent:
    """
    Convert a file access log into a SecurityEvent.
    """

    return SecurityEvent(
        event_id=str(row.get("event_id")),
        timestamp=parse_timestamp(row["timestamp"]),
        event_type="file_access",
        user=row.get("user"),
        device=row.get("device"),
        file=row.get("file") or row.get("file_path"),
        action=row.get("action"),
        success=(
            str(row.get("success") or row.get("result", "")).lower()
            == "success"
            if row.get("success") is not None or row.get("result") is not None
            else None
        ),
        raw_source="file_access_logs",
    )


def normalize_usb(row: Dict[str, Any]) -> SecurityEvent:
    """
    Convert a USB log into a SecurityEvent.
    """

    return SecurityEvent(
        event_id=str(row.get("event_id")),
        timestamp=parse_timestamp(row["timestamp"]),
        event_type="usb",
        user=row.get("user"),
        device=row.get("device"),
        usb_id=row.get("usb_id"),
        action=row.get("action") or row.get("event"),
        raw_source="usb_device_logs",
    )
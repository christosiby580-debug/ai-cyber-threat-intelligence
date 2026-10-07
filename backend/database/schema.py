from backend.models.event import SecurityEvent


EVENT_FIELDS = [
    "event_id",
    "timestamp",
    "event_type",
    "user",
    "device",
    "src_ip",
    "dst_ip",
    "file",
    "application",
    "process",
    "usb_id",
    "domain",
    "action",
    "success",
    "raw_source",
]


def event_to_record(event: SecurityEvent) -> dict:
    """
    Convert a SecurityEvent into a database-friendly dictionary.
    """

    return event.model_dump()


def record_to_event(record: dict) -> SecurityEvent:
    """
    Convert a database record back into a SecurityEvent.
    """

    return SecurityEvent(**record)
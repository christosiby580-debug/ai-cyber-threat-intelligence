from datetime import datetime
from typing import Dict, Any, List


def is_suspicious_login(event: Dict[str, Any]) -> bool:
    """
    Detect a suspicious authentication event.

    This is intentionally simple for the MVP.
    Member 1 can later provide additional context such as
    known locations or historical login behavior.
    """

    return (
        event.get("event_type") == "authentication"
        and event.get("action") == "login"
        and event.get("success") is True
        and event.get("anomalous") is True
    )


def is_sensitive_file_access(event: Dict[str, Any]) -> bool:
    """
    Detect access to a sensitive file.
    """

    sensitive_files = {
        "confidential.pdf",
        "financial_report.xlsx",
        "employee_data.csv",
        "customer_data.csv",
    }

    return (
        event.get("event_type") == "file_access"
        and event.get("action") in {"read", "copy", "download"}
        and event.get("file") in sensitive_files
    )


def is_usb_activity(event: Dict[str, Any]) -> bool:
    """
    Detect USB connection or file-copy activity.
    """

    return (
        event.get("event_type") == "usb"
        and event.get("action") in {"connect", "file_copy"}
    )


def detect_suspicious_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Run all detection rules against normalized events.
    """

    suspicious = []

    for event in events:

        if is_suspicious_login(event):
            suspicious.append({
                "event": event,
                "stage": "SUSPICIOUS_LOGIN",
                "reason": "Anomalous successful login"
            })

        elif is_sensitive_file_access(event):
            suspicious.append({
                "event": event,
                "stage": "SENSITIVE_FILE_ACCESS",
                "reason": "Sensitive file accessed"
            })

        elif is_usb_activity(event):
            suspicious.append({
                "event": event,
                "stage": "DATA_EXFILTRATION",
                "reason": "USB activity detected"
            })

    return suspicious

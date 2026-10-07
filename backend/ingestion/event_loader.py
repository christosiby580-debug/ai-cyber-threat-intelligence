from typing import List

from backend.ingestion.csv_loader import load_csv
from backend.ingestion.log_parser import parse_log_row
from backend.ingestion.normalizer import (
    normalize_authentication,
    normalize_file_access,
    normalize_usb,
)
from backend.models.event import SecurityEvent


def load_all_events() -> List[SecurityEvent]:
    """
    Load all raw security logs and convert them
    into a common SecurityEvent format.
    """

    events = []

    # Authentication logs
    auth_df = load_csv("data/raw/authentication_logs.csv")

    for _, row in auth_df.iterrows():
        parsed_row = parse_log_row(row)
        events.append(normalize_authentication(parsed_row))

    # File access logs
    file_df = load_csv("data/raw/file_access_logs.csv")

    for _, row in file_df.iterrows():
        parsed_row = parse_log_row(row)
        events.append(normalize_file_access(parsed_row))

    # USB logs
    usb_df = load_csv("data/raw/usb_device_logs.csv")

    for _, row in usb_df.iterrows():
        parsed_row = parse_log_row(row)
        events.append(normalize_usb(parsed_row))

    # Sort events chronologically
    events.sort(key=lambda event: event.timestamp)

    return events
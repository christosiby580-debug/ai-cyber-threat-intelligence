from backend.ingestion.csv_loader import load_csv
from backend.ingestion.log_parser import parse_log_row
from backend.ingestion.normalizer import (
    normalize_authentication,
    normalize_file_access,
    normalize_usb,
)


def test_authentication():
    print("\n=== AUTHENTICATION EVENTS ===")

    df = load_csv("data/raw/authentication_logs.csv")

    for _, row in df.iterrows():
        parsed_row = parse_log_row(row)
        event = normalize_authentication(parsed_row)
        print(event.model_dump())


def test_file_access():
    print("\n=== FILE ACCESS EVENTS ===")

    df = load_csv("data/raw/file_access_logs.csv")

    for _, row in df.iterrows():
        parsed_row = parse_log_row(row)
        event = normalize_file_access(parsed_row)
        print(event.model_dump())


def test_usb():
    print("\n=== USB EVENTS ===")

    df = load_csv("data/raw/usb_device_logs.csv")

    for _, row in df.iterrows():
        parsed_row = parse_log_row(row)
        event = normalize_usb(parsed_row)
        print(event.model_dump())


if __name__ == "__main__":
    test_authentication()
    test_file_access()
    test_usb()
from backend.ingestion.event_loader import load_all_events


if __name__ == "__main__":
    events = load_all_events()

    print(f"Total events loaded: {len(events)}")
    print()

    for event in events:
        print(
            event.timestamp,
            "|",
            event.event_type,
            "|",
            event.user,
            "|",
            event.device,
            "|",
            event.action,
        )
from backend.database.repository import EventRepository
from backend.ingestion.event_loader import load_all_events


if __name__ == "__main__":
    # Load normalized events
    events = load_all_events()

    # Create repository
    repository = EventRepository()

    # Store events
    repository.add_events(events)

    print("Total events:", repository.count())

    print("\nAlice's events:")

    for event in repository.get_events_by_user("alice"):
        print(
            event.event_id,
            "|",
            event.event_type,
            "|",
            event.action,
        )

    print("\nEvent EVT-004:")

    event = repository.get_event_by_id("EVT-004")

    if event:
        print(event.model_dump())
from backend.database.schema import event_to_record, record_to_event
from backend.ingestion.event_loader import load_all_events


if __name__ == "__main__":
    events = load_all_events()

    # Convert event to database record
    record = event_to_record(events[0])

    print("Database record:")
    print(record)

    # Convert database record back to event
    restored_event = record_to_event(record)

    print("\nRestored event:")
    print(restored_event.model_dump())

    print("\nEvent ID:", restored_event.event_id)
    print("Event type:", restored_event.event_type)
from typing import List, Optional

from backend.models.event import SecurityEvent


class EventRepository:
    """
    Simple in-memory repository for normalized security events.

    Later this can be replaced with PostgreSQL, SQLite,
    or another persistent database without changing
    the detection layer.
    """

    def __init__(self):
        self.events: List[SecurityEvent] = []

    def add_event(self, event: SecurityEvent) -> None:
        """Store one security event."""
        self.events.append(event)

    def add_events(self, events: List[SecurityEvent]) -> None:
        """Store multiple security events."""
        self.events.extend(events)

    def get_all_events(self) -> List[SecurityEvent]:
        """Return all stored events."""
        return self.events

    def get_event_by_id(self, event_id: str) -> Optional[SecurityEvent]:
        """Find an event by its event ID."""

        for event in self.events:
            if event.event_id == event_id:
                return event

        return None

    def get_events_by_user(self, user: str) -> List[SecurityEvent]:
        """Return all events associated with a user."""

        return [
            event
            for event in self.events
            if event.user == user
        ]

    def get_events_by_device(self, device: str) -> List[SecurityEvent]:
        """Return all events associated with a device."""

        return [
            event
            for event in self.events
            if event.device == device
        ]

    def count(self) -> int:
        """Return the number of stored events."""
        return len(self.events)
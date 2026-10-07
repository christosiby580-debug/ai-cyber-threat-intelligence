from datetime import datetime, timedelta
from typing import Dict, Any, List


DEFAULT_WINDOW_MINUTES = 30


def parse_timestamp(timestamp: str) -> datetime:
    """
    Convert an ISO timestamp into a datetime object.
    Supports timestamps ending with Z.
    """
    return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))


def same_entity(event1: Dict[str, Any], event2: Dict[str, Any]) -> bool:
    """
    Check whether two events are associated with the same
    user and/or device.
    """

    same_user = (
        event1.get("user")
        and event2.get("user")
        and event1.get("user") == event2.get("user")
    )

    same_device = (
        event1.get("device")
        and event2.get("device")
        and event1.get("device") == event2.get("device")
    )

    return same_user or same_device


def within_time_window(
    event1: Dict[str, Any],
    event2: Dict[str, Any],
    window_minutes: int = DEFAULT_WINDOW_MINUTES
) -> bool:
    """
    Check whether two events occurred within the correlation window.
    """

    time1 = parse_timestamp(event1["timestamp"])
    time2 = parse_timestamp(event2["timestamp"])

    difference = abs(time2 - time1)

    return difference <= timedelta(minutes=window_minutes)


def correlate_events(
    events: List[Dict[str, Any]],
    window_minutes: int = DEFAULT_WINDOW_MINUTES
) -> List[List[Dict[str, Any]]]:
    """
    Group events that are likely related to the same activity.

    Events are correlated when:
    - They involve the same user or device.
    - They occur within the configured time window.
    """

    if not events:
        return []

    sorted_events = sorted(
        events,
        key=lambda event: parse_timestamp(event["timestamp"])
    )

    groups = []

    for event in sorted_events:

        added_to_group = False

        for group in groups:

            reference_event = group[-1]

            if (
                same_entity(event, reference_event)
                and within_time_window(
                    event,
                    reference_event,
                    window_minutes
                )
            ):
                group.append(event)
                added_to_group = True
                break

        if not added_to_group:
            groups.append([event])

    return groups
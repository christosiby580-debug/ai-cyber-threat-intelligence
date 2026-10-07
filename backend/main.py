from fastapi import FastAPI

from backend.ingestion.event_loader import load_all_events


app = FastAPI(
    title="AI-Powered Cyber Threat Intelligence API",
    description="Backend API for security event analysis and attack-chain detection.",
    version="1.0.0",
)


@app.get("/")
def root():
    return {
        "message": "Cyber Threat Intelligence API is running",
        "status": "online",
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }


@app.get("/events")
def get_events():
    events = load_all_events()

    return [
        event.model_dump(mode="json")
        for event in events
    ]
@app.get("/events/{event_id}")
def get_event(event_id: str):
    events = load_all_events()

    for event in events:
        if event.event_id == event_id:
            return event.model_dump(mode="json")

    return {
        "error": "Event not found",
        "event_id": event_id,
    }
@app.get("/events/user/{user}")
def get_events_by_user(user: str):
    events = load_all_events()

    user_events = [
        event
        for event in events
        if event.user == user
    ]

    return [
        event.model_dump(mode="json")
        for event in user_events
    ]
@app.get("/events/device/{device}")
def get_events_by_device(device: str):
    events = load_all_events()

    device_events = [
        event
        for event in events
        if event.device == device
    ]

    return [
        event.model_dump(mode="json")
        for event in device_events
    ]
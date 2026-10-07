
from typing import Dict, Any, List

import numpy as np
from sklearn.ensemble import IsolationForest


class EventAnomalyDetector:
    """
    Lightweight anomaly detector for normalized security events.

    The model provides an anomaly signal that can be combined
    with deterministic detection rules.
    """

    def __init__(
        self,
        contamination: float = 0.1,
        random_state: int = 42
    ):
        self.model = IsolationForest(
            contamination=contamination,
            random_state=random_state
        )

    def _event_to_features(self, event: Dict[str, Any]) -> List[float]:
        """
        Convert an event into simple numerical features.

        These features are intentionally generic so they work
        with the normalized event format.
        """

        event_type = event.get("event_type", "")
        action = event.get("action", "")

        event_type_score = {
            "authentication": 1,
            "file_access": 2,
            "usb": 3,
            "network": 4,
            "endpoint": 5,
        }.get(event_type, 0)

        action_score = {
            "login": 1,
            "read": 2,
            "copy": 3,
            "download": 4,
            "connect": 5,
            "file_copy": 6,
        }.get(action, 0)

        success = 1 if event.get("success") is True else 0

        has_user = 1 if event.get("user") else 0
        has_device = 1 if event.get("device") else 0
        has_ip = 1 if event.get("src_ip") else 0
        has_file = 1 if event.get("file") else 0
        has_usb = 1 if event.get("usb_id") else 0

        return [
            event_type_score,
            action_score,
            success,
            has_user,
            has_device,
            has_ip,
            has_file,
            has_usb,
        ]

    def fit(self, events: List[Dict[str, Any]]) -> None:
        """
        Train the anomaly detector on a collection of events.
        """

        if len(events) < 2:
            raise ValueError(
                "At least two events are required to train the detector."
            )

        features = np.array([
            self._event_to_features(event)
            for event in events
        ])

        self.model.fit(features)

    def score_events(
        self,
        events: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Add anomaly predictions and scores to events.
        """

        if not events:
            return []

        features = np.array([
            self._event_to_features(event)
            for event in events
        ])

        predictions = self.model.predict(features)
        scores = self.model.decision_function(features)

        results = []

        for event, prediction, score in zip(
            events,
            predictions,
            scores
        ):
            event_copy = event.copy()

            event_copy["anomalous"] = prediction == -1
            event_copy["anomaly_score"] = round(
                float(score),
                4
            )

            results.append(event_copy)

        return results

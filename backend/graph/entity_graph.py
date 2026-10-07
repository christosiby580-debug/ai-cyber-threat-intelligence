import networkx as nx
from typing import Dict, Any, List


class EntityGraph:
    """
    Graph representation of users, devices, IPs, files,
    applications, and other security entities.
    """

    def __init__(self):
        self.graph = nx.Graph()

    def add_entity(
        self,
        entity_id: str,
        entity_type: str,
        **attributes
    ):
        """
        Add an entity node to the graph.
        """

        self.graph.add_node(
            entity_id,
            entity_type=entity_type,
            **attributes
        )

    def add_relationship(
        self,
        source: str,
        target: str,
        relationship: str,
        **attributes
    ):
        """
        Connect two entities.
        """

        self.graph.add_edge(
            source,
            target,
            relationship=relationship,
            **attributes
        )

    def add_event(self, event: Dict[str, Any]):
        """
        Convert a normalized event into graph entities
        and relationships.
        """

        user = event.get("user")
        device = event.get("device")
        src_ip = event.get("src_ip")
        file_name = event.get("file")
        usb_id = event.get("usb_id")

        # User
        if user:
            self.add_entity(
                user,
                "user"
            )

        # Device
        if device:
            self.add_entity(
                device,
                "device"
            )

        # User -> Device
        if user and device:
            self.add_relationship(
                user,
                device,
                "uses"
            )

        # IP
        if src_ip:
            self.add_entity(
                src_ip,
                "ip"
            )

            if device:
                self.add_relationship(
                    device,
                    src_ip,
                    "connected_from"
                )

        # File
        if file_name:
            self.add_entity(
                file_name,
                "file"
            )

            if device:
                self.add_relationship(
                    device,
                    file_name,
                    "accessed"
                )

            if user:
                self.add_relationship(
                    user,
                    file_name,
                    "accessed"
                )

        # USB
        if usb_id:
            self.add_entity(
                usb_id,
                "usb"
            )

            if device:
                self.add_relationship(
                    device,
                    usb_id,
                    "connected"
                )

            if user:
                self.add_relationship(
                    user,
                    usb_id,
                    "used"
                )

    def add_events(self, events: List[Dict[str, Any]]):
        """
        Add multiple events to the graph.
        """

        for event in events:
            self.add_event(event)

    def get_neighbors(self, entity_id: str):
        """
        Return entities directly connected to an entity.
        """

        if entity_id not in self.graph:
            return []

        return list(self.graph.neighbors(entity_id))

    def get_entity_data(self, entity_id: str):
        """
        Return entity attributes.
        """

        if entity_id not in self.graph:
            return None

        return self.graph.nodes[entity_id]

    def get_graph(self):
        """
        Return the underlying NetworkX graph.
        """

        return self.graph
from typing import Dict, Any, List

from .entity_graph import EntityGraph


def build_entity_graph(
    events: List[Dict[str, Any]]
) -> EntityGraph:
    """
    Build an entity graph from normalized security events.
    """

    entity_graph = EntityGraph()

    entity_graph.add_events(events)

    return entity_graph


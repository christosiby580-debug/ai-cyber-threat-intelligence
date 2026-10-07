from typing import Dict, Any, List

from .entity_graph import EntityGraph


def find_related_entities(
    entity_graph: EntityGraph,
    entity_id: str
) -> List[str]:
    """
    Find entities directly connected to an entity.
    """

    return entity_graph.get_neighbors(entity_id)


def find_user_context(
    entity_graph: EntityGraph,
    user: str
) -> Dict[str, Any]:
    """
    Return the entities associated with a user.
    """

    if user not in entity_graph.graph:
        return {
            "user": user,
            "entities": []
        }

    neighbors = entity_graph.get_neighbors(user)

    return {
        "user": user,
        "entities": neighbors
    }

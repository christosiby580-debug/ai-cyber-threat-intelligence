from typing import Dict, Any, List

def build_graph_context(events: List[Dict[str, Any]]) -> Dict[str, Any]:
entities = []
relationships = []


def add_entity(entity_id, entity_type):
    if not entity_id:
        return

    entity = {
        "id": entity_id,
        "type": entity_type
    }

    if entity not in entities:
        entities.append(entity)

def add_relationship(source, target, relationship):
    if not source or not target:
        return

    item = {
        "source": source,
        "target": target,
        "relationship": relationship
    }

    if item not in relationships:
        relationships.append(item)

for event in events:
    user = event.get("user")
    device = event.get("device")
    src_ip = event.get("src_ip")
    file_name = event.get("file")
    usb_id = event.get("usb_id")

    if user:
        add_entity(user, "user")

    if device:
        add_entity(device, "device")

    if src_ip:
        add_entity(src_ip, "ip")

    if file_name:
        add_entity(file_name, "file")

    if usb_id:
        add_entity(usb_id, "usb")

    if user and device:
        add_relationship(
            user,
            device,
            "uses"
        )

    if device and src_ip:
        add_relationship(
            device,
            src_ip,
            "connected_from"
        )

    if device and file_name:
        add_relationship(
            device,
            file_name,
            "accessed"
        )

    if user and file_name:
        add_relationship(
            user,
            file_name,
            "accessed"
        )

    if device and usb_id:
        add_relationship(
            device,
            usb_id,
            "connected"
        )

    if user and usb_id:
        add_relationship(
            user,
            usb_id,
            "used"
        )

return {
    "entities": entities,
    "relationships": relationships
}

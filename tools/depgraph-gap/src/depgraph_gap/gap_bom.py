from typing import Any

from depgraph_gap.domain import Component, Repository


def build_gap_bom(
    repository: Repository,
    sha: str,
    components: tuple[Component, ...],
    timestamp: str,
    serial_number: str,
) -> dict[str, Any]:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{serial_number}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": {"components": [{"type": "application", "name": "depgraph-gap"}]},
            "component": {"type": "application", "name": str(repository), "version": sha},
        },
        "components": [_component(component) for component in components],
    }


def _component(component: Component) -> dict[str, Any]:
    purl = str(component.purl)
    entry: dict[str, Any] = {"type": "library", "bom-ref": purl, "name": component.name}
    if component.version:
        entry["version"] = component.version
    entry["purl"] = purl
    entry["properties"] = [
        {"name": "depgraph-gap:occurrences", "value": str(component.occurrences)}
    ]
    return entry

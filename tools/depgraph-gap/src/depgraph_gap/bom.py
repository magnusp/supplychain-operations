from collections.abc import Iterator, Mapping
from typing import Any

from depgraph_gap.domain import Bom, BomComponent, PackageId, Repository
from depgraph_gap.errors import MalformedBom
from depgraph_gap.purl import parse_purl


def parse_cyclonedx(document: Mapping[str, Any], repository: Repository) -> Bom:
    if document.get("bomFormat") != "CycloneDX":
        raise MalformedBom("document is not a CycloneDX BOM")
    components = tuple(_flatten(document.get("components") or []))
    metadata_root = (document.get("metadata") or {}).get("component")
    if metadata_root is not None:
        return Bom(root=_parse_component(metadata_root), components=components)
    return _split_repository_root(components, repository)


def _flatten(raw_components: list[Any]) -> Iterator[BomComponent]:
    for raw in raw_components:
        yield _parse_component(raw)
        yield from _flatten(raw.get("components") or [])


def _parse_component(raw: Any) -> BomComponent:
    if not isinstance(raw, dict) or not isinstance(raw.get("name"), str):
        raise MalformedBom(f"component without a name: {raw!r}")
    return BomComponent(
        name=raw["name"],
        version=raw.get("version") or None,
        purl=raw.get("purl") or None,
        kind=raw.get("type", "library"),
    )


def _split_repository_root(components: tuple[BomComponent, ...], repository: Repository) -> Bom:
    root_package = PackageId("github", repository.owner.lower(), repository.name.lower())
    for index, component in enumerate(components):
        purl = parse_purl(component.purl) if component.purl else None
        if purl is not None and purl.package == root_package:
            return Bom(root=component, components=components[:index] + components[index + 1 :])
    return Bom(root=None, components=components)

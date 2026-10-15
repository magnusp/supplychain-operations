from depgraph_gap.domain import Bom, BomComponent, Repository

WIDGET = Repository("acme", "widget")


def component(
    purl: str | None, name: str = "component", version: str | None = None, kind: str = "library"
) -> BomComponent:
    return BomComponent(name=name, version=version, purl=purl, kind=kind)


def bom(*components: BomComponent, root: BomComponent | None = None) -> Bom:
    return Bom(root=root, components=components)

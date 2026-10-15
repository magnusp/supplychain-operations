from depgraph_gap.comparison import compare
from depgraph_gap.domain import Repository
from depgraph_gap.gap_bom import build_gap_bom
from tests.builders import WIDGET, bom, component


def test_lists_exactly_the_trivy_only_components_with_their_occurrences() -> None:
    github = bom(component("pkg:npm/shared@1", name="shared", version="1"))
    trivy = bom(
        component("pkg:npm/shared@1", name="shared", version="1"),
        component("pkg:pypi/Requests@2.0.0", name="Requests", version="2.0.0"),
        component("pkg:pypi/Requests@2.0.0", name="Requests", version="2.0.0"),
        component("pkg:golang/stdlib", name="stdlib"),
        component(None, name="go.mod", kind="application"),
    )

    document = build_gap_bom(
        Repository("acme", "widget"),
        sha="abc123",
        components=compare(github, trivy, WIDGET).trivy_only,
        timestamp="2026-10-15T12:00:00Z",
        serial_number="11111111-2222-3333-4444-555555555555",
    )

    assert document == {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:11111111-2222-3333-4444-555555555555",
        "version": 1,
        "metadata": {
            "timestamp": "2026-10-15T12:00:00Z",
            "tools": {"components": [{"type": "application", "name": "depgraph-gap"}]},
            "component": {"type": "application", "name": "acme/widget", "version": "abc123"},
        },
        "components": [
            {
                "type": "library",
                "bom-ref": "pkg:golang/stdlib",
                "name": "stdlib",
                "purl": "pkg:golang/stdlib",
                "properties": [{"name": "depgraph-gap:occurrences", "value": "1"}],
            },
            {
                "type": "library",
                "bom-ref": "pkg:pypi/requests@2.0.0",
                "name": "Requests",
                "version": "2.0.0",
                "purl": "pkg:pypi/requests@2.0.0",
                "properties": [{"name": "depgraph-gap:occurrences", "value": "2"}],
            },
        ],
    }

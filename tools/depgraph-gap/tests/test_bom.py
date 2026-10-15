import pytest

from depgraph_gap.bom import parse_cyclonedx
from depgraph_gap.domain import BomComponent, Repository
from depgraph_gap.errors import MalformedBom

REPOSITORY = Repository(owner="acme", name="widget")


def test_takes_the_root_from_metadata_and_flattens_nested_components() -> None:
    document = {
        "bomFormat": "CycloneDX",
        "metadata": {"component": {"type": "application", "name": "https://github.com/acme/widget"}},
        "components": [
            {"type": "application", "name": "go.mod"},
            {
                "type": "library",
                "name": "outer",
                "version": "1",
                "purl": "pkg:npm/outer@1",
                "components": [{"type": "library", "name": "inner", "purl": "pkg:npm/inner@2"}],
            },
        ],
    }

    bom = parse_cyclonedx(document, REPOSITORY)

    assert bom.root == BomComponent(
        name="https://github.com/acme/widget", version=None, purl=None, kind="application"
    )
    assert [(c.name, c.purl) for c in bom.components] == [
        ("go.mod", None),
        ("outer", "pkg:npm/outer@1"),
        ("inner", "pkg:npm/inner@2"),
    ]
    assert bom.component_count == 4


def test_finds_the_root_of_a_github_sbom_by_the_repository_purl() -> None:
    document = {
        "bomFormat": "CycloneDX",
        "metadata": {},
        "components": [
            {"type": "library", "name": "left-pad", "purl": "pkg:npm/left-pad@1.0.0"},
            {"type": "library", "name": "com.github.acme/widget", "purl": "pkg:github/Acme/Widget@main"},
        ],
    }

    bom = parse_cyclonedx(document, REPOSITORY)

    assert bom.root == BomComponent(
        name="com.github.acme/widget", version=None, purl="pkg:github/Acme/Widget@main", kind="library"
    )
    assert [c.name for c in bom.components] == ["left-pad"]
    assert bom.component_count == 2


def test_a_bom_without_a_recognizable_root_has_no_root() -> None:
    document = {
        "bomFormat": "CycloneDX",
        "components": [{"type": "library", "name": "left-pad", "purl": "pkg:npm/left-pad@1.0.0"}],
    }

    bom = parse_cyclonedx(document, REPOSITORY)

    assert bom.root is None
    assert bom.component_count == 1


@pytest.mark.parametrize(
    "document",
    [
        {"bomFormat": "SPDX"},
        {"bomFormat": "CycloneDX", "components": [{"type": "library"}]},
        {"bomFormat": "CycloneDX", "components": ["left-pad"]},
    ],
)
def test_rejects_a_document_that_is_not_a_usable_cyclonedx_bom(document: dict) -> None:
    with pytest.raises(MalformedBom):
        parse_cyclonedx(document, REPOSITORY)

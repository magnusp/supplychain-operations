import pytest

from depgraph_gap.purl import is_ignored_for_uncovered_decision, parse_purl


@pytest.mark.parametrize(
    ("raw", "normalized"),
    [
        ("pkg:NPM/%40Angular/Core@1.0.0", "pkg:npm/%40angular/core@1.0.0"),
        ("pkg:npm/@angular/core@1.0.0", "pkg:npm/%40angular/core@1.0.0"),
        ("pkg:pypi/Foo_Bar.baz@1.0", "pkg:pypi/foo-bar-baz@1.0"),
        ("pkg:maven/org.Acme/Lib@1.0?type=jar#sub/path", "pkg:maven/org.Acme/Lib@1.0"),
        (
            "pkg:golang/github.com/Foo/Bar@v1.0.0+incompatible",
            "pkg:golang/github.com/foo/bar@v1.0.0+incompatible",
        ),
        ("pkg:githubactions/Actions/Checkout@abc123", "pkg:githubactions/actions/checkout@abc123"),
        ("pkg:golang/stdlib", "pkg:golang/stdlib"),
    ],
)
def test_normalizes_to_canonical_form(raw: str, normalized: str) -> None:
    assert str(parse_purl(raw)) == normalized


@pytest.mark.parametrize("raw", ["", "not-a-purl", "pkg:", "pkg:npm", "pkg:npm/", "npm/foo@1"])
def test_rejects_text_that_is_not_a_purl(raw: str) -> None:
    assert parse_purl(raw) is None


def test_exposes_type_and_version_of_the_parsed_purl() -> None:
    purl = parse_purl("pkg:Cargo/serde@1.0.200")

    assert (purl.type, purl.version) == ("cargo", "1.0.200")


@pytest.mark.parametrize(
    ("raw", "ignored"),
    [
        ("pkg:golang/stdlib", True),
        ("pkg:golang/stdlib@v1.24.0", True),
        ("pkg:golang/stdlib@go1.25.3", True),
        ("pkg:npm/stdlib@1.0.0", False),
        ("pkg:pypi/stdlib@1.0.0", False),
        ("pkg:golang/example.com/stdlib@v1.0.0", False),
        ("pkg:golang/stdlib-extra@v1.0.0", False),
        ("pkg:golang/github.com/acme/widget@v1.0.0", False),
    ],
)
def test_only_the_go_standard_library_is_ignored_for_the_uncovered_decision(
    raw: str, ignored: bool
) -> None:
    assert is_ignored_for_uncovered_decision(parse_purl(raw)) is ignored

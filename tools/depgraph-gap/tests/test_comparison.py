import dataclasses

import pytest

from depgraph_gap.comparison import (
    compare,
    disagrees,
    find_version_mismatches,
    summarize_ecosystems,
)
from depgraph_gap.domain import PackageId, PerSide, Side, SideAccounting
from depgraph_gap.errors import LosslessInvariantViolation
from tests.builders import bom, component

GITHUB_ROOT = component("pkg:github/acme/widget@main", name="com.github.acme/widget")
TRIVY_ROOT = component(None, name="https://github.com/acme/widget", kind="application")


def test_drops_only_the_root_of_each_side() -> None:
    github = bom(component("pkg:npm/left-pad@1.0.0"), root=GITHUB_ROOT)
    trivy = bom(component("pkg:npm/left-pad@1.0.0"), root=TRIVY_ROOT)

    result = compare(github, trivy)

    assert result.dropped_root == PerSide(github=(GITHUB_ROOT,), trivy=(TRIVY_ROOT,))
    assert [str(entry.purl) for entry in result.shared] == ["pkg:npm/left-pad@1.0.0"]
    assert result.github_only == ()
    assert result.trivy_only == ()


def test_does_not_drop_a_repository_purl_that_is_not_the_root() -> None:
    other = component("pkg:github/acme/other@main")
    github = bom(other, root=GITHUB_ROOT)

    result = compare(github, bom())

    assert [str(entry.purl) for entry in result.github_only] == ["pkg:github/acme/other@main"]


def test_lists_components_without_a_usable_purl_per_side_and_never_compares_them() -> None:
    github = bom(
        component(None, name="go.mod", kind="application"),
        component("garbage", name="broken", version="1"),
    )
    trivy = bom(component(None, name="go.mod", kind="application"))

    result = compare(github, trivy)

    assert [(entry.name, entry.raw_purl) for entry in result.unkeyed.github] == [
        ("go.mod", None),
        ("broken", "garbage"),
    ]
    assert [entry.name for entry in result.unkeyed.trivy] == ["go.mod"]
    assert result.shared == ()
    assert result.github_only == ()
    assert result.trivy_only == ()


def test_counts_repeated_purls_as_one_entry_with_occurrences() -> None:
    github = bom(*[component("pkg:npm/foo@1")] * 3)
    trivy = bom(*[component("pkg:npm/foo@1")] * 2)

    result = compare(github, trivy)

    assert [(str(entry.purl), entry.occurrences) for entry in result.shared] == [
        ("pkg:npm/foo@1", PerSide(github=3, trivy=2))
    ]
    assert result.accounting(Side.GITHUB).shared == 3
    assert result.accounting(Side.TRIVY).shared == 2


def test_matches_purls_that_differ_only_in_spelling() -> None:
    github = bom(component("pkg:golang/github.com/ThreeDotsLabs/watermill@v1.5.3"))
    trivy = bom(component("pkg:golang/github.com/threedotslabs/watermill@v1.5.3"))

    result = compare(github, trivy)

    assert [str(entry.purl) for entry in result.shared] == [
        "pkg:golang/github.com/threedotslabs/watermill@v1.5.3"
    ]


def test_flags_an_ecosystem_as_uncovered_when_only_trivy_has_components() -> None:
    github = bom(component("pkg:golang/example.com/a@v1.0.0"), component("pkg:npm/only-github@1"))
    trivy = bom(
        component("pkg:golang/example.com/a@v1.0.0"),
        component("pkg:pypi/requests@2.0.0"),
        component("pkg:pypi/flask@3.0.0"),
    )

    summaries = summarize_ecosystems(compare(github, trivy))

    assert [
        (s.purl_type, s.shared, s.trivy_only, s.github_only, s.uncovered) for s in summaries
    ] == [
        ("pypi", 0, 2, 0, True),
        ("golang", 1, 0, 0, False),
        ("npm", 0, 0, 1, False),
    ]


def test_reports_a_version_mismatch_without_making_the_ecosystem_uncovered() -> None:
    github = bom(component("pkg:npm/foo@1.0.0"))
    trivy = bom(component("pkg:npm/foo@2.0.0"), component("pkg:npm/foo@3.0.0"))

    result = compare(github, trivy)
    mismatches = find_version_mismatches(result)
    (summary,) = summarize_ecosystems(result)

    assert [(m.package, m.github_versions, m.trivy_versions) for m in mismatches] == [
        (PackageId("npm", None, "foo"), ("1.0.0",), ("2.0.0", "3.0.0"))
    ]
    assert (summary.purl_type, summary.github_only, summary.trivy_only) == ("npm", 1, 2)
    assert summary.uncovered is False


def test_a_package_that_only_one_side_has_is_not_a_version_mismatch() -> None:
    result = compare(bom(component("pkg:npm/foo@1")), bom(component("pkg:npm/bar@1")))

    assert find_version_mismatches(result) == ()


def test_disagrees_when_either_side_has_a_keyed_component_the_other_lacks() -> None:
    same = bom(component("pkg:npm/foo@1"))

    assert disagrees(compare(same, same)) is False
    assert disagrees(compare(same, bom())) is True
    assert disagrees(compare(bom(), same)) is True


def test_every_input_component_lands_in_exactly_one_bucket_per_side() -> None:
    github = bom(
        component("pkg:npm/shared@1"),
        component("pkg:npm/shared@1"),
        component("pkg:npm/github-only@1"),
        component(None, name="loose"),
        root=GITHUB_ROOT,
    )
    trivy = bom(
        component("pkg:npm/shared@1"),
        component("pkg:pypi/trivy-only@1"),
        component(None, name="lockfile", kind="application"),
        component(None, name="another"),
        root=TRIVY_ROOT,
    )

    result = compare(github, trivy)

    assert result.accounting(Side.GITHUB) == SideAccounting(
        input_components=5, shared=2, only=1, unkeyed=1, dropped_root=1
    )
    assert result.accounting(Side.TRIVY) == SideAccounting(
        input_components=5, shared=1, only=1, unkeyed=2, dropped_root=1
    )


def test_a_comparison_that_loses_a_component_fails_loudly() -> None:
    complete = compare(bom(component("pkg:npm/a@1"), component("pkg:npm/b@1")), bom())

    with pytest.raises(LosslessInvariantViolation, match=r"github side lost components: 2 in, 1"):
        dataclasses.replace(complete, github_only=complete.github_only[:1])


def test_a_comparison_that_invents_a_component_fails_loudly() -> None:
    complete = compare(bom(), bom(component("pkg:npm/a@1")))

    with pytest.raises(LosslessInvariantViolation, match=r"trivy side lost components: 0 in, 1"):
        dataclasses.replace(complete, input_components=PerSide(github=0, trivy=0))

import dataclasses

import pytest

from depgraph_gap.comparison import (
    compare,
    has_uncovered_ecosystem,
    find_version_mismatches,
    summarize_ecosystems,
)
from depgraph_gap.domain import (
    DropReason,
    DroppedComponent,
    PackageId,
    PerSide,
    Repository,
    Side,
    SideAccounting,
)
from depgraph_gap.errors import LosslessInvariantViolation
from tests.builders import WIDGET, bom, component

GITHUB_ROOT = component("pkg:github/acme/widget@main", name="com.github.acme/widget")
TRIVY_ROOT = component(None, name="https://github.com/acme/widget", kind="application")
NO_MODULE_DROP = {DropReason.ROOT: 0, DropReason.REPOSITORY_MODULE: 0}


def test_drops_the_root_of_each_side_with_the_reason_root() -> None:
    github = bom(component("pkg:npm/left-pad@1.0.0"), root=GITHUB_ROOT)
    trivy = bom(component("pkg:npm/left-pad@1.0.0"), root=TRIVY_ROOT)

    result = compare(github, trivy, WIDGET)

    assert result.dropped == PerSide(
        github=(DroppedComponent(GITHUB_ROOT, DropReason.ROOT),),
        trivy=(DroppedComponent(TRIVY_ROOT, DropReason.ROOT),),
    )
    assert [str(entry.purl) for entry in result.shared] == ["pkg:npm/left-pad@1.0.0"]
    assert result.github_only == ()
    assert result.trivy_only == ()


def test_drops_the_repository_go_module_on_both_sides_with_its_own_reason() -> None:
    github_module = component("pkg:golang/github.com/acme/widget", name="github.com/acme/widget")
    trivy_module = component("pkg:golang/github.com/Acme/Widget", name="github.com/Acme/Widget")
    dependency = component("pkg:golang/github.com/other/lib@v1.0.0", name="lib", version="v1.0.0")

    result = compare(
        bom(github_module, dependency, root=GITHUB_ROOT),
        bom(dependency, trivy_module, root=TRIVY_ROOT),
        WIDGET,
    )

    assert result.dropped == PerSide(
        github=(
            DroppedComponent(GITHUB_ROOT, DropReason.ROOT),
            DroppedComponent(github_module, DropReason.REPOSITORY_MODULE),
        ),
        trivy=(
            DroppedComponent(TRIVY_ROOT, DropReason.ROOT),
            DroppedComponent(trivy_module, DropReason.REPOSITORY_MODULE),
        ),
    )
    assert [str(entry.purl) for entry in result.shared] == [
        "pkg:golang/github.com/other/lib@v1.0.0"
    ]
    assert result.accounting(Side.TRIVY).dropped == {
        DropReason.ROOT: 1,
        DropReason.REPOSITORY_MODULE: 1,
    }
    assert result.accounting(Side.TRIVY).dropped_total == 2


def test_drops_the_repository_go_module_whatever_its_version_and_major_suffix() -> None:
    purls = [
        "pkg:golang/github.com/acme/widget@v1.2.3",
        "pkg:golang/github.com/acme/widget/v2",
        "pkg:golang/github.com/acme/widget/v10@v10.0.0",
    ]

    result = compare(bom(), bom(*[component(purl) for purl in purls]), WIDGET)

    assert [entry.reason for entry in result.dropped.trivy] == [DropReason.REPOSITORY_MODULE] * 3
    assert result.trivy_only == ()


def test_matches_the_repository_go_module_case_insensitively_in_both_directions() -> None:
    mixed_case = Repository("ThreeDotsLabs", "Watermill")
    purls = [
        "pkg:golang/github.com/threedotslabs/watermill",
        "pkg:golang/github.com/THREEDOTSLABS/WATERMILL",
    ]

    result = compare(bom(), bom(*[component(purl) for purl in purls]), mixed_case)

    assert len(result.dropped.trivy) == 2
    assert result.trivy_only == ()


@pytest.mark.parametrize(
    "purl",
    [
        "pkg:golang/github.com/acme/widget/internal",
        "pkg:golang/github.com/acme/widget/v1",
        "pkg:golang/github.com/acme/widget/v2/sub",
        "pkg:golang/github.com/acme/widget-extra",
        "pkg:golang/github.com/other/widget",
        "pkg:golang/gitlab.com/acme/widget",
        "pkg:npm/widget",
        "pkg:pypi/acme/widget",
        "pkg:githubactions/acme/widget",
    ],
)
def test_keeps_every_component_that_does_not_identify_the_repository_module(purl: str) -> None:
    result = compare(bom(), bom(component(purl)), WIDGET)

    assert result.dropped.trivy == ()
    assert [str(entry.purl) for entry in result.trivy_only] == [purl]


def test_a_go_repository_without_dependencies_is_not_an_uncovered_golang_ecosystem() -> None:
    github = bom(root=GITHUB_ROOT)
    trivy = bom(
        component("pkg:golang/github.com/acme/widget", name="github.com/acme/widget"),
        component(None, name="go.mod", kind="application"),
        root=TRIVY_ROOT,
    )

    result = compare(github, trivy, WIDGET)

    assert summarize_ecosystems(result) == ()
    assert [entry.name for entry in result.unkeyed.trivy] == ["go.mod"]


def test_a_go_repository_whose_only_trivy_only_golang_component_is_stdlib_is_not_uncovered() -> None:
    github = bom(component("pkg:npm/foo@1"), root=GITHUB_ROOT)
    trivy = bom(
        component("pkg:npm/foo@1"),
        component("pkg:golang/stdlib@v1.24.0", name="stdlib", version="v1.24.0"),
        root=TRIVY_ROOT,
    )

    result = compare(github, trivy, WIDGET)
    golang = next(s for s in summarize_ecosystems(result) if s.purl_type == "golang")

    assert [str(entry.purl) for entry in result.trivy_only] == ["pkg:golang/stdlib@v1.24.0"]
    assert result.accounting(Side.TRIVY).only == 1
    assert (golang.trivy_only, golang.trivy_only_ignored, golang.uncovered) == (1, 1, False)
    assert has_uncovered_ecosystem(result) is False


def test_stdlib_next_to_a_real_trivy_only_golang_dependency_is_still_uncovered() -> None:
    trivy = bom(
        component("pkg:golang/stdlib@v1.24.0", name="stdlib", version="v1.24.0"),
        component("pkg:golang/example.com/lib@v1.0.0", name="lib", version="v1.0.0"),
    )

    result = compare(bom(), trivy, WIDGET)
    (golang,) = summarize_ecosystems(result)

    assert (golang.trivy_only, golang.trivy_only_ignored, golang.uncovered) == (2, 1, True)
    assert has_uncovered_ecosystem(result) is True


def test_a_component_named_stdlib_in_another_ecosystem_is_not_ignored() -> None:
    result = compare(bom(), bom(component("pkg:npm/stdlib@1.0.0")), WIDGET)
    (npm,) = summarize_ecosystems(result)

    assert (npm.trivy_only, npm.trivy_only_ignored, npm.uncovered) == (1, 0, True)


def test_does_not_drop_a_repository_purl_that_is_not_the_root() -> None:
    other = component("pkg:github/acme/other@main")
    github = bom(other, root=GITHUB_ROOT)

    result = compare(github, bom(), WIDGET)

    assert [str(entry.purl) for entry in result.github_only] == ["pkg:github/acme/other@main"]


def test_lists_components_without_a_usable_purl_per_side_and_never_compares_them() -> None:
    github = bom(
        component(None, name="go.mod", kind="application"),
        component("garbage", name="broken", version="1"),
    )
    trivy = bom(component(None, name="go.mod", kind="application"))

    result = compare(github, trivy, WIDGET)

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

    result = compare(github, trivy, WIDGET)

    assert [(str(entry.purl), entry.occurrences) for entry in result.shared] == [
        ("pkg:npm/foo@1", PerSide(github=3, trivy=2))
    ]
    assert result.accounting(Side.GITHUB).shared == 3
    assert result.accounting(Side.TRIVY).shared == 2


def test_matches_purls_that_differ_only_in_spelling() -> None:
    github = bom(component("pkg:golang/github.com/ThreeDotsLabs/watermill@v1.5.3"))
    trivy = bom(component("pkg:golang/github.com/threedotslabs/watermill@v1.5.3"))

    result = compare(github, trivy, WIDGET)

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

    summaries = summarize_ecosystems(compare(github, trivy, WIDGET))

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

    result = compare(github, trivy, WIDGET)
    mismatches = find_version_mismatches(result)
    (summary,) = summarize_ecosystems(result)

    assert [(m.package, m.github_versions, m.trivy_versions) for m in mismatches] == [
        (PackageId("npm", None, "foo"), ("1.0.0",), ("2.0.0", "3.0.0"))
    ]
    assert (summary.purl_type, summary.github_only, summary.trivy_only) == ("npm", 1, 2)
    assert summary.uncovered is False


def test_a_package_that_only_one_side_has_is_not_a_version_mismatch() -> None:
    result = compare(bom(component("pkg:npm/foo@1")), bom(component("pkg:npm/bar@1")), WIDGET)

    assert find_version_mismatches(result) == ()


def test_an_ecosystem_that_only_trivy_has_is_uncovered_for_the_fail_decision() -> None:
    github = bom(component("pkg:npm/foo@1"))
    trivy = bom(component("pkg:npm/foo@1"), component("pkg:pypi/bar@1"))

    assert has_uncovered_ecosystem(compare(github, trivy, WIDGET)) is True


def test_a_difference_in_a_covered_or_github_only_ecosystem_is_not_uncovered() -> None:
    covered_but_different = compare(
        bom(component("pkg:npm/foo@1")), bom(component("pkg:npm/foo@2")), WIDGET
    )
    github_only_ecosystem = compare(
        bom(component("pkg:githubactions/actions/checkout@v4")), bom(), WIDGET
    )

    assert has_uncovered_ecosystem(covered_but_different) is False
    assert has_uncovered_ecosystem(github_only_ecosystem) is False


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

    result = compare(github, trivy, WIDGET)

    assert result.accounting(Side.GITHUB) == SideAccounting(
        input_components=5, shared=2, only=1, unkeyed=1, dropped=NO_MODULE_DROP | {DropReason.ROOT: 1}
    )
    assert result.accounting(Side.TRIVY) == SideAccounting(
        input_components=5, shared=1, only=1, unkeyed=2, dropped=NO_MODULE_DROP | {DropReason.ROOT: 1}
    )


def test_a_comparison_that_loses_a_component_fails_loudly() -> None:
    complete = compare(bom(component("pkg:npm/a@1"), component("pkg:npm/b@1")), bom(), WIDGET)

    with pytest.raises(LosslessInvariantViolation, match=r"github side lost components: 2 in, 1"):
        dataclasses.replace(complete, github_only=complete.github_only[:1])


def test_a_comparison_that_invents_a_component_fails_loudly() -> None:
    complete = compare(bom(), bom(component("pkg:npm/a@1")), WIDGET)

    with pytest.raises(LosslessInvariantViolation, match=r"trivy side lost components: 0 in, 1"):
        dataclasses.replace(complete, input_components=PerSide(github=0, trivy=0))

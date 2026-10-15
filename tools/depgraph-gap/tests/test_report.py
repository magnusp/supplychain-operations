from depgraph_gap.comparison import compare
from depgraph_gap.domain import Attempt, Repository, RunRecord, ToolVersions
from depgraph_gap.report import build_report, render_summary
from tests.builders import bom, component

VERSIONS = ToolVersions(gh="gh version 2.91.0", trivy="Version: 0.75.0", cyclonedx="0.33.1")
REPOSITORY = Repository("acme", "widget")


def report_for(attempts: tuple[Attempt, ...]) -> dict:
    github = bom(
        component("pkg:golang/example.com/a@v1", name="a", version="v1"),
        component("pkg:npm/foo@1", name="foo", version="1"),
        root=component("pkg:github/acme/widget@main"),
    )
    trivy = bom(
        component("pkg:golang/example.com/a@v1", name="a", version="v1"),
        component("pkg:npm/foo@2", name="foo", version="2"),
        component("pkg:pypi/requests@2.0.0", name="requests", version="2.0.0"),
        component(None, name="poetry.lock", kind="application"),
        component("pkg:golang/github.com/acme/widget", name="github.com/acme/widget"),
        root=component(None, name="https://github.com/acme/widget", kind="application"),
    )
    return build_report(RunRecord(REPOSITORY, attempts, VERSIONS), compare(github, trivy, REPOSITORY))


def test_the_report_leads_with_ecosystems_and_keeps_package_detail_underneath() -> None:
    report = report_for((Attempt("abc", "abc"),))

    assert list(report)[:4] == ["repository", "run", "accounting", "ecosystems"]
    assert report["ecosystems"] == [
        {
            "purl_type": "pypi",
            "trivy_only": 1,
            "github_only": 0,
            "shared": 0,
            "trivy_only_ignored": 0,
            "uncovered": True,
        },
        {
            "purl_type": "golang",
            "trivy_only": 0,
            "github_only": 0,
            "shared": 1,
            "trivy_only_ignored": 0,
            "uncovered": False,
        },
        {
            "purl_type": "npm",
            "trivy_only": 1,
            "github_only": 1,
            "shared": 0,
            "trivy_only_ignored": 0,
            "uncovered": False,
        },
    ]
    assert report["uncovered_ecosystems"] == ["pypi"]
    assert report["version_mismatches"] == [
        {"package": "pkg:npm/foo", "github_versions": ["1"], "trivy_versions": ["2"]}
    ]
    assert report["packages"]["trivy_only"] == [
        {"purl": "pkg:npm/foo@2", "name": "foo", "version": "2", "occurrences": 1},
        {
            "purl": "pkg:pypi/requests@2.0.0",
            "name": "requests",
            "version": "2.0.0",
            "occurrences": 1,
        },
    ]
    assert report["packages"]["unkeyed"]["trivy"] == [
        {"name": "poetry.lock", "version": None, "kind": "application", "purl": None}
    ]
    assert report["packages"]["dropped"] == {
        "github": [
            {
                "reason": "root",
                "name": "component",
                "version": None,
                "kind": "library",
                "purl": "pkg:github/acme/widget@main",
            }
        ],
        "trivy": [
            {
                "reason": "root",
                "name": "https://github.com/acme/widget",
                "version": None,
                "kind": "application",
                "purl": None,
            },
            {
                "reason": "repository_module",
                "name": "github.com/acme/widget",
                "version": None,
                "kind": "library",
                "purl": "pkg:golang/github.com/acme/widget",
            },
        ],
    }


def test_the_report_records_shas_tool_versions_and_per_side_counts() -> None:
    report = report_for((Attempt("abc", "abc"),))

    assert report["run"] == {
        "attempts": [{"sha_before": "abc", "sha_after": "abc"}],
        "drifted": False,
        "drift_warning": None,
        "tool_versions": {
            "gh": "gh version 2.91.0",
            "trivy": "Version: 0.75.0",
            "cyclonedx": "0.33.1",
        },
    }
    assert report["accounting"] == {
        "github": {
            "input": 3,
            "shared": 1,
            "only": 1,
            "unkeyed": 0,
            "dropped": {"root": 1, "repository_module": 0},
        },
        "trivy": {
            "input": 6,
            "shared": 1,
            "only": 2,
            "unkeyed": 1,
            "dropped": {"root": 1, "repository_module": 1},
        },
    }


def test_a_drift_that_survives_all_attempts_is_warned_about_with_both_shas() -> None:
    report = report_for((Attempt("a1", "a2"), Attempt("a2", "a3")))

    assert report["run"]["drifted"] is True
    assert report["run"]["drift_warning"] == (
        "The default branch moved from a2 to a3 during the last of 2 attempts. "
        "The two inventories may describe different commits."
    )
    assert "warning: The default branch moved from a2 to a3" in render_summary(report)


def test_the_summary_flags_uncovered_ecosystems_and_shows_the_accounting() -> None:
    summary = render_summary(report_for((Attempt("abc", "abc"),)))

    assert summary == "\n".join(
        [
            "repository: acme/widget",
            "commit: abc",
            "attempts: 1",
            "ecosystems by purl type:",
            "  UNCOVERED pypi  trivy-only=1  github-only=0  shared=0",
            "  golang  trivy-only=0  github-only=0  shared=1",
            "  npm  trivy-only=1  github-only=1  shared=0",
            "uncovered ecosystems: pypi",
            "version mismatches: 1",
            "accounting per side (components in = components placed in a bucket):",
            "  github: 3 in = 1 shared + 1 only + 0 unkeyed + 1 dropped (1 root, 0 repository module)",
            "  trivy: 6 in = 1 shared + 2 only + 1 unkeyed + 2 dropped (1 root, 1 repository module)",
        ]
    )


def test_the_report_and_summary_show_how_many_trivy_only_components_were_ignored() -> None:
    github = bom(root=component("pkg:github/acme/widget@main"))
    trivy = bom(component("pkg:golang/stdlib@v1.24.0", name="stdlib", version="v1.24.0"))
    record = RunRecord(REPOSITORY, (Attempt("abc", "abc"),), VERSIONS)

    report = build_report(record, compare(github, trivy, REPOSITORY))

    assert report["ecosystems"] == [
        {
            "purl_type": "golang",
            "trivy_only": 1,
            "github_only": 0,
            "shared": 0,
            "trivy_only_ignored": 1,
            "uncovered": False,
        }
    ]
    assert report["uncovered_ecosystems"] == []
    assert report["packages"]["trivy_only"] == [
        {"purl": "pkg:golang/stdlib@v1.24.0", "name": "stdlib", "version": "v1.24.0", "occurrences": 1}
    ]
    assert (
        "  golang  trivy-only=1  github-only=0  shared=0"
        "  (1 trivy-only ignored for the uncovered decision)"
    ) in render_summary(report).splitlines()
    assert "uncovered ecosystems: none" in render_summary(report)

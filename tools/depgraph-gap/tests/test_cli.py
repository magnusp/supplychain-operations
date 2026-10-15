import json
from pathlib import Path

import pytest

from depgraph_gap.cli import parse_repository, run
from depgraph_gap.domain import Bom, Repository, ToolVersions
from depgraph_gap.errors import InvalidRepository
from tests.builders import bom, component

VERSIONS = ToolVersions(gh="gh 1", trivy="trivy 1", cyclonedx="cyclonedx 1")
ENVIRON = {"GITHUB_TOKEN": "t"}


GITHUB = bom(component("pkg:npm/foo@1"), root=component("pkg:github/acme/widget@main"))


class FakeSources:
    def __init__(
        self, trivy: Bom, head_shas: list[str] | None = None, github: Bom = GITHUB
    ) -> None:
        self._github = github
        self._trivy = trivy
        self._head_shas = iter(head_shas or [])

    def head_sha(self, repository: Repository) -> str:
        return next(self._head_shas, "abc123")

    def github_bom(self, repository: Repository) -> Bom:
        return self._github

    def trivy_bom(self, repository: Repository, sha: str) -> Bom:
        return self._trivy


AGREEING = bom(component("pkg:npm/foo@1"))
DISAGREEING = bom(component("pkg:npm/foo@1"), component("pkg:pypi/bar@1", name="bar", version="1"))


def opener(trivy: Bom, head_shas: list[str] | None = None, github: Bom = GITHUB):
    return lambda environ: (FakeSources(trivy, head_shas, github), VERSIONS)


def test_prints_the_json_report_on_stdout_and_the_summary_on_stderr(capsys) -> None:
    code = run(["acme/widget"], ENVIRON, opener(DISAGREEING))

    captured = capsys.readouterr()
    assert code == 0
    assert json.loads(captured.out)["accounting"] == {
        "github": {
            "input": 2,
            "shared": 1,
            "only": 0,
            "unkeyed": 0,
            "dropped": {"root": 1, "repository_module": 0},
        },
        "trivy": {
            "input": 2,
            "shared": 1,
            "only": 1,
            "unkeyed": 0,
            "dropped": {"root": 0, "repository_module": 0},
        },
    }
    assert "UNCOVERED pypi" in captured.err


def test_an_uncovered_ecosystem_exits_zero_unless_fail_on_diff_is_set(capsys) -> None:
    assert run(["acme/widget"], ENVIRON, opener(DISAGREEING)) == 0
    assert run(["acme/widget", "--fail-on-diff"], ENVIRON, opener(DISAGREEING)) == 1


def test_fail_on_diff_exits_zero_when_the_sides_agree(capsys) -> None:
    assert run(["acme/widget", "--fail-on-diff"], ENVIRON, opener(AGREEING)) == 0


def test_fail_on_diff_exits_zero_when_only_github_has_an_ecosystem(capsys) -> None:
    github_with_actions = bom(
        component("pkg:npm/foo@1"),
        component("pkg:githubactions/actions/checkout@v4"),
        root=component("pkg:github/acme/widget@main"),
    )

    code = run(
        ["acme/widget", "--fail-on-diff"], ENVIRON, opener(AGREEING, github=github_with_actions)
    )

    captured = capsys.readouterr()
    assert code == 0
    assert "githubactions  trivy-only=0  github-only=1  shared=0" in captured.err
    assert "uncovered ecosystems: none" in captured.err


def test_fail_on_diff_exits_zero_when_only_versions_differ(capsys) -> None:
    trivy_with_other_version = bom(component("pkg:npm/foo@2"))

    code = run(["acme/widget", "--fail-on-diff"], ENVIRON, opener(trivy_with_other_version))

    assert code == 0


GO_STDLIB = component("pkg:golang/stdlib@v1.24.0", name="stdlib", version="v1.24.0")
GO_DEPENDENCY = component("pkg:golang/example.com/lib@v1.0.0", name="lib", version="v1.0.0")


def test_fail_on_diff_exits_zero_when_the_only_trivy_only_golang_component_is_stdlib(
    tmp_path: Path, capsys
) -> None:
    trivy = bom(component("pkg:npm/foo@1"), GO_STDLIB)
    target = tmp_path / "gap.cdx.json"

    code = run(
        ["acme/widget", "--fail-on-diff", "--emit-gap-bom", str(target)],
        ENVIRON,
        opener(trivy),
    )

    captured = capsys.readouterr()
    assert code == 0
    assert "UNCOVERED" not in captured.err
    assert (
        "  golang  trivy-only=1  github-only=0  shared=0"
        "  (1 trivy-only ignored for the uncovered decision)"
    ) in captured.err
    assert [c["purl"] for c in json.loads(target.read_text())["components"]] == [
        "pkg:golang/stdlib@v1.24.0"
    ]
    assert {
        "purl_type": "golang",
        "trivy_only": 1,
        "github_only": 0,
        "shared": 0,
        "trivy_only_ignored": 1,
        "uncovered": False,
    } in json.loads(captured.out)["ecosystems"]


def test_fail_on_diff_exits_one_when_golang_has_a_real_trivy_only_dependency_besides_stdlib(
    capsys,
) -> None:
    trivy = bom(component("pkg:npm/foo@1"), GO_STDLIB, GO_DEPENDENCY)

    code = run(["acme/widget", "--fail-on-diff"], ENVIRON, opener(trivy))

    captured = capsys.readouterr()
    assert code == 1
    assert (
        "  UNCOVERED golang  trivy-only=2  github-only=0  shared=0"
        "  (1 trivy-only ignored for the uncovered decision)"
    ) in captured.err


def test_writes_a_gap_bom_of_the_trivy_only_components(tmp_path: Path, capsys) -> None:
    target = tmp_path / "gap.cdx.json"

    code = run(["acme/widget", "--emit-gap-bom", str(target)], ENVIRON, opener(DISAGREEING))

    document = json.loads(target.read_text())
    assert code == 0
    assert [c["purl"] for c in document["components"]] == ["pkg:pypi/bar@1"]
    assert document["metadata"]["component"] == {
        "type": "application",
        "name": "acme/widget",
        "version": "abc123",
    }


def test_a_drift_warning_reaches_the_report_and_does_not_fail_the_run(capsys) -> None:
    shas = ["a1", "a2", "a2", "a3", "a3", "a4", "a4", "a5"]

    code = run(["acme/widget"], ENVIRON, opener(AGREEING, shas))

    captured = capsys.readouterr()
    assert code == 0
    assert json.loads(captured.out)["run"]["drifted"] is True
    assert "warning: The default branch moved from a4 to a5" in captured.err


def test_exits_two_with_a_clear_message_when_the_token_is_unset(capsys) -> None:
    code = run(["acme/widget"], {}, opener(AGREEING))

    assert code == 2
    assert "GITHUB_TOKEN is not set" in capsys.readouterr().err


def test_exits_two_when_the_repository_is_not_owner_slash_repo(capsys) -> None:
    code = run(["https://github.com/acme/widget"], ENVIRON, opener(AGREEING))

    assert code == 2
    assert "expected owner/repo" in capsys.readouterr().err


def test_exits_two_when_the_gap_bom_cannot_be_written(tmp_path: Path, capsys) -> None:
    target = tmp_path / "missing-directory" / "gap.json"

    code = run(["acme/widget", "--emit-gap-bom", str(target)], ENVIRON, opener(DISAGREEING))

    assert code == 2
    assert "missing-directory" in capsys.readouterr().err


def test_parses_owner_and_name() -> None:
    assert parse_repository("acme/wid.get-1") == Repository(owner="acme", name="wid.get-1")


@pytest.mark.parametrize("text", ["widget", "a/b/c", "", "acme/", "/widget", "a b/c"])
def test_rejects_text_that_is_not_owner_slash_repo(text: str) -> None:
    with pytest.raises(InvalidRepository):
        parse_repository(text)

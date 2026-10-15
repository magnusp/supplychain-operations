import pytest

from depgraph_gap.domain import Bom, Repository, ToolVersions
from depgraph_gap.errors import DependencyGraphDisabled, ToolFailed
from tests.builders import bom, component
from tests.live_support import run_noting_disabled_dependency_graph

VERSIONS = ToolVersions(gh="gh 1", trivy="trivy 1", cyclonedx="cyclonedx 1")
ENVIRON = {"GITHUB_TOKEN": "t"}


class FailingGithubSources:
    def __init__(self, error: Exception | None) -> None:
        self._error = error

    def head_sha(self, repository: Repository) -> str:
        return "abc123"

    def github_bom(self, repository: Repository) -> Bom:
        if self._error:
            raise self._error
        return bom(component("pkg:npm/foo@1"))

    def trivy_bom(self, repository: Repository, sha: str) -> Bom:
        return bom(component("pkg:npm/foo@1"))


def run_with(error: Exception | None):
    return run_noting_disabled_dependency_graph(
        ["acme/widget"], ENVIRON, lambda environ: (FailingGithubSources(error), VERSIONS)
    )


def test_a_disabled_dependency_graph_exits_two_and_is_noted_for_the_skip(capsys) -> None:
    result = run_with(DependencyGraphDisabled("404"))

    assert (result.code, result.dependency_graph_disabled) == (2, True)


@pytest.mark.parametrize("error", [ToolFailed("`gh api` exited with 1: HTTP 403"), OSError("disk")])
def test_any_other_failure_exits_two_and_is_not_noted_for_the_skip(
    error: Exception, capsys
) -> None:
    result = run_with(error)

    assert (result.code, result.dependency_graph_disabled) == (2, False)


def test_a_successful_run_is_not_noted_for_the_skip(capsys) -> None:
    result = run_with(None)

    assert (result.code, result.dependency_graph_disabled) == (0, False)

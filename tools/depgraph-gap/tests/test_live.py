import json
import os

import pytest

from depgraph_gap.cli import open_external_tools
from tests.live_support import run_noting_disabled_dependency_graph

pytestmark = pytest.mark.live


def test_runs_against_the_real_tools_and_accounts_for_every_component(
    live_repo: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert os.environ.get("GITHUB_TOKEN"), "the live test needs GITHUB_TOKEN in the environment"

    result = run_noting_disabled_dependency_graph([live_repo], os.environ, open_external_tools)

    captured = capsys.readouterr()
    if result.dependency_graph_disabled:
        pytest.skip(
            f"the dependency graph is disabled for {live_repo}: "
            "the SBOM endpoint returned 404. Pass --live-repo with a repository that enables it."
        )
    assert result.code == 0, captured.err
    for side, counts in json.loads(captured.out)["accounting"].items():
        accounted = (
            counts["shared"] + counts["only"] + counts["unkeyed"] + sum(counts["dropped"].values())
        )
        assert accounted == counts["input"], side

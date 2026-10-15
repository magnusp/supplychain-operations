import json
import os

import pytest

from depgraph_gap.cli import main

pytestmark = pytest.mark.live


def test_runs_against_the_real_tools_and_accounts_for_every_component(
    live_repo: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert os.environ.get("GITHUB_TOKEN"), "the live test needs GITHUB_TOKEN in the environment"

    code = main([live_repo])

    captured = capsys.readouterr()
    assert code == 0, captured.err
    for side, counts in json.loads(captured.out)["accounting"].items():
        accounted = (
            counts["shared"] + counts["only"] + counts["unkeyed"] + sum(counts["dropped"].values())
        )
        assert accounted == counts["input"], side

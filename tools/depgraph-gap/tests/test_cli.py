import json

import pytest

from depgraph_gap.cli import parse_repository, run
from depgraph_gap.domain import Bom, Repository, ToolVersions
from depgraph_gap.errors import InvalidRepository
from tests.builders import bom, component

VERSIONS = ToolVersions(gh="gh 1", trivy="trivy 1", cyclonedx="cyclonedx 1")


class StableSources:
    def head_sha(self, repository: Repository) -> str:
        return "abc123"

    def github_bom(self, repository: Repository) -> Bom:
        return bom(component("pkg:npm/foo@1"), root=component("pkg:github/acme/widget@main"))

    def trivy_bom(self, repository: Repository, sha: str) -> Bom:
        return bom(component("pkg:npm/foo@1"), component("pkg:pypi/bar@1"))


def open_stable(environ):
    return StableSources(), VERSIONS


def test_prints_the_accounting_of_each_side_and_exits_zero(capsys) -> None:
    code = run(["acme/widget"], {"GITHUB_TOKEN": "t"}, open_stable)

    assert code == 0
    assert json.loads(capsys.readouterr().out)["accounting"] == {
        "github": {"input": 2, "shared": 1, "only": 0, "unkeyed": 0, "dropped_root": 1},
        "trivy": {"input": 2, "shared": 1, "only": 1, "unkeyed": 0, "dropped_root": 0},
    }


def test_exits_two_with_a_clear_message_when_the_token_is_unset(capsys) -> None:
    code = run(["acme/widget"], {}, open_stable)

    assert code == 2
    assert "GITHUB_TOKEN is not set" in capsys.readouterr().err


def test_exits_two_when_the_repository_is_not_owner_slash_repo(capsys) -> None:
    code = run(["https://github.com/acme/widget"], {"GITHUB_TOKEN": "t"}, open_stable)

    assert code == 2
    assert "expected owner/repo" in capsys.readouterr().err


def test_parses_owner_and_name() -> None:
    assert parse_repository("acme/wid.get-1") == Repository(owner="acme", name="wid.get-1")


@pytest.mark.parametrize("text", ["widget", "a/b/c", "", "acme/", "/widget", "a b/c"])
def test_rejects_text_that_is_not_owner_slash_repo(text: str) -> None:
    with pytest.raises(InvalidRepository):
        parse_repository(text)

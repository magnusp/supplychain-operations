from depgraph_gap.domain import Attempt, Bom, Repository
from depgraph_gap.pipeline import collect
from tests.builders import bom, component

REPOSITORY = Repository(owner="acme", name="widget")


class FakeSources:
    def __init__(self, head_shas: list[str]) -> None:
        self._head_shas = iter(head_shas)
        self.trivy_scans: list[str] = []
        self.github_fetches = 0

    def head_sha(self, repository: Repository) -> str:
        return next(self._head_shas)

    def github_bom(self, repository: Repository) -> Bom:
        self.github_fetches += 1
        return bom(component("pkg:npm/github-run-%d@1" % self.github_fetches))

    def trivy_bom(self, repository: Repository, sha: str) -> Bom:
        self.trivy_scans.append(sha)
        return bom(component(f"pkg:npm/trivy-at-{sha}@1"))


def test_a_stable_head_needs_one_attempt() -> None:
    sources = FakeSources(["aaa", "aaa"])

    collected = collect(REPOSITORY, sources)

    assert collected.attempts == (Attempt("aaa", "aaa"),)
    assert sources.trivy_scans == ["aaa"]


def test_redoes_the_whole_run_when_head_moves_and_keeps_the_last_run() -> None:
    sources = FakeSources(["aaa", "bbb", "bbb", "bbb"])

    collected = collect(REPOSITORY, sources)

    assert collected.attempts == (Attempt("aaa", "bbb"), Attempt("bbb", "bbb"))
    assert sources.trivy_scans == ["aaa", "bbb"]
    assert sources.github_fetches == 2
    assert [c.purl for c in collected.trivy.components] == ["pkg:npm/trivy-at-bbb@1"]
    assert [c.purl for c in collected.github.components] == ["pkg:npm/github-run-2@1"]


def test_gives_up_after_three_redos_and_records_the_drift() -> None:
    shas = ["a1", "a2", "a2", "a3", "a3", "a4", "a4", "a5"]
    sources = FakeSources(shas)

    collected = collect(REPOSITORY, sources)

    assert collected.attempts == (
        Attempt("a1", "a2"),
        Attempt("a2", "a3"),
        Attempt("a3", "a4"),
        Attempt("a4", "a5"),
    )
    assert collected.attempts[-1].drifted is True
    assert sources.trivy_scans == ["a1", "a2", "a3", "a4"]


def test_succeeds_on_the_last_allowed_attempt() -> None:
    shas = ["a1", "a2", "a2", "a3", "a3", "a4", "a4", "a4"]
    sources = FakeSources(shas)

    collected = collect(REPOSITORY, sources)

    assert len(collected.attempts) == 4
    assert collected.attempts[-1].drifted is False

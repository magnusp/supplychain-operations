from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from depgraph_gap.cli import OpenSources, run
from depgraph_gap.domain import Bom, Repository, ToolVersions
from depgraph_gap.errors import DependencyGraphDisabled
from depgraph_gap.pipeline import Sources


@dataclass(frozen=True, slots=True)
class LiveRun:
    code: int
    dependency_graph_disabled: bool


class _WatchedSources:
    def __init__(self, inner: Sources) -> None:
        self._inner = inner
        self.dependency_graph_disabled = False

    def head_sha(self, repository: Repository) -> str:
        return self._inner.head_sha(repository)

    def github_bom(self, repository: Repository) -> Bom:
        try:
            return self._inner.github_bom(repository)
        except DependencyGraphDisabled:
            self.dependency_graph_disabled = True
            raise

    def trivy_bom(self, repository: Repository, sha: str) -> Bom:
        return self._inner.trivy_bom(repository, sha)


def run_noting_disabled_dependency_graph(
    argv: Sequence[str], environ: Mapping[str, str], open_sources: OpenSources
) -> LiveRun:
    watched: list[_WatchedSources] = []

    def open_watched(env: Mapping[str, str]) -> tuple[Sources, ToolVersions]:
        sources, versions = open_sources(env)
        watched.append(_WatchedSources(sources))
        return watched[-1], versions

    code = run(argv, environ, open_watched)
    return LiveRun(code, any(sources.dependency_graph_disabled for sources in watched))

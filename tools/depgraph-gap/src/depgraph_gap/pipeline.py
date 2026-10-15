from dataclasses import dataclass
from typing import Protocol

from depgraph_gap.domain import Attempt, Bom, Repository

MAX_REDOS = 3


class Sources(Protocol):
    def head_sha(self, repository: Repository) -> str: ...

    def github_bom(self, repository: Repository) -> Bom: ...

    def trivy_bom(self, repository: Repository, sha: str) -> Bom: ...


@dataclass(frozen=True, slots=True)
class Collected:
    github: Bom
    trivy: Bom
    attempts: tuple[Attempt, ...]


def collect(repository: Repository, sources: Sources, max_redos: int = MAX_REDOS) -> Collected:
    attempts: list[Attempt] = []
    while True:
        sha_before = sources.head_sha(repository)
        github = sources.github_bom(repository)
        trivy = sources.trivy_bom(repository, sha_before)
        attempt = Attempt(sha_before=sha_before, sha_after=sources.head_sha(repository))
        attempts.append(attempt)
        if not attempt.drifted or len(attempts) > max_redos:
            return Collected(github=github, trivy=trivy, attempts=tuple(attempts))

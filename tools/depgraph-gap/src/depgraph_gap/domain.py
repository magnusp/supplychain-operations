from dataclasses import dataclass
from enum import Enum

from depgraph_gap.errors import LosslessInvariantViolation


class Side(Enum):
    GITHUB = "github"
    TRIVY = "trivy"


@dataclass(frozen=True, slots=True)
class PerSide[T]:
    github: T
    trivy: T

    def __getitem__(self, side: Side) -> T:
        return self.github if side is Side.GITHUB else self.trivy


@dataclass(frozen=True, slots=True)
class Repository:
    owner: str
    name: str

    def __str__(self) -> str:
        return f"{self.owner}/{self.name}"

    @property
    def url(self) -> str:
        return f"https://github.com/{self}"


@dataclass(frozen=True, slots=True)
class PackageId:
    type: str
    namespace: str | None
    name: str

    def __str__(self) -> str:
        namespace = f"{self.namespace}/" if self.namespace else ""
        return f"pkg:{self.type}/{namespace}{self.name}"


@dataclass(frozen=True, slots=True)
class Purl:
    package: PackageId
    version: str | None

    @property
    def type(self) -> str:
        return self.package.type

    def __str__(self) -> str:
        return f"{self.package}@{self.version}" if self.version else str(self.package)


@dataclass(frozen=True, slots=True)
class BomComponent:
    name: str
    version: str | None
    purl: str | None
    kind: str


@dataclass(frozen=True, slots=True)
class Bom:
    root: BomComponent | None
    components: tuple[BomComponent, ...]

    @property
    def component_count(self) -> int:
        return len(self.components) + (1 if self.root else 0)


@dataclass(frozen=True, slots=True)
class Component:
    purl: Purl
    name: str
    version: str | None
    occurrences: int


@dataclass(frozen=True, slots=True)
class UnkeyedComponent:
    name: str
    version: str | None
    kind: str
    raw_purl: str | None


@dataclass(frozen=True, slots=True)
class SharedComponent:
    purl: Purl
    occurrences: PerSide[int]


@dataclass(frozen=True, slots=True)
class SideAccounting:
    input_components: int
    shared: int
    only: int
    unkeyed: int
    dropped_root: int

    @property
    def accounted(self) -> int:
        return self.shared + self.only + self.unkeyed + self.dropped_root


@dataclass(frozen=True, slots=True)
class Comparison:
    shared: tuple[SharedComponent, ...]
    trivy_only: tuple[Component, ...]
    github_only: tuple[Component, ...]
    unkeyed: PerSide[tuple[UnkeyedComponent, ...]]
    dropped_root: PerSide[tuple[BomComponent, ...]]
    input_components: PerSide[int]

    def __post_init__(self) -> None:
        for side in Side:
            accounting = self.accounting(side)
            if accounting.accounted != accounting.input_components:
                raise LosslessInvariantViolation(
                    f"{side.value} side lost components: "
                    f"{accounting.input_components} in, {accounting.accounted} accounted for "
                    f"({accounting.shared} shared, {accounting.only} only, "
                    f"{accounting.unkeyed} unkeyed, {accounting.dropped_root} dropped root)"
                )

    def accounting(self, side: Side) -> SideAccounting:
        only = self.github_only if side is Side.GITHUB else self.trivy_only
        return SideAccounting(
            input_components=self.input_components[side],
            shared=sum(entry.occurrences[side] for entry in self.shared),
            only=sum(entry.occurrences for entry in only),
            unkeyed=len(self.unkeyed[side]),
            dropped_root=len(self.dropped_root[side]),
        )


@dataclass(frozen=True, slots=True)
class EcosystemSummary:
    purl_type: str
    shared: int
    trivy_only: int
    github_only: int

    @property
    def uncovered(self) -> bool:
        return self.trivy_only > 0 and self.shared == 0 and self.github_only == 0


@dataclass(frozen=True, slots=True)
class VersionMismatch:
    package: PackageId
    github_versions: tuple[str | None, ...]
    trivy_versions: tuple[str | None, ...]


@dataclass(frozen=True, slots=True)
class ToolVersions:
    gh: str
    trivy: str
    cyclonedx: str


@dataclass(frozen=True, slots=True)
class Attempt:
    sha_before: str
    sha_after: str

    @property
    def drifted(self) -> bool:
        return self.sha_before != self.sha_after


@dataclass(frozen=True, slots=True)
class RunRecord:
    repository: Repository
    attempts: tuple[Attempt, ...]
    tool_versions: ToolVersions

    @property
    def final_attempt(self) -> Attempt:
        return self.attempts[-1]

    @property
    def drifted(self) -> bool:
        return self.final_attempt.drifted

from collections import Counter
from dataclasses import dataclass

from depgraph_gap.domain import (
    Bom,
    BomComponent,
    Comparison,
    Component,
    EcosystemSummary,
    PackageId,
    PerSide,
    Purl,
    SharedComponent,
    UnkeyedComponent,
    VersionMismatch,
)
from depgraph_gap.purl import parse_purl


@dataclass(frozen=True, slots=True)
class _BucketedSide:
    keyed: dict[Purl, Component]
    unkeyed: tuple[UnkeyedComponent, ...]
    dropped_root: tuple[BomComponent, ...]


def compare(github: Bom, trivy: Bom) -> Comparison:
    github_side = _bucket_side(github)
    trivy_side = _bucket_side(trivy)
    shared_purls = github_side.keyed.keys() & trivy_side.keyed.keys()
    return Comparison(
        shared=tuple(
            SharedComponent(
                purl=purl,
                occurrences=PerSide(
                    github=github_side.keyed[purl].occurrences,
                    trivy=trivy_side.keyed[purl].occurrences,
                ),
            )
            for purl in sorted(shared_purls, key=str)
        ),
        trivy_only=_only(trivy_side.keyed, shared_purls),
        github_only=_only(github_side.keyed, shared_purls),
        unkeyed=PerSide(github=github_side.unkeyed, trivy=trivy_side.unkeyed),
        dropped_root=PerSide(github=github_side.dropped_root, trivy=trivy_side.dropped_root),
        input_components=PerSide(github=github.component_count, trivy=trivy.component_count),
    )


def summarize_ecosystems(comparison: Comparison) -> tuple[EcosystemSummary, ...]:
    shared = Counter(entry.purl.type for entry in comparison.shared)
    trivy_only = Counter(entry.purl.type for entry in comparison.trivy_only)
    github_only = Counter(entry.purl.type for entry in comparison.github_only)
    summaries = (
        EcosystemSummary(
            purl_type=purl_type,
            shared=shared[purl_type],
            trivy_only=trivy_only[purl_type],
            github_only=github_only[purl_type],
        )
        for purl_type in shared.keys() | trivy_only.keys() | github_only.keys()
    )
    return tuple(sorted(summaries, key=lambda summary: (not summary.uncovered, summary.purl_type)))


def find_version_mismatches(comparison: Comparison) -> tuple[VersionMismatch, ...]:
    github_versions = _versions_by_package(comparison.github_only)
    trivy_versions = _versions_by_package(comparison.trivy_only)
    return tuple(
        VersionMismatch(
            package=package,
            github_versions=github_versions[package],
            trivy_versions=trivy_versions[package],
        )
        for package in sorted(github_versions.keys() & trivy_versions.keys(), key=str)
    )


def disagrees(comparison: Comparison) -> bool:
    return bool(comparison.github_only or comparison.trivy_only)


def _bucket_side(bom: Bom) -> _BucketedSide:
    keyed: dict[Purl, Component] = {}
    unkeyed: list[UnkeyedComponent] = []
    for component in bom.components:
        purl = parse_purl(component.purl) if component.purl else None
        if purl is None:
            unkeyed.append(
                UnkeyedComponent(
                    name=component.name,
                    version=component.version,
                    kind=component.kind,
                    raw_purl=component.purl,
                )
            )
        elif purl in keyed:
            seen = keyed[purl]
            keyed[purl] = Component(purl, seen.name, seen.version, seen.occurrences + 1)
        else:
            keyed[purl] = Component(purl, component.name, component.version, 1)
    return _BucketedSide(
        keyed=keyed,
        unkeyed=tuple(unkeyed),
        dropped_root=(bom.root,) if bom.root else (),
    )


def _only(keyed: dict[Purl, Component], shared_purls: set[Purl]) -> tuple[Component, ...]:
    return tuple(keyed[purl] for purl in sorted(keyed.keys() - shared_purls, key=str))


def _versions_by_package(
    components: tuple[Component, ...],
) -> dict[PackageId, tuple[str | None, ...]]:
    grouped: dict[PackageId, list[str | None]] = {}
    for component in components:
        grouped.setdefault(component.purl.package, []).append(component.purl.version)
    return {package: tuple(sorted(versions, key=str)) for package, versions in grouped.items()}

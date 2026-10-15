from typing import Any

from depgraph_gap.comparison import find_version_mismatches, summarize_ecosystems
from depgraph_gap.domain import (
    Comparison,
    Component,
    DroppedComponent,
    RunRecord,
    Side,
    UnkeyedComponent,
)


def build_report(record: RunRecord, comparison: Comparison) -> dict[str, Any]:
    ecosystems = summarize_ecosystems(comparison)
    return {
        "repository": str(record.repository),
        "run": {
            "attempts": [
                {"sha_before": attempt.sha_before, "sha_after": attempt.sha_after}
                for attempt in record.attempts
            ],
            "drifted": record.drifted,
            "drift_warning": _drift_warning(record),
            "tool_versions": {
                "gh": record.tool_versions.gh,
                "trivy": record.tool_versions.trivy,
                "cyclonedx": record.tool_versions.cyclonedx,
            },
        },
        "accounting": {side.value: _accounting(comparison, side) for side in Side},
        "ecosystems": [
            {
                "purl_type": summary.purl_type,
                "trivy_only": summary.trivy_only,
                "github_only": summary.github_only,
                "shared": summary.shared,
                "uncovered": summary.uncovered,
            }
            for summary in ecosystems
        ],
        "uncovered_ecosystems": [summary.purl_type for summary in ecosystems if summary.uncovered],
        "version_mismatches": [
            {
                "package": str(mismatch.package),
                "github_versions": list(mismatch.github_versions),
                "trivy_versions": list(mismatch.trivy_versions),
            }
            for mismatch in find_version_mismatches(comparison)
        ],
        "packages": {
            "shared": [
                {
                    "purl": str(entry.purl),
                    "github_occurrences": entry.occurrences.github,
                    "trivy_occurrences": entry.occurrences.trivy,
                }
                for entry in comparison.shared
            ],
            "trivy_only": [_component(entry) for entry in comparison.trivy_only],
            "github_only": [_component(entry) for entry in comparison.github_only],
            "unkeyed": {
                side.value: [_unkeyed(entry) for entry in comparison.unkeyed[side]] for side in Side
            },
            "dropped": {
                side.value: [_dropped(entry) for entry in comparison.dropped[side]]
                for side in Side
            },
        },
    }


def render_summary(report: dict[str, Any]) -> str:
    run = report["run"]
    final = run["attempts"][-1]
    lines = [
        f"repository: {report['repository']}",
        f"commit: {final['sha_before']}",
        f"attempts: {len(run['attempts'])}",
    ]
    if run["drift_warning"]:
        lines.append(f"warning: {run['drift_warning']}")
    lines.append("ecosystems by purl type:")
    for ecosystem in report["ecosystems"]:
        flag = "UNCOVERED " if ecosystem["uncovered"] else ""
        lines.append(
            f"  {flag}{ecosystem['purl_type']}"
            f"  trivy-only={ecosystem['trivy_only']}"
            f"  github-only={ecosystem['github_only']}"
            f"  shared={ecosystem['shared']}"
        )
    uncovered = report["uncovered_ecosystems"]
    lines.append(f"uncovered ecosystems: {', '.join(uncovered) if uncovered else 'none'}")
    lines.append(f"version mismatches: {len(report['version_mismatches'])}")
    lines.append("accounting per side (components in = components placed in a bucket):")
    for side, counts in report["accounting"].items():
        lines.append(
            f"  {side}: {counts['input']} in = {counts['shared']} shared"
            f" + {counts['only']} only + {counts['unkeyed']} unkeyed"
            f" + {sum(counts['dropped'].values())} dropped ({_dropped_breakdown(counts['dropped'])})"
        )
    return "\n".join(lines)


def _drift_warning(record: RunRecord) -> str | None:
    if not record.drifted:
        return None
    attempt = record.final_attempt
    return (
        f"The default branch moved from {attempt.sha_before} to {attempt.sha_after} "
        f"during the last of {len(record.attempts)} attempts. "
        "The two inventories may describe different commits."
    )


def _accounting(comparison: Comparison, side: Side) -> dict[str, Any]:
    accounting = comparison.accounting(side)
    return {
        "input": accounting.input_components,
        "shared": accounting.shared,
        "only": accounting.only,
        "unkeyed": accounting.unkeyed,
        "dropped": {reason.value: count for reason, count in accounting.dropped.items()},
    }


def _component(component: Component) -> dict[str, Any]:
    return {
        "purl": str(component.purl),
        "name": component.name,
        "version": component.version,
        "occurrences": component.occurrences,
    }


def _unkeyed(component: UnkeyedComponent) -> dict[str, Any]:
    return {
        "name": component.name,
        "version": component.version,
        "kind": component.kind,
        "purl": component.raw_purl,
    }


def _dropped(entry: DroppedComponent) -> dict[str, Any]:
    return {
        "reason": entry.reason.value,
        "name": entry.component.name,
        "version": entry.component.version,
        "kind": entry.component.kind,
        "purl": entry.component.purl,
    }


def _dropped_breakdown(dropped: dict[str, int]) -> str:
    return ", ".join(f"{count} {reason.replace('_', ' ')}" for reason, count in dropped.items())

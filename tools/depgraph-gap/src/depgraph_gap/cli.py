import argparse
import json
import os
import re
import sys
import uuid
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path

from depgraph_gap.adapters import ExternalTools
from depgraph_gap.comparison import compare, has_uncovered_ecosystem
from depgraph_gap.domain import Component, Repository, RunRecord, ToolVersions
from depgraph_gap.errors import DepgraphGapError, InvalidRepository, MissingToken
from depgraph_gap.gap_bom import build_gap_bom
from depgraph_gap.pipeline import Sources, collect
from depgraph_gap.report import build_report, render_summary

EXIT_OK = 0
EXIT_UNCOVERED = 1
EXIT_ERROR = 2

OpenSources = Callable[[Mapping[str, str]], tuple[Sources, ToolVersions]]

_REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$")


def main(argv: Sequence[str] | None = None) -> int:
    return run(sys.argv[1:] if argv is None else argv, os.environ, open_external_tools)


def run(argv: Sequence[str], environ: Mapping[str, str], open_sources: OpenSources) -> int:
    arguments = _parse_arguments(argv)
    try:
        repository = parse_repository(arguments.repository)
        if not environ.get("GITHUB_TOKEN"):
            raise MissingToken(
                "GITHUB_TOKEN is not set. Export a token that can read the repository."
            )
        sources, tool_versions = open_sources(environ)
        collected = collect(repository, sources)
        record = RunRecord(repository, collected.attempts, tool_versions)
        comparison = compare(collected.github, collected.trivy, repository)
        report = build_report(record, comparison)
        if arguments.emit_gap_bom:
            _write_gap_bom(arguments.emit_gap_bom, record, comparison.trivy_only)
        print(json.dumps(report, indent=2))
        print(render_summary(report), file=sys.stderr)
        if arguments.fail_on_diff and has_uncovered_ecosystem(comparison):
            return EXIT_UNCOVERED
        return EXIT_OK
    except (DepgraphGapError, OSError) as error:
        print(f"depgraph-gap: error: {error}", file=sys.stderr)
        return EXIT_ERROR


def open_external_tools(environ: Mapping[str, str]) -> tuple[Sources, ToolVersions]:
    tools = ExternalTools(env=environ)
    return tools, tools.check()


def parse_repository(text: str) -> Repository:
    if not _REPOSITORY_PATTERN.match(text):
        raise InvalidRepository(f"expected owner/repo on github.com, got {text!r}")
    owner, name = text.split("/")
    return Repository(owner=owner, name=name)


def _parse_arguments(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="depgraph-gap",
        description="Compare the GitHub dependency graph with Trivy for one repository.",
        epilog="Prints the JSON report on stdout and a summary on stderr. "
        "Exit codes: 0 success, 1 uncovered ecosystem found with --fail-on-diff, 2 error.",
    )
    parser.add_argument("repository", help="repository as owner/repo on github.com")
    parser.add_argument(
        "--emit-gap-bom",
        type=Path,
        metavar="PATH",
        help="write a CycloneDX BOM of the components that only Trivy found",
    )
    parser.add_argument(
        "--fail-on-diff",
        action="store_true",
        help="exit 1 when at least one ecosystem is uncovered (Trivy has counted components "
        "of a purl type and GitHub has none, the Go standard library does not count)",
    )
    return parser.parse_args(argv)


def _write_gap_bom(path: Path, record: RunRecord, trivy_only: tuple[Component, ...]) -> None:
    document = build_gap_bom(
        repository=record.repository,
        sha=record.final_attempt.sha_before,
        components=trivy_only,
        timestamp=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        serial_number=str(uuid.uuid4()),
    )
    path.write_text(json.dumps(document, indent=2) + "\n")

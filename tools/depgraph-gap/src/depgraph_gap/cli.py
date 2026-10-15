import argparse
import json
import os
import re
import sys
from collections.abc import Callable, Mapping, Sequence

from depgraph_gap.adapters import ExternalTools
from depgraph_gap.comparison import compare
from depgraph_gap.domain import Comparison, Repository, Side, ToolVersions
from depgraph_gap.errors import DepgraphGapError, InvalidRepository, MissingToken
from depgraph_gap.pipeline import Sources, collect

EXIT_OK = 0
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
            raise MissingToken("GITHUB_TOKEN is not set. Export a token that can read the repository.")
        sources, _tool_versions = open_sources(environ)
        collected = collect(repository, sources)
        comparison = compare(collected.github, collected.trivy)
        print(json.dumps({"accounting": _accounting(comparison)}, indent=2))
        return EXIT_OK
    except DepgraphGapError as error:
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
    )
    parser.add_argument("repository", help="repository as owner/repo on github.com")
    return parser.parse_args(argv)


def _accounting(comparison: Comparison) -> dict[str, dict[str, int]]:
    return {
        side.value: {
            "input": comparison.accounting(side).input_components,
            "shared": comparison.accounting(side).shared,
            "only": comparison.accounting(side).only,
            "unkeyed": comparison.accounting(side).unkeyed,
            "dropped_root": comparison.accounting(side).dropped_root,
        }
        for side in Side
    }

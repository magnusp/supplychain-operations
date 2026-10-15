import json
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest

from depgraph_gap.adapters import ExternalTools
from depgraph_gap.domain import Repository
from depgraph_gap.errors import ConversionLoss, DependencyGraphDisabled, MissingTool, ToolFailed

REPOSITORY = Repository(owner="acme", name="widget")
SBOM_PATH = "repos/acme/widget/dependency-graph/sbom"
TOKEN_ENV = {"PATH": "/usr/bin", "GITHUB_TOKEN": "secret"}

SPDX_PACKAGES = [{"name": "left-pad"}, {"name": "com.github.acme/widget"}]
CYCLONEDX_COMPONENTS = [
    {"type": "library", "name": "left-pad", "version": "1.0.0", "purl": "pkg:npm/left-pad@1.0.0"},
    {"type": "library", "name": "com.github.acme/widget", "purl": "pkg:github/acme/widget@main"},
]


def completed(args: Sequence[str], stdout: str = "", stderr: str = "", code: int = 0):
    return subprocess.CompletedProcess(list(args), code, stdout, stderr)


class FakeBinaries:
    def __init__(self, cyclonedx_components=CYCLONEDX_COMPONENTS, sbom_result=None) -> None:
        self.cyclonedx_components = cyclonedx_components
        self.sbom_result = sbom_result
        self.calls: list[tuple[list[str], Mapping[str, str]]] = []

    def __call__(self, args: Sequence[str], env: Mapping[str, str]):
        self.calls.append((list(args), env))
        match args[0], args[1:]:
            case "gh", ["api", path] if path == SBOM_PATH:
                return self.sbom_result or completed(
                    args, json.dumps({"sbom": {"packages": SPDX_PACKAGES}})
                )
            case "gh", ["api", path, "--jq", ".sha"]:
                return completed(args, "abc123\n")
            case "cyclonedx", ["convert", *options]:
                target = Path(options[options.index("--output-file") + 1])
                target.write_text(
                    json.dumps({"bomFormat": "CycloneDX", "components": self.cyclonedx_components})
                )
                return completed(args)
            case "trivy", ["repo", *options]:
                target = Path(options[options.index("--output") + 1])
                target.write_text(
                    json.dumps(
                        {
                            "bomFormat": "CycloneDX",
                            "metadata": {"component": {"type": "application", "name": "repo"}},
                            "components": [{"type": "library", "name": "x", "purl": "pkg:npm/x@1"}],
                        }
                    )
                )
                return completed(args)
        raise AssertionError(f"unexpected call {args}")


def test_resolves_the_head_sha_through_gh() -> None:
    binaries = FakeBinaries()

    assert ExternalTools(env=TOKEN_ENV, run=binaries).head_sha(REPOSITORY) == "abc123"
    assert binaries.calls[0][0] == ["gh", "api", "repos/acme/widget/commits/HEAD", "--jq", ".sha"]


def test_converts_the_github_sbom_and_splits_off_the_repository_root() -> None:
    bom = ExternalTools(env=TOKEN_ENV, run=FakeBinaries()).github_bom(REPOSITORY)

    assert [c.purl for c in bom.components] == ["pkg:npm/left-pad@1.0.0"]
    assert bom.root.purl == "pkg:github/acme/widget@main"


def test_a_404_from_the_dependency_graph_says_the_graph_is_probably_disabled() -> None:
    not_found = completed([], stderr="gh: Not Found (HTTP 404)", code=1)
    tools = ExternalTools(env=TOKEN_ENV, run=FakeBinaries(sbom_result=not_found))

    with pytest.raises(DependencyGraphDisabled, match="dependency graph is probably disabled"):
        tools.github_bom(REPOSITORY)


def test_another_gh_failure_is_reported_with_its_stderr() -> None:
    forbidden = completed([], stderr="gh: Forbidden (HTTP 403)", code=1)
    tools = ExternalTools(env=TOKEN_ENV, run=FakeBinaries(sbom_result=forbidden))

    with pytest.raises(ToolFailed, match=r"HTTP 403"):
        tools.github_bom(REPOSITORY)


def test_stops_when_the_conversion_loses_a_component() -> None:
    tools = ExternalTools(
        env=TOKEN_ENV, run=FakeBinaries(cyclonedx_components=CYCLONEDX_COMPONENTS[:1])
    )

    with pytest.raises(ConversionLoss, match="2 SPDX packages, 1 CycloneDX components"):
        tools.github_bom(REPOSITORY)


def test_scans_the_pinned_commit_with_trivy_and_passes_the_token_through() -> None:
    binaries = FakeBinaries()

    bom = ExternalTools(env=TOKEN_ENV, run=binaries).trivy_bom(REPOSITORY, "abc123")

    args, env = binaries.calls[0]
    assert args[:5] == ["trivy", "repo", "https://github.com/acme/widget", "--commit", "abc123"]
    assert env["GITHUB_TOKEN"] == "secret"
    assert [c.purl for c in bom.components] == ["pkg:npm/x@1"]
    assert bom.root.name == "repo"


def test_names_the_missing_binary_at_start_up(tmp_path: Path) -> None:
    tools = ExternalTools(env={"PATH": str(tmp_path)}, run=FakeBinaries())

    with pytest.raises(MissingTool, match="`gh` is not on your PATH"):
        tools.check()

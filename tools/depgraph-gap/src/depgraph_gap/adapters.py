import json
import shutil
import subprocess
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from depgraph_gap.bom import parse_cyclonedx
from depgraph_gap.domain import Bom, Repository, ToolVersions
from depgraph_gap.errors import (
    ConversionLoss,
    DependencyGraphDisabled,
    MalformedBom,
    MissingTool,
    ToolFailed,
)

TRIVY_FLAGS = (
    "--format",
    "cyclonedx",
    "--detection-priority",
    "comprehensive",
    "--include-dev-deps",
    "--scanners",
    "vuln",
    "--quiet",
)

Runner = Callable[[Sequence[str], Mapping[str, str]], subprocess.CompletedProcess[str]]

_INSTALL_HINTS = {
    "gh": "Install it from https://cli.github.com.",
    "trivy": "Run `mise install` in the repository root.",
    "cyclonedx": "Run `mise install` in the repository root.",
}


def run_subprocess(args: Sequence[str], env: Mapping[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, env=dict(env), capture_output=True, text=True, check=False)


@dataclass(frozen=True, slots=True)
class ExternalTools:
    env: Mapping[str, str]
    run: Runner = run_subprocess

    def check(self) -> ToolVersions:
        for name, hint in _INSTALL_HINTS.items():
            if shutil.which(name, path=self.env.get("PATH")) is None:
                raise MissingTool(f"`{name}` is not on your PATH. {hint}")
        return ToolVersions(
            gh=_first_line(self._succeed(["gh", "--version"])),
            trivy=_first_line(self._succeed(["trivy", "--version"])),
            cyclonedx=_first_line(self._succeed(["cyclonedx", "--version"])),
        )

    def head_sha(self, repository: Repository) -> str:
        args = ["gh", "api", f"repos/{repository}/commits/HEAD", "--jq", ".sha"]
        return self._succeed(args).strip()

    def github_bom(self, repository: Repository) -> Bom:
        spdx = self._fetch_spdx(repository)
        spdx_package_count = len(spdx.get("packages") or [])
        with tempfile.TemporaryDirectory() as directory:
            spdx_path = Path(directory, "github.spdx.json")
            cyclonedx_path = Path(directory, "github.cdx.json")
            spdx_path.write_text(json.dumps(spdx))
            self._succeed(
                [
                    "cyclonedx",
                    "convert",
                    "--input-file",
                    str(spdx_path),
                    "--input-format",
                    "spdxjson",
                    "--output-file",
                    str(cyclonedx_path),
                    "--output-format",
                    "json",
                ]
            )
            bom = parse_cyclonedx(_read_json(cyclonedx_path), repository)
        if bom.component_count != spdx_package_count:
            raise ConversionLoss(
                "SPDX to CycloneDX conversion changed the component count: "
                f"{spdx_package_count} SPDX packages, {bom.component_count} CycloneDX components"
            )
        return bom

    def trivy_bom(self, repository: Repository, sha: str) -> Bom:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory, "trivy.cdx.json")
            self._succeed(
                [
                    "trivy",
                    "repo",
                    repository.url,
                    "--commit",
                    sha,
                    *TRIVY_FLAGS,
                    "--output",
                    str(output),
                ]
            )
            return parse_cyclonedx(_read_json(output), repository)

    def _fetch_spdx(self, repository: Repository) -> dict[str, Any]:
        args = ["gh", "api", f"repos/{repository}/dependency-graph/sbom"]
        result = self.run(args, self.env)
        if result.returncode != 0 and "HTTP 404" in result.stderr:
            raise DependencyGraphDisabled(
                f"GitHub returned 404 for the SBOM of {repository}. "
                "The dependency graph is probably disabled for this repository."
            )
        _require_success(args, result)
        try:
            return json.loads(result.stdout)["sbom"]
        except (json.JSONDecodeError, KeyError) as error:
            raise MalformedBom(f"GitHub SBOM response has no `sbom` object: {error}") from error

    def _succeed(self, args: Sequence[str]) -> str:
        result = self.run(args, self.env)
        _require_success(args, result)
        return result.stdout


def _first_line(text: str) -> str:
    return text.strip().partition("\n")[0]


def _require_success(args: Sequence[str], result: subprocess.CompletedProcess[str]) -> None:
    if result.returncode != 0:
        raise ToolFailed(
            f"`{' '.join(args[:3])}` exited with {result.returncode}: {result.stderr.strip()}"
        )


def _read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise MalformedBom(f"cannot read {path.name}: {error}") from error

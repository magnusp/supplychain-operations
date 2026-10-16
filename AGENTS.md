# AGENTS.md

This repository holds small, independent command-line tools in `tools/<name>/`.
Read `README.md` for the layout and `docs/adr/` for the reasons behind it.

## Tool independence

- Keep each tool self-contained. Copy a small function into the second tool instead of sharing it ([ADR 0001](docs/adr/0001-monorepo-layout.md)).
- Run a tool's commands from its directory, for example `cd tools/depgraph-gap && uv run pytest`.
- Run live tests only on request. They call the real `gh`, `trivy`, and `cyclonedx` against github.com and carry the `live` marker.

## Commits and releases

- Write Conventional Commit PR titles with the tool name as scope, for example `fix(depgraph-gap): ...`. The repository squashes PRs, so the title becomes the commit.
- Leave `version` in `pyproject.toml`, the project entry in `uv.lock`, `.release-please-manifest.json`, and `CHANGELOG.md` to release-please.
- To add a tool, follow the "Add a tool" steps in [ADR 0003](docs/adr/0003-per-tool-releases-and-images.md).

## Pinned versions

- Pin every GitHub Action to a commit SHA with the version in a trailing comment. Renovate updates both.
- Pin external binaries in `mise.toml` and in the tool's `Dockerfile`. Keep the two in step.
- Mark a `Dockerfile` `ARG` version with a `# renovate:` comment so Renovate tracks it.
- When you change `GH_VERSION` or `CYCLONEDX_VERSION`, update the `*_SHA256_*` arguments next to it. The build fails on a mismatch.

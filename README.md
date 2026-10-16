# supplychain-operations

This repository holds small command-line tools for supply chain operations.
Each tool answers one question about the dependencies of a GitHub repository.

## Layout

- `tools/<name>/` holds one tool.
  - Each tool has its own `pyproject.toml`, `README.md`, `src/`, and `tests/`.
  - A tool does not import code from another tool.
- `docs/adr/` holds the architecture decision records.
- `mise.toml` pins the Python version and the external binaries that the tools call.
- `.github/workflows/` holds the continuous integration workflow.
- `release-please-config.json` and `.release-please-manifest.json` configure per-tool releases.
- `renovate.json` configures Renovate to update the pinned versions.

## Set up your machine

1. Install [mise](https://mise.jdx.dev/).
2. Run `mise install` in the repository root.
3. Set `GITHUB_TOKEN` in your environment.

You need the `gh` command-line tool on your `PATH`.
The `mise.toml` file does not pin `gh`.

## Tools

- [`depgraph-gap`](tools/depgraph-gap/README.md) compares the GitHub dependency graph with the packages that Trivy finds.
  It shows the ecosystems that Dependabot and GitHub Advanced Security do not cover.

## Releases

Each tool has its own version and tags, such as `depgraph-gap-v0.2.0`.
Use [Conventional Commits](https://www.conventionalcommits.org/) for pull request titles.
release-please opens a release pull request for each tool.
When you merge it, the `release` workflow publishes the image to `ghcr.io/magnusp/<tool>`.

To run a released tool, run `docker run --rm -e GITHUB_TOKEN ghcr.io/magnusp/depgraph-gap owner/repo`.

## Decisions

- [ADR 0001, monorepo layout](docs/adr/0001-monorepo-layout.md)
- [ADR 0002, purl-keyed inventory comparison](docs/adr/0002-purl-keyed-inventory-comparison.md)
- [ADR 0003, per-tool releases and Docker images](docs/adr/0003-per-tool-releases-and-images.md)

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

## Decisions

- [ADR 0001, monorepo layout](docs/adr/0001-monorepo-layout.md)
- [ADR 0002, purl-keyed inventory comparison](docs/adr/0002-purl-keyed-inventory-comparison.md)

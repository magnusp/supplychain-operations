# ADR 0001: Monorepo layout

- **Status:** Accepted
- **Date:** 2026-10-15

## Context

This repository will hold several small tools.
Each tool has one job and its own tests.
The tools run from a terminal or from continuous integration.

The tools call external binaries such as `gh`, `trivy`, and `cyclonedx`.
Every contributor needs the same versions of these binaries.

## Decision

Each tool lives in `tools/<name>/`.
The directory holds a `pyproject.toml`, a `README.md`, a `src/` directory, and a `tests/` directory.

The tools share no code.
The repository has no shared library and no workspace tooling.
If two tools need the same function, each tool keeps its own copy.

The root `mise.toml` pins `python`, `uv`, `trivy`, and `cyclonedx`.
The repository defines no `mise` tasks.
You run a tool with `uv run` from the tool directory.

One GitHub Actions workflow runs `pytest` for each tool.
A path filter starts the job for a tool only when that tool changes.

Renovate updates the pinned versions.
The repository does not use Dependabot.

## Consequences

- A tool is deletable. You remove its directory and its job.
- A change in one tool cannot break another tool.
- Two tools can hold a small duplicate of the same function.
- Each tool has its own `uv.lock`, so Renovate opens one update per tool.
- A new tool needs a new job and a new path filter in the workflow.

## Alternatives considered

- **A uv workspace.** One lock file would cover all tools. The tools would then have to agree on every dependency version. We rejected it because the tools have no shared dependencies today.
- **A shared library.** It removes duplicate code. It also couples the tools through one release cycle. We rejected it until a real duplicate exists.
- **`mise` tasks.** They hide the real command. A reader cannot see what `uv run pytest` does. We rejected them.

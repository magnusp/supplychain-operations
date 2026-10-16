# ADR 0003: Per-tool releases and Docker images

- **Status:** Accepted
- **Date:** 2026-10-16

## Context

This repository holds several tools.
Each tool has its own `pyproject.toml` and its own lock file.
New tools will arrive.
A new tool must not need changes to another tool.

## Decision

Each tool has its own version.
A release tag has the form `<tool>-v<version>`, for example `depgraph-gap-v0.2.0`.

[release-please](https://github.com/googleapis/release-please) in manifest mode opens one release pull request for each tool.
It reads Conventional Commits and bumps `pyproject.toml` and `uv.lock`.
It also writes the changelog and creates the tag.

Each tool has a `Dockerfile` in its directory.
The build context is the tool directory.
The image holds only the binaries that the tool needs.

When release-please releases a tool, the `release` workflow builds the image for that tool.
It publishes the image to `ghcr.io/<owner>/<tool>` for `linux/amd64` and `linux/arm64`.
The image has two tags: the version and `latest`.

A separate workflow checks that each pull request title follows Conventional Commits.
The repository squashes pull requests, so the title becomes the commit message.

## Add a tool

1. Add the tool to `packages` in `release-please-config.json`.
2. Add the tool to `.release-please-manifest.json`.
3. Add a `Dockerfile` and a `.dockerignore` to the tool directory.
4. Add a job and a path filter for the tool to `.github/workflows/test.yml`.

The `release` workflow needs no change.
It builds an image for every path that release-please releases.

## Consequences

- Tools release independently, which matches [ADR 0001](0001-monorepo-layout.md).
- A pull request that release-please opens does not start the `test` workflow, because it uses `GITHUB_TOKEN`.
- You must enable **Allow GitHub Actions to create and approve pull requests** in the repository settings.
- The `Dockerfile` pins `gh` and `cyclonedx` with a `renovate:` comment, so Renovate updates them.

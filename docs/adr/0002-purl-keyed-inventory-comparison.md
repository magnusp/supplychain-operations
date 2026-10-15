# ADR 0002: Purl-keyed inventory comparison

- **Status:** Accepted
- **Date:** 2026-10-15

## Context

The `depgraph-gap` tool compares two inventories of one repository at one commit.
The first inventory is the GitHub dependency graph, exported as an SPDX SBOM.
The second inventory is the output of Trivy.

A difference between the inventories can mean three things.
GitHub does not support an ecosystem.
The dependency graph is incomplete for a supported ecosystem.
Trivy reports a package that does not exist.

The tool exists to find the first case.
A comparison that silently drops components hides that case.

## Decision

The tool keys every component by its normalized package URL (purl).
Normalization decodes percent-encoding, lowercases the type, and lowercases the name for case-insensitive ecosystems.
Normalization drops qualifiers and subpaths.
The tool keeps one entry for each purl and counts the occurrences.

The tool puts every input component into exactly one bucket.

- **Shared:** both sides have the purl.
- **Trivy-only:** only Trivy has the purl.
- **GitHub-only:** only GitHub has the purl.
- **Unkeyed:** the component has no purl, or the purl does not parse. The tool lists these per side and never compares them.
- **Dropped root:** the component that describes the repository itself. Each side has at most one.

The tool drops no other component.

The lossless invariant is a hard rule.
For each side, the bucket counts must add up to the input component count.
If they do not, the tool stops with an error.
The tool also compares the component count before and after the SPDX to CycloneDX conversion.
If the count changes, the tool stops with an error.

A version mismatch is a package that both sides list with different versions.
The tool reports a version mismatch separately.
A version mismatch never makes an ecosystem uncovered.

An ecosystem is uncovered when Trivy has components of that purl type and GitHub has none.

The tool uses the `cyclonedx` binary only to convert SPDX to CycloneDX.
The comparison runs in Python.
The prototype evidence is in the "Why the diff is in Python" section of the tool README.

## Consequences

- Every input component is visible in the output. A reader can audit the counts.
- A coverage claim rests on purl types, so a purl that Trivy or GitHub builds differently can look like a gap. The shared bucket exposes these cases.
- Dropping qualifiers can merge two distinct packages into one entry. The occurrence count shows the merge.
- The tool trusts the purl that each source emits. It does not look up the package in a registry.
- The tool compares one commit. If the default branch moves during a run, the tool starts the run again.

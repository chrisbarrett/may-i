---
audience: contributor
bucket: contributor-internals
---
# release-verification Specification

## Purpose

Contributor-only. Defines the release-time verification gate: a single
fail-before-mutate driver (`scripts/release.sh`) that runs the heavy
verification suite (fmt-check, clippy, instrumented test run with coverage
gate, time-boxed fuzz pass, nix build) before any mutation to the working
tree, Git history, or remote. Covers preconditions enforced by the driver,
the fuzz-target invocation, the slim release CI workflow, and the
non-blocking nightly workflow that surfaces slow-burn regressions between
releases. Companion to `testing-strategy`, which defines the four
verification tiers (pre-commit / pre-push / release / nightly) at a higher
level.

## Requirements

### Requirement: Release driver script is the documented release path

Cutting a release SHALL be performed by `scripts/release.sh`, invoked
with the target version string. The manual sequence of editing
`Cargo.toml`, committing, tagging, and pushing SHALL NOT be the
documented or expected path.

#### Scenario: Contributor cuts a release

- **WHEN** a contributor cuts a new release
- **THEN** they SHALL invoke `scripts/release.sh <version>` rather
  than performing the bump-commit-tag sequence by hand

#### Scenario: Documentation references the script

- **WHEN** `CLAUDE.md` describes the release tagging process
- **THEN** it SHALL reference `scripts/release.sh` as the entry point

### Requirement: Verification precedes mutation

The release driver SHALL run the full verification suite (formatting
check, clippy, instrumented test run with coverage gate, time-boxed
fuzz pass, nix build) before performing any mutation to the working
tree, Git history, or remote.

#### Scenario: Verification step fails

- **WHEN** any verification step exits non-zero
- **THEN** the driver SHALL exit before bumping `Cargo.toml`, leaving
  the working tree, index, and Git history unchanged

#### Scenario: Verification passes

- **WHEN** every verification step exits zero
- **THEN** the driver SHALL proceed to the bump-commit-tag-push
  sequence in that order

### Requirement: Release driver enforces preconditions

The driver SHALL refuse to start when the working tree is dirty, the
current branch is not `main`, or the local `main` is not in sync with
`origin/main`.

#### Scenario: Dirty working tree

- **WHEN** `scripts/release.sh` runs with uncommitted changes present
- **THEN** the driver SHALL exit non-zero with a message identifying
  the dirty tree

#### Scenario: Branch is not main

- **WHEN** `scripts/release.sh` runs from a branch other than `main`
- **THEN** the driver SHALL exit non-zero with a message identifying
  the wrong branch

#### Scenario: Local main behind origin

- **WHEN** `scripts/release.sh` runs and local `main` does not match
  `origin/main`
- **THEN** the driver SHALL exit non-zero with a message instructing
  the contributor to sync with origin first

### Requirement: Release verification exercises the fuzz target

The release verification suite SHALL run the `fuzz_evaluator` target
for a bounded time (`-max_total_time=60`) so the fuzz corpus is
exercised on every release.

#### Scenario: Fuzz target executes during release

- **WHEN** the release driver reaches the fuzz step
- **THEN** it SHALL invoke `cargo +nightly fuzz run fuzz_evaluator --
  -max_total_time=60` and require exit zero

#### Scenario: Required tooling missing

- **WHEN** the release driver runs without `cargo-fuzz` or a nightly
  toolchain installed
- **THEN** it SHALL fail with a clear error and an install hint
  before any mutation occurs

### Requirement: Release artefact workflow does not re-run tests

The `release.yml` GitHub Actions workflow SHALL build and package the
binary for each target platform on `v*` tag push, and MUST NOT invoke
`cargo test` in any form. Verification responsibility lives entirely
in `scripts/release.sh`.

#### Scenario: Release workflow runs after tag push

- **WHEN** a `v*` tag is pushed and `release.yml` executes
- **THEN** each per-target job SHALL build, package, and upload
  artefacts without invoking a test step

### Requirement: Nightly workflow exercises slow verification non-blockingly

A scheduled GitHub Actions workflow SHALL run `cargo tarpaulin` and a
longer fuzz pass (`-max_total_time=600`) against `main` on a nightly
cadence. Failures SHALL NOT block contributor work or PR merges; they
SHALL be surfaced as workflow-run failures visible in the Actions UI.

#### Scenario: Nightly cadence triggers

- **WHEN** the scheduled time elapses
- **THEN** the workflow SHALL run against the latest `main` commit
  and report its result via the standard Actions UI

#### Scenario: Nightly failure does not block

- **WHEN** the nightly workflow fails
- **THEN** open PRs SHALL still be mergeable and unrelated CI checks
  SHALL be unaffected

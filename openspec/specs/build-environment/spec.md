---
audience: contributor
bucket: contributor-internals
---
# build-environment Specification

## Purpose

Contributor-only. Defines the environment every build and test command runs in:
the pinned toolchain and the requirement to enter it, the compilation-caching
policy that separates a contributor's fast inner loop from CI's cold builds, and
the requirement that the agent-facing command surface be documented rather than
rediscovered. Complements `testing-strategy`, which defines *what* each
verification tier runs; this spec defines the environment it runs in.

## Requirements

### Requirement: Build and test commands run in the pinned toolchain

The workspace SHALL build only under the toolchain pinned by
`rust-toolchain.toml`, and the repository SHALL make entering that toolchain the
documented first step for any build, test, lint, or coverage command.

`crates/core` enables an unstable compiler feature, so a stable `rustc` fails the
build immediately with `E0554` rather than degrading. A contributor or agent
whose ambient shell resolves a different toolchain SHALL be able to determine the
correct invocation from `AGENTS.md` alone, without inferring it from the failure.

#### Scenario: Ambient shell resolves the wrong toolchain

- **WHEN** a build is attempted from a shell whose `rustc` is not the pinned
  toolchain
- **THEN** the failure is `E0554` on the unstable feature attribute
- **AND** `AGENTS.md` SHALL name the command that enters the pinned toolchain, so
  the reader can recover without diagnosing the error

#### Scenario: Documented commands are runnable as written

- **WHEN** a contributor copies any build, test, lint, or coverage command from
  `AGENTS.md` into a shell that has not entered the dev shell
- **THEN** the command as written SHALL either enter the pinned toolchain itself
  or appear under an instruction to enter it first

### Requirement: Local builds are incremental; CI builds are not

Local builds SHALL use incremental compilation. CI builds SHALL NOT.

The repository SHALL carry its own Cargo build configuration establishing the
local policy, so a contributor's global configuration cannot silently disable
incremental compilation for this workspace. That configuration SHALL also clear
any inherited `rustc-wrapper`: a caching wrapper that rejects incremental
invocations would otherwise fail the build outright rather than fall back.

CI SHALL override the local policy through the environment, because its cache is
cold on every run and incremental state cannot survive between jobs.

#### Scenario: Contributor's global config disables incremental

- **WHEN** a contributor's user-level Cargo configuration sets
  `incremental = false`
- **AND** a build is run from within this workspace
- **THEN** the repository-level configuration SHALL take precedence and the build
  SHALL be incremental

#### Scenario: Inherited rustc wrapper rejects incremental invocations

- **WHEN** a contributor's user-level Cargo configuration sets a `rustc-wrapper`
  that refuses `-C incremental`
- **AND** a build is run from within this workspace
- **THEN** the repository-level configuration SHALL clear the wrapper, and the
  build SHALL succeed rather than fail in the wrapper

#### Scenario: CI job builds without incremental state

- **WHEN** any GitHub Actions workflow in this repository runs a `cargo` build,
  test, or clippy step
- **THEN** incremental compilation SHALL be disabled for that step via the
  environment, overriding the repository configuration

### Requirement: AGENTS.md names the command for each verification tier

`AGENTS.md` SHALL name the concrete command a contributor runs for each
verification tier defined in `testing-strategy`, and SHALL name the
affected-crate command used for scoped runs.

An agent that reads only `AGENTS.md` is the target reader: the file is the
entry point, and a tier whose command appears only in `prek.toml` or a CI
workflow is not discoverable from it.

#### Scenario: Every tier has a named command

- **WHEN** `AGENTS.md` is read
- **THEN** it SHALL name a command for the pre-commit, pre-push, release, and
  nightly tiers

#### Scenario: Scoped runs are discoverable

- **WHEN** a contributor wants to verify only the crates their edit affects
- **THEN** `AGENTS.md` SHALL name the affected-crate command, not only the
  full-workspace one

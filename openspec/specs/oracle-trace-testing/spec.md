---
audience: contributor
bucket: testing
---
# oracle-trace-testing Specification

## Purpose

Contributor-only. Snapshot-based integration tests that load a frozen V1 fixture (via transparent migration), evaluate canonical cases through the full eval pipeline, and compare both ANSI-stripped and raw-coloured trace output byte-for-byte against checked-in oracle snapshots, with config-path normalisation and pinned 80-column geometry.

## Requirements

### Requirement: Integration test loads V1 fixture and evaluates commands

The test harness SHALL load `tests/fixtures/v1/config.lisp` (V1 syntax) via
`may_i_config::load`, which transparently migrates it. For each case in
`tests/fixtures/v1/cases.toml`, it SHALL evaluate the command with the specified
facts using the full eval pipeline (TracingFold + trace rendering).

#### Scenario: Config loads via transparent migration
- **WHEN** the test calls `may_i_config::load` with the V1 fixture path
- **THEN** the config loads successfully with transparent V1-to-V2 migration

#### Scenario: Each test case evaluates without error
- **WHEN** a test case specifies command `"git status"` with no facts
- **THEN** evaluation completes and produces a trace and result

#### Scenario: Test case with runtime facts
- **WHEN** a test case specifies facts `[":opencode/agent=build"]`
- **THEN** those facts are parsed and passed to the eval context

### Requirement: Stripped output matches oracle snapshots

For each test case, the trace output with ANSI codes stripped SHALL match the
corresponding `tests/snapshots/oracle_v1/{name}.txt` file byte-for-byte, after
config path normalisation.

#### Scenario: Structural match for simple allow
- **WHEN** evaluating `"cat foo"` against the V1 fixture
- **THEN** the stripped output matches `cat_file.txt`

#### Scenario: Structural match for multi-rule trace
- **WHEN** evaluating `"git status"` against the V1 fixture (no facts)
- **THEN** the stripped output matches `git_status.txt`, which includes 4 rule
  traces (lines 43, 47, 52, 60) with non-matching positional annotations

#### Scenario: Structural match for context-dependent rule
- **WHEN** evaluating `"git checkout -- main.ts"` with fact `:opencode/agent=plan`
- **THEN** the stripped output matches `git_checkout_file_plan.txt`, showing the
  plan-mode rule matching with positional annotations

#### Scenario: Structural match for default ask
- **WHEN** evaluating `"unknown-cmd arg"` against the V1 fixture
- **THEN** the stripped output matches `unknown_cmd.txt`, showing "No matching rule"

### Requirement: Raw ANSI output matches oracle snapshots

For each test case, the trace output with ANSI colour codes SHALL match the
corresponding `tests/snapshots/oracle_v1/{name}.raw` file byte-for-byte, after
config path normalisation.

#### Scenario: Colour codes for deny decision
- **WHEN** evaluating `"rm -rf /"` against the V1 fixture
- **THEN** the raw output matches `rm_rf_root.raw`, including red colouring on
  `:deny` and the result command text

#### Scenario: Colour codes for allow decision
- **WHEN** evaluating `"git status"` against the V1 fixture
- **THEN** the raw output matches `git_status.raw`, including green colouring on
  `:allow` and green bold on "yes" annotations

### Requirement: Config path is normalised before comparison

The output line `config: <path>` SHALL be replaced with a stable placeholder
before comparing against snapshots. The same normalisation SHALL be applied to
the oracle snapshot content.

#### Scenario: Path differs between machines
- **WHEN** the dev build produces `config: /tmp/test123/config.lisp`
- **AND** the oracle snapshot contains `config: ~/src/.../config.lisp`
- **THEN** both are normalised to `config: <config-path>` before comparison

### Requirement: Terminal width pinned at 80 columns

The test SHALL set `COLUMNS=80` before rendering so the two-column layout is
deterministic and matches the oracle capture environment.

#### Scenario: Deterministic layout
- **WHEN** the test renders trace output
- **THEN** `COLUMNS` is set to `"80"` and layout uses 80-column geometry

### Requirement: Colour output forced in test environment

The test SHALL force colour output (via `colored::control::set_override(true)`)
to match the oracle capture which used `CLICOLOR_FORCE=1`.

#### Scenario: Colour enabled despite non-TTY
- **WHEN** the test captures output to a string buffer
- **THEN** ANSI escape sequences are present in the raw output

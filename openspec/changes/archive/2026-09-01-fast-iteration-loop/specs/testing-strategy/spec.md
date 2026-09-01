## MODIFIED Requirements

### Requirement: Verification tiers are explicit

The repository SHALL define four verification tiers, each with a
specific cadence and scope:

- **pre-commit**: fast, scoped to affected crates. Includes `cargo
  fmt --check`, affected `cargo clippy`, affected `cargo test`, and
  OpenSpec validation. No separate `cargo build` step: clippy runs
  the same compiler checks, and test forces full codegen.
- **pre-push**: full-workspace, no instrumentation. Includes
  `cargo clippy --workspace --all-targets -- -D warnings` and
  `cargo test --workspace`. Oracle tests run at their reduced default
  case count at this tier.
- **release**: instrumentation and fuzz on top of CI. Runs only via
  `scripts/release.sh`. Includes a CI-green gate on HEAD (which
  proves fmt, clippy, and tests passed in CI for the same commit),
  `cargo tarpaulin` (with `run-types = ["Lib", "Tests", "Doctests"]`),
  `cargo +nightly fuzz run fuzz_evaluator -- -max_total_time=60`, and
  `nix build`.
- **nightly**: slow, non-blocking. Runs `cargo tarpaulin`, a longer
  fuzz pass (`-max_total_time=600`), the full oracle sweep at its
  elevated case count, and `nix flake check` (package build, clippy,
  fmt, nextest, cargo-audit against a freshly updated advisory
  database) against `main` on a scheduled GitHub Actions workflow.

#### Scenario: Coverage gate runs at release tier only

- **WHEN** `cargo tarpaulin` is configured as a verification step
- **THEN** it SHALL appear in the release tier (`scripts/release.sh`)
  and the nightly tier, but NOT in the pre-push tier

#### Scenario: Fuzz pass runs at release and nightly tiers

- **WHEN** the fuzz target is invoked in CI or hooks
- **THEN** it SHALL only appear in the release tier (60s budget) and
  the nightly tier (600s budget)

#### Scenario: Tarpaulin run-types cover all test kinds at release tier

- **WHEN** `cargo tarpaulin` runs as part of release verification
- **THEN** its `run-types` configuration SHALL include `Lib`,
  `Tests`, and `Doctests`

#### Scenario: Full oracle sweep runs at nightly tier only

- **WHEN** an oracle test's case count is elevated above its default
- **THEN** the elevated count SHALL be configured in the nightly tier,
  and the pre-commit and pre-push tiers SHALL run the default count

## ADDED Requirements

### Requirement: Oracle test case counts are environment-tunable

A test that spawns an external process once per generated case SHALL take its
case count from the `PROPTEST_CASES` environment variable rather than hardcoding
it, and its compiled-in default SHALL be sized for the pre-push tier.

Hardcoding the count in `proptest_config` overrides the environment variable, so
a contributor cannot reduce it for a fast local run and the nightly tier cannot
raise it. Sizing the default for the nightly sweep instead charges every
pre-push run for coverage only the nightly tier needs.

#### Scenario: Contributor reduces the case count locally

- **WHEN** a contributor sets `PROPTEST_CASES` to a value below the default and
  runs an oracle test
- **THEN** the test SHALL run that many cases

#### Scenario: Nightly tier raises the case count

- **WHEN** the nightly workflow sets `PROPTEST_CASES` above the default
- **THEN** the test SHALL run that many cases

#### Scenario: Default is sized for pre-push

- **WHEN** an oracle test runs with no `PROPTEST_CASES` set
- **THEN** it SHALL run its reduced default count, not the nightly sweep count

### Requirement: External-oracle tests are hermetic

A test that consults an external interpreter as a ground-truth oracle SHALL
invoke it with startup files suppressed, so the contributor's own shell
configuration cannot change what the oracle accepts.

An oracle that sources a contributor's startup files is not a fixed ground
truth: options set there can alter the interpreter's grammar, making the test
pass on one machine and fail on another for reasons unrelated to the code under
test.

#### Scenario: Contributor startup file sets a grammar-affecting option

- **WHEN** a contributor's shell startup file sets an option that changes how the
  interpreter parses input
- **AND** the oracle test runs
- **THEN** the oracle's verdict SHALL be unaffected by that option

### Requirement: Integration test targets are consolidated by theme

Integration test targets in a crate SHALL be grouped by theme rather than one
per scenario file, and the `may-i` crate SHALL define no more than six.

Each integration test target is separately linked and separately monomorphises
the generic chains it pulls in, and that cost is fixed rather than proportional
to the test code in the file: in the state this requirement replaces, a 38-line
target and a 573-line target cost the same to build. A crate that adds a target
per scenario therefore pays its whole dependency graph again for each one.

Adding a scenario SHALL mean adding a test function to an existing themed
target. A new target SHALL be justified by a distinct harness need — a different
process environment, a different fixture set — not by topical separation, which
modules within a target already provide.

#### Scenario: Root crate target count is bounded

- **WHEN** the `tests/` directory of the `may-i` crate is enumerated
- **THEN** it SHALL contain no more than six integration test targets

#### Scenario: New scenario joins an existing target

- **WHEN** a contributor adds an integration test for a new scenario in an
  already-covered theme
- **THEN** the test SHALL be added to the existing themed target rather than as a
  new target

#### Scenario: Consolidation relocates key-bearing test artefacts

- **WHEN** existing integration test files are merged into a themed target
- **AND** the merge changes the lookup key of a checked-in `insta` snapshot or
  `proptest-regressions/` file, because that key derives from the target and
  module path
- **THEN** the affected artefacts SHALL be relocated to their new keys in the
  same change, so no assertion is silently skipped or re-accepted

#### Scenario: Consolidation preserves assertion count

- **WHEN** existing integration test files are merged into a themed target
- **THEN** every test function from the merged files SHALL still be present and
  executed, with no test dropped or left `#[ignore]`d by the merge

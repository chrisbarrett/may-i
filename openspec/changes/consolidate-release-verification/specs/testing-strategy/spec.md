## ADDED Requirements

### Requirement: Verification tiers are explicit

The repository SHALL define four verification tiers, each with a
specific cadence and scope:

- **pre-commit**: fast, scoped to affected crates. Includes `cargo
  fmt --check`, affected `cargo build`, affected `cargo clippy`,
  affected `cargo test`, and OpenSpec validation.
- **pre-push**: full-workspace, no instrumentation. Includes
  `cargo build --workspace`, `cargo clippy --workspace --all-targets
  -- -D warnings`, `cargo test --workspace`, and `nix build`.
- **release**: full-workspace with instrumentation and fuzz. Runs
  only via `scripts/release.sh`. Includes `cargo fmt --check`,
  `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo tarpaulin` (with `run-types = ["Lib", "Tests", "Doctests"]`),
  `cargo +nightly fuzz run fuzz_evaluator -- -max_total_time=60`, and
  `nix build`.
- **nightly**: slow, non-blocking. Runs `cargo tarpaulin` and a
  longer fuzz pass (`-max_total_time=600`) against `main` on a
  scheduled GitHub Actions workflow.

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

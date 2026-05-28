## Why

Heavy verification work currently runs three times per release: once in the
pre-push tarpaulin hook, again in CI on push to main, and a third time per
target in the release workflow. Coverage gating and fuzzing are entangled
with the every-push path, so ordinary pushes pay the cost of release-grade
verification, while the actual release tag-and-bump flow is manual and can
publish an unverified commit if a step is skipped. Consolidating heavy
verification into a single release-time gate lets us detect and correct
failures before any commit, tag, or push mutates state, and keeps everyday
pushes fast.

## What Changes

- Add `scripts/release.sh`: a linear, fail-before-mutate release driver
  that runs the heavy suite (fmt-check, clippy, tarpaulin, time-boxed
  fuzz, nix build) **before** bumping `Cargo.toml`, committing, tagging,
  and pushing.
- Slim pre-push hooks: drop `cargo-test-full` (tarpaulin) so push stays
  fast; keep `cargo-build-full`, `cargo-clippy-full`, `nix-build`.
- Widen `tarpaulin.toml` `run-types` to `["Lib", "Tests", "Doctests"]` so
  the release-time coverage pass also exercises integration and doc
  tests in one build.
- Strip `cargo test --release --workspace` from `release.yml` per-target
  jobs; the release workflow builds and packages only.
- Add a nightly GitHub Actions workflow that runs `cargo tarpaulin` plus
  a longer fuzz pass against `main`, non-blocking, to surface slow-burn
  regressions between releases.
- **BREAKING (process)**: cutting a release SHALL go through
  `scripts/release.sh`. Manual `Cargo.toml` edit + tag is no longer the
  documented path.

## Capabilities

### New Capabilities
- `release-verification`: contributor-facing capability describing the
  verification gate that precedes any release tag, the ordering rules
  (verify before mutate), and the recovery contract on failure.

### Modified Capabilities
- `testing-strategy`: extend with where each tier of verification runs
  (pre-commit / pre-push / release / nightly) and which test types each
  tier covers.

## Impact

- Files: `prek.toml`, `tarpaulin.toml`, `.github/workflows/ci.yml`,
  `.github/workflows/release.yml`, new `scripts/release.sh`, new
  `.github/workflows/nightly.yml`.
- Contributor docs: `CLAUDE.md` release tagging note updated to
  reference `scripts/release.sh` instead of manual bump.
- No runtime/library code touched; behaviour change is entirely in the
  development and release pipeline.

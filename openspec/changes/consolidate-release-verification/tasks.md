## 1. Release driver script

- [ ] 1.1 Create `scripts/release.sh` with `set -euo pipefail` and a single positional `<version>` argument
- [ ] 1.2 Implement precondition checks: clean working tree, current branch is `main`, local `main` matches `origin/main` after fetch
- [ ] 1.3 Implement tooling preflight: detect missing `cargo-fuzz` or nightly toolchain and exit with an install hint before any mutation
- [ ] 1.4 Implement verification block: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo tarpaulin`, `cargo +nightly fuzz run fuzz_evaluator -- -max_total_time=60`, `nix build .#default --no-link`
- [ ] 1.5 Implement mutation block in strict order: rewrite `version` in `Cargo.toml`, run `cargo check` to refresh `Cargo.lock`, `git add` both, `git commit -m "Release v$VERSION"`, `git tag -a "v$VERSION" -m "v$VERSION"`, push branch then tag
- [ ] 1.6 `chmod +x scripts/release.sh`

## 2. Tarpaulin and pre-push hook adjustments

- [ ] 2.1 Update `tarpaulin.toml` `run-types` to `["Lib", "Tests", "Doctests"]`
- [ ] 2.2 Remove the `cargo-test-full` hook (the tarpaulin entry) from `prek.toml` pre-push stage
- [ ] 2.3 Add a plain `cargo-test-full` hook to `prek.toml` pre-push stage that runs `cargo test --workspace` without instrumentation
- [ ] 2.4 Confirm pre-push hook set is now: `cargo-build-full`, `cargo-clippy-full`, `cargo-test-full` (plain), `nix-build`

## 3. Release workflow simplification

- [ ] 3.1 Remove the `cargo test --release --workspace` step from each per-target job in `.github/workflows/release.yml`
- [ ] 3.2 Verify the per-target job sequence is: checkout, toolchain, cache, build, package, upload

## 4. Nightly verification workflow

- [ ] 4.1 Create `.github/workflows/nightly.yml` with a `schedule` trigger (cron, daily) and `workflow_dispatch` for manual runs
- [ ] 4.2 Add a tarpaulin job that runs `cargo tarpaulin` against latest `main`
- [ ] 4.3 Add a fuzz job that runs `cargo +nightly fuzz run fuzz_evaluator -- -max_total_time=600` and uploads any new crash artefacts as a workflow artefact
- [ ] 4.4 Ensure neither job is referenced from branch-protection-required checks

## 5. Documentation

- [ ] 5.1 Update the `# Release tagging` section of `CLAUDE.md` to instruct contributors to run `scripts/release.sh <version>` and describe the verify-before-mutate ordering
- [ ] 5.2 Note the nightly workflow's purpose (non-blocking coverage + fuzz signal) and where its results appear

## 6. Verification

- [ ] 6.1 Run `scripts/release.sh` against a throwaway version on a scratch branch (no push) to exercise the verification block end-to-end
- [ ] 6.2 Run `prek run --hook-stage pre-push --all-files` to confirm slimmed pre-push hooks pass on a clean tree
- [ ] 6.3 Trigger `nightly.yml` via `workflow_dispatch` once and confirm both jobs complete and report results to the Actions UI
- [ ] 6.4 Run `openspec validate consolidate-release-verification --strict` and confirm zero errors
